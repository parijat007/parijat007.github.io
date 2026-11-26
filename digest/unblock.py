"""The unblock agent: hourly, it clears what would otherwise wait for the owner.

1. Failed runs: a brief, watch, patch-day or deploy run that failed is re-run once (failed jobs only).
   If the re-run fails too, you get one Telegram alert with the link.
2. Merge queue: an open PR from this repo, opened by the owner, not a draft, with every check green, gets a
   comment "auto-merge at HH:MM UTC" and a Telegram notice. One hour later it is merged and the site is
   deployed, unless the PR has the `hold` label or a comment that says "hold". Excluded: forks, Dependabot,
   other authors, and PRs that change workflow files (GitHub lets only you merge those; you get a notice).
3. Owner to-do: checks what it can see for itself (DNSSEC, DMARC policy, rulesets, ORCID works, secrets
   present) and sends one Telegram list on Mondays, plus a reminder three days before a dated item is due.
   Items that turn green drop off on their own.

Nothing here touches secrets' values, repo settings or DNS: it checks, re-runs, merges by the rules above,
and tells you the rest.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import date, datetime, timedelta, timezone

import requests

log = logging.getLogger("digest.unblock")
GH = "https://api.github.com"
SITE = "theparijat.com"
ORCID = "0009-0000-9233-3352"
RETRY_WORKFLOWS = {"brief.yml", "watch.yml", "patchday.yml", "vendor_patchday.yml", "pages.yml", "orcid.yml"}
HOLD_MINUTES = 60
MARKER = "<!-- watchfloor-automerge -->"
HOLD_RE = re.compile(r"^\s*/?hold\b", re.I)


# ---------- GitHub ----------

DRY = False


def gh(method: str, path: str, **kw):
    if DRY and method != "GET":
        log.info("dry run: would %s %s", method, path)
        return {}
    r = requests.request(method, f"{GH}{path}", timeout=30, headers={
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"}, **kw)
    if r.status_code >= 400:
        raise RuntimeError(f"GitHub {method} {path}: HTTP {r.status_code} {r.text[:200]}")
    return r.json() if r.text else {}


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ---------- 1. failed runs ----------

def failed_runs(runs: list[dict], now: datetime) -> tuple[list[dict], list[dict]]:
    """(to re-run, to alert). A run is re-run once; a failed re-run is alerted once (within the last hour).
    Skipped when a newer run of the same workflow has already succeeded."""
    latest_ok: dict[str, datetime] = {}
    for r in runs:
        if r.get("conclusion") == "success":
            wf = r["path"].rsplit("/", 1)[-1]
            latest_ok[wf] = max(latest_ok.get(wf, _ts(r["created_at"])), _ts(r["created_at"]))
    rerun, alert = [], []
    for r in runs:
        wf = r["path"].rsplit("/", 1)[-1]
        if wf not in RETRY_WORKFLOWS or r.get("status") != "completed" or r.get("conclusion") not in ("failure", "timed_out"):
            continue
        if latest_ok.get(wf, datetime.min.replace(tzinfo=timezone.utc)) > _ts(r["created_at"]):
            continue
        done = _ts(r["updated_at"])
        if r.get("run_attempt", 1) == 1 and now - done < timedelta(hours=6):
            rerun.append(r)
        elif r.get("run_attempt", 1) >= 2 and now - done < timedelta(hours=1):
            alert.append(r)
    return rerun, alert


# ---------- 2. merge queue ----------

def merge_decision(pr: dict, checks: list[dict], files: list[str], comments: list[dict], owner: str,
                   repo: str, now: datetime) -> tuple[str, str]:
    """Returns (action, reason): skip | wait | announce | merge | needs_owner."""
    if pr.get("draft") or pr["head"]["repo"] is None or pr["head"]["repo"]["full_name"] != repo:
        return "skip", "draft or fork"
    if pr["user"]["login"] != owner:
        return "skip", f"opened by {pr['user']['login']}"
    if any(lb["name"].lower() == "hold" for lb in pr.get("labels", [])):
        return "skip", "hold label"
    if not checks or any(c.get("status") != "completed" for c in checks):
        return "wait", "checks still running"
    if any(c.get("conclusion") not in ("success", "skipped", "neutral") for c in checks):
        return "skip", "a check failed"
    if any(f.startswith(".github/workflows/") for f in files):
        return "needs_owner", "changes workflow files"
    sha = pr["head"]["sha"]
    notice = next((c for c in reversed(comments) if f"{MARKER} sha={sha}" in (c.get("body") or "")), None)
    if any(HOLD_RE.search(c.get("body") or "") for c in comments
           if not notice or _ts(c["created_at"]) >= _ts(notice["created_at"])):
        return "skip", "hold comment"
    if not notice:                                       # first green, or new commits since the notice
        return "announce", "all checks green"
    if now - _ts(notice["created_at"]) >= timedelta(minutes=HOLD_MINUTES):
        return "merge", "hold window passed"
    return "wait", "inside the hold window"


def run_merge_queue(repo: str, owner: str, now: datetime) -> list[str]:
    msgs = []
    for pr in gh("GET", f"/repos/{repo}/pulls?state=open&per_page=50"):
        n = pr["number"]
        if pr.get("draft") or pr["user"]["login"] != owner:
            continue
        checks = gh("GET", f"/repos/{repo}/commits/{pr['head']['sha']}/check-runs?per_page=100")["check_runs"]
        files = [f["filename"] for f in gh("GET", f"/repos/{repo}/pulls/{n}/files?per_page=100")]
        comments = gh("GET", f"/repos/{repo}/issues/{n}/comments?per_page=100")
        action, why = merge_decision(pr, checks, files, comments, owner, repo, now)
        log.info("PR #%d: %s (%s)", n, action, why)
        if action == "announce":
            at = (now + timedelta(minutes=HOLD_MINUTES)).strftime("%H:%M UTC")
            gh("POST", f"/repos/{repo}/issues/{n}/comments", json={"body": f"{MARKER} sha={pr['head']['sha']}\nAll checks passed. "
               f"The unblock agent will merge this at about {at} and deploy the site, unless you add the "
               "`hold` label or comment `hold`."})
            msgs.append(f"PR #{n} \"{pr['title']}\" passed every check. It merges at about {at} unless you "
                        f"comment hold on it: {pr['html_url']}")
        elif action == "needs_owner" and not any("needs you" in (c.get("body") or "") for c in comments):
            gh("POST", f"/repos/{repo}/issues/{n}/comments", json={"body": f"{MARKER} needs-owner\nAll checks passed. This PR "
               "changes workflow files, which GitHub lets only the owner merge: needs you."})
            msgs.append(f"PR #{n} \"{pr['title']}\" is green but changes workflow files, so only you can merge "
                        f"it: {pr['html_url']}")
        elif action == "merge":
            try:
                gh("PUT", f"/repos/{repo}/pulls/{n}/merge", json={"merge_method": "merge", "sha": pr["head"]["sha"]})
            except RuntimeError as e:
                msgs.append(f"PR #{n} could not be merged automatically ({str(e)[:120]}). It needs you: {pr['html_url']}")
                continue
            # A merge made with the workflow token does not start push-triggered workflows: deploy explicitly.
            gh("POST", f"/repos/{repo}/actions/workflows/pages.yml/dispatches", json={"ref": "main"})
            msgs.append(f"Merged PR #{n} \"{pr['title']}\" and started the site deploy.")
    return msgs


# ---------- 3. owner to-do ----------

def _dns(name: str, rtype: str) -> list[str]:
    try:
        r = requests.get("https://dns.google/resolve", params={"name": name, "type": rtype}, timeout=15).json()
        return [a.get("data", "") for a in r.get("Answer", [])]
    except (requests.RequestException, ValueError):
        return ["?"]


def owner_checks(repo: str) -> dict[str, bool | None]:
    """True done, False not yet, None could not check."""
    out: dict[str, bool | None] = {}
    ds = _dns(SITE, "DS")
    out["dnssec"] = None if ds == ["?"] else bool(ds)
    dm = " ".join(_dns(f"_dmarc.{SITE}", "TXT"))
    out["dmarc"] = None if dm == "?" else bool(re.search(r"p=(quarantine|reject)", dm))
    try:
        rs = gh("GET", f"/repos/{repo}/rulesets")
        out["rulesets"] = {r.get("target") for r in rs} >= {"branch", "tag"}
    except RuntimeError:
        out["rulesets"] = None
    try:
        perms = gh("GET", f"/repos/{repo}/actions/permissions/workflow")
        out["token_read_only"] = perms.get("default_workflow_permissions") == "read"
    except RuntimeError:
        out["token_read_only"] = None
    try:
        w = requests.get(f"https://pub.orcid.org/v3.0/{ORCID}/works", headers={"Accept": "application/json"},
                         timeout=20).json()
        out["orcid"] = bool(w.get("group"))
    except (requests.RequestException, ValueError):
        out["orcid"] = None
    for key, env in (("backup", "AWS_BACKUP_ROLE_ARN"), ("nvd", "NVD_API_KEY"), ("vulncheck", "VULNCHECK_API_KEY")):
        out[key] = bool(os.environ.get(env))
    return out


TODO = [
    # key, what, how, due (ISO or None)
    ("backup", "Deploy the S3 backup stack", "deploy the stack, then add the AWS_BACKUP_ROLE_ARN and AWS_BACKUP_BUCKET "
     "repository secrets", None),
    ("nvd", "NVD API key in GitHub", "Settings > Secrets and variables > Actions > New secret NVD_API_KEY", None),
    ("rulesets", "Rulesets on main and on tags", "Settings > Rules > Rulesets: one for the default branch, one for tags", None),
    ("token_read_only", "Actions token read-only by default", "Settings > Actions > General > Workflow permissions: "
     "Read repository contents", None),
    ("dnssec", "DNSSEC on theparijat.com", "turn on DNSSEC at the registrar (Route 53: DNSSEC signing, then the DS record)", None),
    ("dmarc", "DMARC enforcement", "move _dmarc.theparijat.com from p=none to p=reject once reports are clean "
     "(p=quarantine also clears this item)", "2026-12-06"),
    ("orcid", "ORCID works public", "orcid.org > Works: set visibility to Everyone", None),
    ("vulncheck", "VulnCheck key", "free key at vulncheck.com, then the VULNCHECK_API_KEY secret", None),
    ("cronjob", "cron-job.org token rotation", "replace the GitHub token used by cron-job.org (see mac/EXTERNAL_CRON.md)",
     "2026-12-23"),
]


def owner_message(state: dict[str, bool | None], today: date, weekly: bool) -> str | None:
    lines = []
    for key, what, how, due in TODO:
        done = state.get(key)
        if done:
            continue
        soon = due and 0 <= (date.fromisoformat(due) - today).days <= 3
        if not (weekly or soon):
            continue
        tag = f" (due {due})" if due else ""
        unknown = key in state and done is None          # a check that could not run (not a manual item)
        lines.append(f"- {what}{tag}: {how}" + (" [could not check]" if unknown else ""))
    if not lines:
        return None
    head = "Watchfloor: your open items" if weekly else "Watchfloor: due soon"
    return head + "\n\n" + "\n".join(lines)


# ---------- main ----------

MIN_GAP_MINUTES = 40


def recent_run(runs: list[dict], me: str, now: datetime) -> bool:
    """An earlier unblock run was created in the last 40 minutes and did not fail. It is triggered both by its
    schedule and by each watch run; comparing creation times means exactly one of two near-simultaneous
    runs goes ahead (the concurrency group makes the later one wait for the earlier)."""
    mine = next((r for r in runs if str(r["id"]) == str(me)), None)
    if not mine:
        return False
    t = _ts(mine["created_at"])
    return any(str(r["id"]) != str(me) and r.get("conclusion") in ("success", None)
               and (_ts(r["created_at"]), r["id"]) < (t, mine["id"])
               and now - _ts(r["created_at"]) < timedelta(minutes=MIN_GAP_MINUTES)
               for r in runs)

def main() -> None:
    import argparse  # noqa: PLC0415
    global DRY
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="decide and print; change nothing, send nothing")
    ap.add_argument("--owner-check", action="store_true", help="run the to-do checks now, not only at 14 UTC")
    a = ap.parse_args()
    DRY = a.dry_run
    repo, now = os.environ["GITHUB_REPOSITORY"], datetime.now(timezone.utc)
    owner = repo.split("/")[0]
    msgs: list[str] = []

    me = os.environ.get("GITHUB_RUN_ID")
    if me and os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        mine = gh("GET", f"/repos/{repo}/actions/workflows/unblock.yml/runs?per_page=10")["workflow_runs"]
        if recent_run(mine, me, now):
            log.info("ran less than %d minutes ago; skipping", MIN_GAP_MINUTES)
            return

    runs = gh("GET", f"/repos/{repo}/actions/runs?per_page=60&created=>{(now - timedelta(hours=12)).date()}")["workflow_runs"]
    rerun, alert = failed_runs(runs, now)
    for r in rerun:
        log.info("re-running failed jobs of %s #%d", r["name"], r["id"])
        try:
            gh("POST", f"/repos/{repo}/actions/runs/{r['id']}/rerun-failed-jobs")
        except RuntimeError as e:
            msgs.append(f"{r['name']} failed and could not be re-run ({str(e)[:100]}): {r['html_url']}")
    msgs += [f"{r['name']} failed twice (the automatic re-run failed too): {r['html_url']}" for r in alert]

    if os.environ.get("WF_AUTOMERGE", "on") != "off":
        msgs += run_merge_queue(repo, owner, now)

    weekly = (now.weekday() == 0 and now.hour == 14) or a.owner_check
    if now.hour == 14 or a.owner_check:
        m = owner_message(owner_checks(repo), now.date(), weekly)
        if m:
            msgs.append(m)

    for m in msgs:
        log.info("notify: %s", m.splitlines()[0])
    if DRY:
        print("\n\n".join(msgs) or "nothing to do")
        return
    if msgs and os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        from .notify import _telegram  # noqa: PLC0415
        try:
            _telegram(["Watchfloor unblock\n\n" + "\n\n".join(msgs)], 0)
        except Exception as e:  # noqa: BLE001
            print(f"::warning title=Unblock notice not sent::{e}")


if __name__ == "__main__":
    main()
