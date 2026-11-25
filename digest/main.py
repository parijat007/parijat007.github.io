"""Daily Threat & Tooling Digest: collect -> enrich -> LLM rank/summarize -> validate -> deliver.

Usage:
  python -m digest.main                 # full run
  python -m digest.main --dry-run       # print messages instead of sending
  python -m digest.main --dry-run --llm-fixture tests/sample_llm.json --items-fixture tests/sample_items.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import collectors as C
from .config import load_config
from .notify import send
from .render import parse_json, render, to_markdown, validate

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "state" / "seen.json"
log = logging.getLogger("digest")


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save_state(seen: dict, digest: dict, run_date: str, keep_days: int) -> None:
    for e in digest.get("items", []):
        for ident in e.get("identifiers", []) + [e.get("primary_source")]:
            if ident:
                seen[ident] = run_date
    cutoff = (datetime.fromisoformat(run_date) - timedelta(days=keep_days * 2)).date().isoformat()
    seen = {k: v for k, v in seen.items() if v >= cutoff}
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(seen, indent=1, sort_keys=True))


def collect(cfg: dict, since: datetime, until: datetime) -> tuple[list[dict], dict]:
    status: dict[str, str] = {}
    kev = C.load_kev()
    items = C.kev_items(kev, since)
    status["CISA KEV"] = f"ok ({len(items)} new)"
    for name, fn in (
        ("NVD", lambda: C.nvd_items(cfg["nvd"], since, until) if cfg["nvd"].get("enabled") else []),
        ("GitHub Advisory", lambda: C.ghsa_items(cfg["ghsa"], since) if cfg["ghsa"].get("enabled") else []),
        ("GitHub", lambda: C.repo_items(cfg["github_repos"]) if cfg["github_repos"].get("enabled") else []),
    ):
        try:
            got = fn()
            items += got
            status[name] = f"ok ({len(got)})"
        except Exception as e:  # noqa: BLE001
            status[name] = f"error: {type(e).__name__}"
            log.warning("%s failed: %s", name, e)
    items += C.rss_items(cfg["feeds"], since, cfg.get("max_entries_per_feed", 15), status)

    # De-dupe by URL, enrich, pre-rank, cap
    uniq = {it["url"]: it for it in items}
    items = list(uniq.values())
    C.enrich(items, kev, cfg["stack_watchlist"])
    items.sort(key=C.prerank(items), reverse=True)
    return items[: cfg.get("max_items_to_llm", 60)], status


PROMPT_VERSION = "v2.1"


def must_report(items: list[dict]) -> set[str]:
    """CVE ids of newly listed CISA KEV entries: a brief that mentions none of them is wrong."""
    out = set()
    for it in items:
        if it.get("source_name") == "CISA KEV":
            out |= {c.upper() for c in (it.get("cves") or [it.get("id", "")]) if str(c).upper().startswith("CVE-")}
    return out


def check_coverage(parsed: dict, required: set[str], cap: int = 5) -> None:
    """Every newly listed KEV entry must be in the answer (up to the brief's threat cap).
    Rejects a false 'quiet day' and briefs that drop exploited items for weaker news."""
    if not required:
        return
    blob = json.dumps(parsed.get("items") or []).upper()
    missing = sorted(c for c in required if c not in blob)
    if len(required) - len(missing) < min(len(required), cap):
        raise ValueError(f"under-reported: {len(missing)} of {len(required)} new KEV entries missing "
                         f"({', '.join(missing[:6])}); quiet_day={parsed.get('quiet_day')}")


PERF: list[dict] = []   # one entry per model attempt in this run, saved in the brief's meta


def _short_error(e: Exception) -> str:
    m = str(e)
    for key in ("PerDay", "HTTP 429", "HTTP 503", "HTTP 500", "HTTP 404", "HTTP 410", "truncated",
                "under-reported", "no API key", "Timeout", "no items"):
        if key in m or key in type(e).__name__:
            return key
    return type(e).__name__


def schedule_delay_min(cron: str, now) -> int | None:
    """Minutes between the cron slot GitHub was asked for (WF_SCHEDULE) and when the run started."""
    try:
        minute, hour = (int(x) for x in cron.split()[:2])
    except (ValueError, AttributeError):
        return None
    slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if slot > now:
        slot -= timedelta(days=1)
    return int((now - slot).total_seconds() // 60)


def call_llm(cfg: dict, items: list[dict], ctx: dict) -> tuple[str, str]:
    """Try each provider in order (local first). Returns (json_text, provider_name)."""
    from .llm import chain, complete

    system = (ROOT / "digest" / "prompt.md").read_text()
    for k, v in ctx.items():
        system = system.replace("{{" + k + "}}", v)
    errors = []
    for name in chain(cfg["llm"]):
        pc = cfg["llm"]["providers"].get(name)
        if not pc:
            continue
        # Free cloud tiers cap tokens per request: send fewer, shorter items to them
        n, chars = pc.get("max_items", 40), pc.get("max_text_chars", 400)
        slim = [{k: (v[:chars] if k == "text" and isinstance(v, str) else v)
                 for k, v in it.items() if k not in ("source_tier",)} for it in items[:n]]
        payload = json.dumps(slim, ensure_ascii=False).replace("</", "<\\/")   # no way to close the data block
        user = ("<untrusted_items>\n" + payload +
                "\n</untrusted_items>\n\nProduce today's digest JSON.")
        required = must_report(items[:n])
        for attempt in (1, 2):
            t0 = time.monotonic()
            try:
                text = complete(name, cfg["llm"], system, user)
                parsed = parse_json(text)
                if not isinstance(parsed.get("items"), list):
                    raise ValueError("no items array")
                check_coverage(parsed, required)
                PERF.append({"provider": name, "model": pc.get("_used_model"), "attempt": attempt,
                             "seconds": round(time.monotonic() - t0, 1), "ok": True})
                return text, name
            except Exception as e:  # noqa: BLE001  (network, quota, bad JSON: move on)
                PERF.append({"provider": name, "model": pc.get("_used_model"), "attempt": attempt,
                             "seconds": round(time.monotonic() - t0, 1), "ok": False,
                             "error": _short_error(e)})
                log.warning("provider %s attempt %d failed: %s", name, attempt, str(e)[:300])
                if isinstance(e, ValueError) and "text" in locals():
                    log.warning("provider %s returned (first 300 chars): %r", name, text[:300])
                errors.append(f"{name}: {type(e).__name__}")
                if "no API key" in str(e) or "Connection" in type(e).__name__:
                    break
                if "under-reported" in str(e):
                    # one corrective retry: name what was left out
                    user += ("\n\nYour previous answer left out newly listed CISA KEV entries. They are "
                             "confirmed exploited and must each appear as an item: " + ", ".join(sorted(required)))
                    time.sleep(61 if name == "groq" else 5)   # Groq free tier: tokens per minute
                elif any(code in str(e) for code in ("HTTP 429", "HTTP 503", "HTTP 500")) and attempt == 1:
                    time.sleep(61 if "HTTP 429" in str(e) else 30)   # rate limit resets per minute
    raise RuntimeError("all model providers failed: " + "; ".join(errors))


def _sentences(text: str, limit: int) -> str:
    """Trim to whole sentences within limit; never cut mid-word."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = cut.rfind(". ")
    return cut[: end + 1] if end > limit // 3 else cut[: cut.rfind(" ")].rstrip(",;:") + "…"


def _fallback_action(it: dict) -> str:
    ra = it.get("required_action") or ""
    if ra and len(ra) <= 180 and "BOD" not in ra:
        return ra
    due = (it.get("kev") or {}).get("dueDate")
    return ("Apply the vendor's fix or mitigation" + (f" before the CISA KEV due date ({due})" if due else "")
            + "; if no fix exists, isolate or discontinue the affected product.")


SEV_FROM_CVSS = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0, "INFO")]


def fallback_digest(items: list[dict], run_date: str) -> dict:
    """Deterministic brief used when the local model is unavailable. Facts only, no prose generation."""
    # Facts-only mode: lead with the authoritative KEV records themselves, not news articles about them
    picks = ([it for it in items if it.get("source_type") == "kev"][:5]
             or [it for it in items if it.get("kev")][:5]
             or [it for it in items if (it.get("cvss") or 0) >= 9][:5])
    out = []
    for i, it in enumerate(picks, 1):
        cvss = it.get("cvss") or 0
        sev = "CRITICAL" if it.get("kev") else next(s for t, s in SEV_FROM_CVSS if cvss >= t)
        out.append({
            "rank": i, "headline": it["title"][:110], "category": "VULNERABILITY", "severity": sev,
            "exploitation": "EXPLOITED_CONFIRMED" if it.get("kev") else
                            ("POC_PUBLIC" if it.get("public_poc") else "NO_KNOWN_EXPLOIT"),
            "is_update": False, "stack_match": it.get("stack_match", []),
            "target": it.get("product") or it.get("source_name", ""),
            "identifiers": it.get("cves", [])[:4], "kev_due_date": (it.get("kev") or {}).get("dueDate"),
            "summary": _sentences(it.get("text", ""), 300),
            "action": _fallback_action(it),
            "hunt": None, "fixed_versions": None, "confidence": "HIGH" if it.get("kev") else "MEDIUM",
            "primary_source": it["url"], "corroborating_sources": [],
        })
    return {"run_date": run_date, "quiet_day": not out, "items": out, "notes": "automated fallback",
            "executive_pulse": "Automated brief: the analyst model was offline, so this lists the "
                               "highest-signal confirmed items without commentary."}


def sources_by_name(cfg: dict) -> dict:
    return cfg.get("tiers", {})


def write_brief(digest: dict, run_date: str, meta: dict) -> Path:
    out = ROOT / "data" / "briefs" / f"{run_date}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({**digest, "meta": meta}, indent=1, ensure_ascii=False))
    return out


def brief_window() -> tuple[int, int] | None:
    """WF_BRIEF_WINDOW_UTC="10-17": the UTC hours [start, end) in which a scheduled brief may be written.
    GitHub can run a schedule many hours late; a brief written at night is not the morning brief."""
    w = os.environ.get("WF_BRIEF_WINDOW_UTC", "").strip()
    if not w:
        return None
    a, b = (int(x) for x in w.split("-"))
    return a, b


def in_window(hour: int, win: tuple[int, int] | None) -> bool:
    return win is None or win[0] <= hour < win[1]


def existing_mode(run_date: str, win: tuple[int, int] | None = None) -> str | None:
    """Mode of the brief already published for run_date: "analyst", "fallback", "stale" (written
    outside the morning window, so the morning run replaces it), or None when there is none."""
    f = ROOT / "data" / "briefs" / f"{run_date}.json"
    if not f.exists():
        return None
    try:
        meta = json.loads(f.read_text()).get("meta") or {}
    except (OSError, ValueError):
        return "unknown"
    gen = meta.get("generated_at") or ""
    if win and len(gen) >= 13 and gen[11:13].isdigit() and not in_window(int(gen[11:13]), win):
        return "stale"
    return meta.get("mode") or "unknown"


def run(args) -> int:
    cfg = load_config()
    now = datetime.now(timezone.utc)
    hours = cfg["weekend_hours"] if now.astimezone().weekday() == 0 else cfg["window_hours"]
    since = now - timedelta(hours=hours)
    run_date = now.date().isoformat()

    win = brief_window()
    if args.skip_if_exists and not in_window(now.hour, win):
        log.info("outside the brief window %s UTC (now %02d:%02d); a late schedule is skipped",
                 win, now.hour, now.minute)
        return 0
    prior = existing_mode(run_date, win)
    if args.skip_if_exists and prior == "analyst":
        log.info("analyst brief for %s already published; nothing to do", run_date)
        return 0
    if args.skip_if_exists and prior == "stale":
        log.info("existing brief for %s was written outside the morning window; replacing it", run_date)
    elif args.skip_if_exists and prior:
        log.info("existing %s brief for %s is facts-only; trying to upgrade it", prior, run_date)
    t_start = time.monotonic()
    if args.items_fixture:
        items, status = json.loads(Path(args.items_fixture).read_text()), {"fixture": "ok"}
    else:
        items, status = collect(cfg, since, now)
    t_collected = time.monotonic()
    log.info("collected %d items for the model", len(items))
    if not getattr(locals().get("args"), "items_fixture", None):
        _src = ROOT / "data" / "sources.json"
        _old = json.loads(_src.read_text()) if _src.exists() else {"status": {}}
        _now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        _old["status"].update({k: {"status": v, "checked": _now} for k, v in status.items()})
        _src.parent.mkdir(parents=True, exist_ok=True)
        _src.write_text(json.dumps(_old, indent=1))

    seen = load_state()
    recent_cut = (now - timedelta(days=cfg["repeat_suppression_days"])).date().isoformat()
    newly_kev = must_report(items)   # a CVE newly listed in KEV is news again, whatever was said before
    recent_ids = sorted(k for k, v in seen.items() if v >= recent_cut and not k.startswith("http")
                        and not (prior == "stale" and v == run_date)    # the stale brief's items are re-judged
                        and k.upper() not in newly_kev)
    ctx = {
        "RUN_DATE": run_date,
        "WINDOW_START": since.strftime("%Y-%m-%d %H:%M UTC"),
        "WINDOW_END": now.strftime("%Y-%m-%d %H:%M UTC"),
        "STACK_WATCHLIST": ", ".join(cfg["stack_watchlist"]),
        "PREVIOUSLY_REPORTED_IDS": ", ".join(recent_ids) or "none",
    }

    mode, provider = ("fallback", None) if args.fallback else ("analyst", "fixture")
    digest = None
    if not args.fallback:
        try:
            if args.llm_fixture:
                raw = Path(args.llm_fixture).read_text()
            else:
                raw, provider = call_llm(cfg, items, ctx)
            digest, problems = validate(parse_json(raw), items, sources_by_name(cfg))
        except Exception as e:  # noqa: BLE001
            log.error("analyst models unavailable (%s); publishing facts-only brief", e)
            mode, provider = "fallback", None
    verification = None
    if digest is not None and provider and not args.llm_fixture:   # a different model checks the prose
        from .verify import verify
        verification = verify(digest, items, cfg, provider)
    t_llm = time.monotonic()
    if digest is None:
        digest, problems = validate(fallback_digest(items, run_date), items, sources_by_name(cfg))
    for p in problems:
        log.warning(p)

    failed_feeds = [k for k, v in status.items() if v.startswith("error")]
    footer = f"{len(items)} items screened · {len(digest['items'])} kept"
    if failed_feeds:
        footer += f" · feed errors: {', '.join(failed_feeds)}"
    site = cfg.get("site", {}).get("url", "").rstrip("/")
    if site:
        footer += f"\nFull brief: {site}/brief/{run_date}/"
    blocks = render(digest, run_date, footer)
    meta = {"generated_at": now.isoformat(timespec="seconds"), "mode": mode, "prompt_version": PROMPT_VERSION,
            "model": (cfg["llm"]["providers"].get(provider, {}).get("label") if provider else None),
            "provider": provider,
            "window_start": ctx["WINDOW_START"], "window_end": ctx["WINDOW_END"],
            "items_screened": len(items), "dropped": problems, "sources": status, "verification": verification,
            "perf": {"collect_s": round(t_collected - t_start, 1), "llm_s": round(t_llm - t_collected, 1),
                     "total_s": round(time.monotonic() - t_start, 1), "attempts": PERF,
                     "runner": "github" if os.environ.get("GITHUB_ACTIONS") else "mac",
                     "schedule_delay_min": schedule_delay_min(os.environ.get("WF_SCHEDULE", ""), now)}}
    if prior and prior != "analyst" and mode != "analyst" and args.skip_if_exists:
        log.info("upgrade failed: models still unavailable; keeping the existing facts-only brief")
        return 0
    if prior and mode == "analyst" and prior not in ("analyst", "stale"):
        meta["upgraded_from"] = prior
        blocks[0] = "*Upgraded brief:* the analyst models are back; this replaces this morning's facts-only brief.\n\n" + blocks[0]
    if not args.dry_run:
        write_brief(digest, run_date, meta)

    if args.no_deliver:
        return 0
    errors = send(blocks, cfg, f"Watchfloor brief {run_date}", dry_run=args.dry_run, digest=digest, run_date=run_date)
    if not args.llm_fixture:   # public channel: after the brief is written, once per date (digest/channel.py)
        from .channel import post as post_channel
        try:
            if cfg.get("delivery", {}).get("telegram_channel"):
                os.environ.setdefault("TELEGRAM_CHANNEL_ID", cfg["delivery"]["telegram_channel"])
            post_channel(digest, run_date, (cfg.get("site", {}).get("url") or "").rstrip("/"), ROOT, dry_run=args.dry_run)
        except Exception as e:   # never fail a published brief over the channel
            log.warning("channel post failed: %s", e)
    if not args.dry_run and not args.llm_fixture:
        save_state(seen, digest, run_date, cfg["repeat_suppression_days"])
    (ROOT / "state" / "last_digest.json").write_text(json.dumps(digest, indent=1))
    if not args.dry_run and not args.llm_fixture:
        arch = ROOT / "archive" / run_date[:7]
        arch.mkdir(parents=True, exist_ok=True)
        (arch / f"{run_date}.md").write_text(to_markdown(digest, run_date))
    for ch in errors:   # visible in the Actions summary; data is still committed and published
        print(f"::warning title=Delivery failed::{ch} delivery failed; brief was still published")
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--llm-fixture")
    ap.add_argument("--items-fixture")
    ap.add_argument("--fallback", action="store_true", help="deterministic brief, no LLM")
    ap.add_argument("--no-deliver", action="store_true", help="write data files only")
    ap.add_argument("--skip-if-exists", action="store_true", help="skip if an analyst brief exists today; retry if only a facts-only brief exists")
    args = ap.parse_args()
    try:
        sys.exit(run(args))
    except Exception as e:  # noqa: BLE001
        log.exception("digest run failed")
        cfg = load_config()
        if cfg["delivery"].get("on_failure_alert") and not args.dry_run:
            send([f"⚠️ Threat digest run failed: {type(e).__name__}. Check GitHub Actions logs."],
                 cfg, "Threat Digest FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
