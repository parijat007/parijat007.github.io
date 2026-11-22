"""LinkedIn agent: draft -> check -> you approve -> publish. Nothing posts by itself.

  python -m digest.linkedin auth                 # one-time: sign in to LinkedIn, token saved to Keychain
  python -m digest.linkedin draft --from note    # draft a post from the latest analyst note
  python -m digest.linkedin draft --from brief   # ...or from today's brief
  python -m digest.linkedin draft --from file post-idea.md
  python -m digest.linkedin list                 # drafts waiting for you
  python -m digest.linkedin show <id>
  python -m digest.linkedin publish <id>         # shows the post and asks "Publish? [y/N]"
  python -m digest.linkedin status               # token expiry and author

Drafts live outside the public repo (~/.watchfloor/linkedin). The model writes only from the
source you point it at; every draft is checked (length, banned words, links, employer names)
before you see it. Publishing uses LinkedIn's own API for your own profile (scope
w_member_social), never browser automation.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import urllib.parse
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

from . import llm
from .config import load_config

log = logging.getLogger("digest.linkedin")
ROOT = Path(__file__).resolve().parent.parent
STORE = Path(os.environ.get("WF_LINKEDIN_DIR", Path.home() / ".watchfloor" / "linkedin"))
API = "https://api.linkedin.com"
MAX_CHARS = 3000                       # LinkedIn commentary limit
BANNED = re.compile(r"\b(landscape|delve|elevate|paradigm|testament|substrate|furthermore|moreover|"
                    r"in conclusion|game[- ]changer|spearhead\w*|synerg\w*|thrilled|excited to share)\b", re.I)
URL_RE = re.compile(r"https?://[^\s)>\]\"'<]+")
KEYCHAIN_ACCOUNT = "watchfloor"

SYSTEM = """You write LinkedIn posts for {name}, {headline}
Voice: a senior practitioner talking to other defenders. Confident, specific, plain. No hype,
no emojis, no "I'm excited", no motivational lines, no rhetorical questions as hooks.
Never use: landscape, delve, elevate, paradigm, testament, furthermore, moreover, game-changer.

Rules:
- Use ONLY facts in <source>. Do not add numbers, names, CVEs or claims that are not there.
- Keep "confirmed" and "reported/claimed" distinct exactly as the source does.
- Never mention any employer or client, and never imply you speak for one.
- Structure: one-line opening that states the finding; a short paragraph of why it matters;
  three to five short lines a defender can act on; then the link {link} on its own line;
  then three to five relevant hashtags on the last line.
- 900 to 1,800 characters. Plain text only: no markdown, no bullets symbols other than "-".
Return only the post text."""


# ---------- secrets (env first, then macOS Keychain) ----------

def secret(name: str) -> str | None:
    env = "WF_" + name.upper().replace("-", "_")
    if os.environ.get(env):
        return os.environ[env]
    if sys.platform == "darwin":
        r = subprocess.run(["security", "find-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", name, "-w"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return None


def save_secret(name: str, value: str) -> None:
    if sys.platform != "darwin":
        raise SystemExit(f"save {name} yourself: set WF_{name.upper().replace('-', '_')} in your environment")
    subprocess.run(["security", "add-generic-password", "-U", "-a", KEYCHAIN_ACCOUNT, "-s", name, "-w", value],
                   check=True, capture_output=True)


# ---------- LinkedIn "little text" format ----------

_RESERVED = re.compile(r"([\\|{}@\[\]()<>#*_~])")
_HASHTAG = re.compile(r"(?<!\w)#([A-Za-z][A-Za-z0-9_]{1,60})")


def little_text(text: str) -> str:
    """Escape LinkedIn's reserved characters; keep #hashtags working and URLs intact."""
    out, pos = [], 0
    for m in URL_RE.finditer(text):
        out.append(_escape_plain(text[pos:m.start()]))
        out.append(m.group(0))          # URLs are auto-linked; escaping would break them
        pos = m.end()
    out.append(_escape_plain(text[pos:]))
    return "".join(out)


def _escape_plain(s: str) -> str:
    tags: list[str] = []

    def keep(m: re.Match) -> str:
        tags.append(m.group(1))
        return f"\x00{len(tags) - 1}\x00"
    s = _HASHTAG.sub(keep, s)
    s = _RESERVED.sub(r"\\\1", s)
    return re.sub(r"\x00(\d+)\x00", lambda m: "{hashtag|\\#|" + tags[int(m.group(1))] + "}", s)


# ---------- sources ----------

def _site(cfg: dict) -> str:
    return (cfg.get("site", {}).get("url") or "").rstrip("/")


def source_from_note(cfg: dict) -> dict:
    notes = sorted((ROOT / "data" / "notes").glob("*.md"), reverse=True)
    if not notes:
        raise SystemExit("no analyst notes in data/notes/")
    f = notes[0]
    raw = f.read_text()
    _, fm, body = raw.split("---", 2)
    meta = yaml.safe_load(fm)
    return {"kind": "note", "title": meta["title"], "summary": meta.get("summary", ""),
            "text": f"{meta.get('summary', '')}\n\n{body[:9000]}",
            "link": f"{_site(cfg)}/notes/{f.stem}/", "urls": URL_RE.findall(raw)}


def source_from_brief(cfg: dict) -> dict:
    briefs = sorted((ROOT / "data" / "briefs").glob("*.json"), reverse=True)
    if not briefs:
        raise SystemExit("no briefs in data/briefs/")
    b = json.loads(briefs[0].read_text())
    lines = [f"Pulse: {b.get('executive_pulse', '')}"]
    for e in b.get("items", [])[:5]:
        if e.get("category") == "GITHUB_REPO":
            continue
        lines.append(f"- {e['headline']} | label: {e.get('exploitation')} | severity: {e.get('severity')} | "
                     f"action: {e.get('action')} | fixed: {e.get('fixed_versions')} | source: {e.get('primary_source')}")
    return {"kind": "brief", "title": f"Threat brief {b['run_date']}", "summary": b.get("executive_pulse", ""),
            "text": "\n".join(lines),
            "link": f"{_site(cfg)}/brief/{b['run_date']}/", "urls": URL_RE.findall(json.dumps(b))}


def source_from_file(cfg: dict, path: str) -> dict:
    text = Path(path).read_text()
    return {"kind": "file", "title": Path(path).stem, "text": text[:9000], "link": _site(cfg) + "/",
            "urls": URL_RE.findall(text)}


# ---------- drafting and checks ----------

def check(text: str, src: dict, cfg: dict) -> list[str]:
    """Return problems; an empty list means the draft can be shown to you for approval."""
    problems = []
    if len(text) > MAX_CHARS:
        problems.append(f"too long: {len(text)} > {MAX_CHARS} characters")
    if len(text) < 200:
        problems.append("too short to be useful")
    if (m := BANNED.search(text)):
        problems.append(f"banned phrase: {m.group(0)!r}")
    if src["link"] not in text:
        problems.append(f"missing the link {src['link']}")
    allowed = {src["link"].rstrip("/")} | {u.rstrip("/.,") for u in src["urls"]}
    site = _site(cfg)
    for u in URL_RE.findall(text):
        u = u.rstrip("/.,")
        if u not in allowed and not (site and u.startswith(site)):
            problems.append(f"link not in the source: {u}")
    for org in cfg.get("linkedin", {}).get("never_name", []):
        if re.search(rf"\b{re.escape(org)}\b", text, re.I):
            problems.append(f"names {org!r}: posts must not mention employers or clients")
    if len(re.findall(r"(?<!\w)#\w+", text)) > 5:
        problems.append("more than five hashtags")
    return problems


def fallback_post(src: dict) -> str:
    """No model available: a plain, factual post built from the source's own words."""
    first = src.get("summary") or re.sub(r"(?m)^#+\s.*$", "", src["text"])
    first = re.sub(r"\s+", " ", first).strip()
    summary = first if len(first) <= 700 else first[:700].rsplit(". ", 1)[0] + "."
    return f"{src['title']}\n\n{summary}\n\nFull write-up, sources and hunting guidance:\n{src['link']}\n\n" \
           "#ThreatIntelligence #DetectionEngineering #CloudSecurity"


def draft(cfg: dict, src: dict) -> dict:
    p = yaml.safe_load((ROOT / "site" / "profile.yaml").read_text())
    system = SYSTEM.format(name=p["name"], headline=p["headline"], link=src["link"])
    user = f"<source title={json.dumps(src['title'])}>\n{src['text']}\n</source>\nWrite the post."
    lc = cfg["llm"]
    plain = {**lc, "providers": {k: {**v, "json": None} for k, v in lc["providers"].items()}}
    text, provider, problems = None, "fallback", []
    for name in llm.chain(lc):
        if name == "local" and not llm.local_up(lc):
            continue
        try:
            for _ in range(2):            # one retry with the problems fed back
                text = llm.complete(name, plain, system, user).strip()
                problems = check(text, src, cfg)
                if not problems:
                    break
                user += "\n\nYour previous draft had these problems, fix all of them:\n- " + "\n- ".join(problems)
            provider = name
            break
        except Exception as e:  # noqa: BLE001
            log.warning("%s failed: %s", name, e)
    if not text or problems:
        text, provider = fallback_post(src), "fallback"
        problems = check(text, src, cfg)
    did = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M") + "-" + hashlib.sha1(text.encode()).hexdigest()[:6]
    d = {"id": did, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "status": "draft",
         "source": {k: src[k] for k in ("kind", "title", "link")}, "provider": provider,
         "problems": problems, "text": text}
    STORE.mkdir(parents=True, exist_ok=True)
    (STORE / f"{did}.json").write_text(json.dumps(d, indent=1, ensure_ascii=False))
    return d


def notify_draft(d: dict) -> None:
    """Send the draft to Telegram so you can review it on your phone."""
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN") or secret("telegram-bot-token"), \
        os.environ.get("TELEGRAM_CHAT_ID") or secret("telegram-chat-id")
    if not (tok and chat):
        return
    head = f"LinkedIn draft {d['id']} ({len(d['text'])} chars, {d['provider']})"
    if d["problems"]:
        head += "\nNeeds attention: " + "; ".join(d["problems"])
    msg = f"{head}\n\n{d['text']}\n\nTo publish, on the Mac run:\npython -m digest.linkedin publish {d['id']}"
    requests.post(f"https://api.telegram.org/bot{tok}/sendMessage",
                  json={"chat_id": chat, "text": msg[:4000], "disable_web_page_preview": True}, timeout=20)


# ---------- publishing ----------

def post(text: str, token: str, author: str, version: str) -> str:
    body = {"author": author, "commentary": little_text(text), "visibility": "PUBLIC",
            "distribution": {"feedDistribution": "MAIN_FEED", "targetEntities": [],
                             "thirdPartyDistributionChannels": []},
            "lifecycleState": "PUBLISHED", "isReshareDisabledByAuthor": False}
    r = requests.post(f"{API}/rest/posts", json=body, timeout=30, headers={
        "Authorization": f"Bearer {token}", "LinkedIn-Version": version,
        "X-Restli-Protocol-Version": "2.0.0", "Content-Type": "application/json"})
    if r.status_code != 201:
        raise RuntimeError(f"LinkedIn HTTP {r.status_code}: {r.text[:300]}")
    return r.headers.get("x-restli-id", "")


def publish(cfg: dict, did: str, yes: bool = False) -> None:
    f = STORE / f"{did}.json"
    if not f.exists():
        raise SystemExit(f"no draft {did}; run `list`")
    d = json.loads(f.read_text())
    if d["status"] == "published":
        raise SystemExit(f"{did} was already published: {d.get('url')}")
    problems = check(d["text"], {**d["source"], "urls": URL_RE.findall(d["text"])}, cfg)
    if problems:
        raise SystemExit("fix the draft first (edit the JSON file):\n- " + "\n- ".join(problems))
    token, author = secret("linkedin-access-token"), secret("linkedin-person-urn")
    if not (token and author):
        raise SystemExit("not signed in: run `python -m digest.linkedin auth`")
    print("-" * 60 + f"\n{d['text']}\n" + "-" * 60)
    if not yes and input("Publish this to your LinkedIn profile? [y/N] ").strip().lower() != "y":
        print("Not published.")
        return
    urn = post(d["text"], token, author, cfg.get("linkedin", {}).get("api_version", "202608"))
    d.update(status="published", published=datetime.now(timezone.utc).isoformat(timespec="seconds"),
             post_urn=urn, url=f"https://www.linkedin.com/feed/update/{urn}/" if urn else None)
    f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
    print(f"Published: {d['url'] or urn}")


# ---------- one-time sign-in ----------

def auth(cfg: dict) -> None:
    cid, csec = secret("linkedin-client-id"), secret("linkedin-client-secret")
    if not (cid and csec):
        raise SystemExit("save your LinkedIn app's Client ID and Secret first (see mac/LINKEDIN.md)")
    port = cfg.get("linkedin", {}).get("redirect_port", 8766)
    redirect = f"http://localhost:{port}/callback"
    state = secrets.token_urlsafe(24)
    url = "https://www.linkedin.com/oauth/v2/authorization?" + urllib.parse.urlencode(
        {"response_type": "code", "client_id": cid, "redirect_uri": redirect, "state": state,
         "scope": "openid profile w_member_social"})
    got: dict = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            got.update({k: v[0] for k, v in q.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Signed in. You can close this tab and return to the terminal.")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    print(f"Opening LinkedIn sign-in. If no browser opens, visit:\n{url}")
    webbrowser.open(url)
    srv.handle_request()
    if got.get("state") != state:
        raise SystemExit("sign-in state mismatch; try again")
    if "code" not in got:
        raise SystemExit(f"sign-in failed: {got.get('error_description') or got}")
    tok = requests.post("https://www.linkedin.com/oauth/v2/accessToken", timeout=30, data={
        "grant_type": "authorization_code", "code": got["code"], "redirect_uri": redirect,
        "client_id": cid, "client_secret": csec}).json()
    if "access_token" not in tok:
        raise SystemExit(f"token exchange failed: {tok}")
    me = requests.get(f"{API}/v2/userinfo", headers={"Authorization": f"Bearer {tok['access_token']}"},
                      timeout=30).json()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=int(tok.get("expires_in", 0)))).date().isoformat()
    save_secret("linkedin-access-token", tok["access_token"])
    save_secret("linkedin-person-urn", f"urn:li:person:{me['sub']}")
    save_secret("linkedin-token-expires", expires)
    print(f"Signed in as {me.get('name')}. Token saved to Keychain; it expires {expires}.")


def status() -> None:
    exp = secret("linkedin-token-expires")
    print(f"author: {secret('linkedin-person-urn') or 'not signed in'}")
    if exp:
        left = (datetime.fromisoformat(exp).date() - datetime.now(timezone.utc).date()).days
        print(f"token expires {exp} ({left} days)" + ("  <- run `auth` again" if left < 7 else ""))
    print(f"drafts: {len(list(STORE.glob('*.json')))} in {STORE}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draft")
    d.add_argument("--from", dest="src", choices=["note", "brief", "file"], default="note")
    d.add_argument("path", nargs="?")
    d.add_argument("--no-notify", action="store_true")
    sub.add_parser("list")
    s = sub.add_parser("show")
    s.add_argument("id")
    p = sub.add_parser("publish")
    p.add_argument("id")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    sub.add_parser("auth")
    sub.add_parser("status")
    a = ap.parse_args()
    cfg = load_config()
    if a.cmd == "draft":
        src = {"note": source_from_note, "brief": source_from_brief}.get(a.src)
        src = src(cfg) if src else source_from_file(cfg, a.path or sys.exit("draft --from file needs a path"))
        dr = draft(cfg, src)
        print(dr["text"] + f"\n\n[{dr['id']}] provider={dr['provider']}"
              + (f"\nNEEDS ATTENTION: {dr['problems']}" if dr["problems"] else "\nchecks passed"))
        if not a.no_notify:
            notify_draft(dr)
    elif a.cmd == "list":
        for f in sorted(STORE.glob("*.json")):
            x = json.loads(f.read_text())
            print(f"{x['id']}  {x['status']:<9} {x['source']['title'][:60]}")
    elif a.cmd == "show":
        print(json.loads((STORE / f"{a.id}.json").read_text())["text"])
    elif a.cmd == "publish":
        publish(cfg, a.id, a.yes)
    elif a.cmd == "auth":
        auth(cfg)
    elif a.cmd == "status":
        status()


if __name__ == "__main__":
    main()
