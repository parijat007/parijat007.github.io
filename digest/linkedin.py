"""LinkedIn agent: draft -> check -> you approve -> publish. Nothing posts by itself.

  python -m digest.linkedin auth                 # one-time: sign in to LinkedIn, token saved to Keychain
  python -m digest.linkedin draft --from note    # draft a post from the latest analyst note
  python -m digest.linkedin draft --from brief   # ...or from today's brief
  python -m digest.linkedin draft --from file post-idea.md
  python -m digest.linkedin list                 # drafts waiting for you
  python -m digest.linkedin show <id>
  python -m digest.linkedin judge <id>           # re-run the judge (after you edit a draft)
  python -m digest.linkedin publish <id>         # judge, show post and image, ask "Publish? [y/N]"
  python -m digest.linkedin status               # token expiry and author
  python -m digest.linkedin autopilot            # Mac, every 10 min: draft new notes, act on Telegram replies

Drafts live outside the public repo (~/.watchfloor/linkedin). The model writes only from the
source you point it at; every draft is checked (length, banned words, links, employer names)
before you see it, gets a branded image drawn from the source (digest/post_visual.py), and is
reviewed by the judge (digest/post_judge.py): facts matched against the source, then a second
model. Publishing is blocked unless the judge passes, and you still approve every post. Publishing uses LinkedIn's own API for your own profile (scope
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

from . import llm, post_judge, post_visual
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
# Wording that could read as job-seeking, outside consulting, or speaking for an employer
EMPLOYMENT_RISK = re.compile(
    r"\b(open to (work|new (roles|opportunities))|looking for (a )?(new )?(role|job|opportunit\w+)|hire me|"
    r"for hire|freelanc\w*|consult(ing|ancy|ant)|my (services|clients?)|(dm|message) me for|"
    r"(my|our) (employer|company|team|organi[sz]ation|firm|soc)|at work (we|I)|in my (day )?job|"
    r"internal(ly)? (data|incident|tool)|on behalf of)\b", re.I)

SYSTEM = """You write LinkedIn posts for {name}, {headline}
Voice: a senior practitioner briefing other defenders. Confident, specific, plain. No hype, no emojis,
no "I'm excited", no motivational lines, no rhetorical questions, no engagement bait.
Never use: landscape, delve, elevate, paradigm, testament, furthermore, moreover, game-changer.

Facts (non-negotiable):
- Use ONLY facts in <source>. Do not add numbers, names, CVEs, versions, dates or claims that are not there.
- Keep "confirmed" and "reported" exactly as the source's status list marks them. Keep every caveat the
  source attaches to a figure (for example "flagged does not mean malicious").
- Copy a fix step whole: if the source says upgrade and then rotate or restrict, say both.
- Time words must be true: do not say "this month" or "this week" about something the source dates earlier.
- Never mention any employer or client, never imply you speak for one, never describe your own workplace.
- No job-seeking or sales language ("open to work", "hire me", "consulting", "services", "DM me").

Craft (how an expert post reads):
1. Opening: one or two sentences, under 200 characters, that state the finding and why it matters.
   LinkedIn cuts the post at about 210 characters, so the opening must stand alone. Spell out an acronym
   the first time ("Model Context Protocol (MCP)").
2. The evidence: a short lead-in line, then two to four "- " lines, one per data point, each with its
   number, its status (confirmed or reported) where the source gives one, and its caveat.
3. The mechanism in two or three sentences: how the attack works and why defenders' usual controls miss it.
4. "What to do this week:" then three to five "- " lines grouped by verb, each starting with one word and a
   colon: Patch, Inventory, Contain, Hunt (use the ones the source supports). Include a Hunt line whenever
   the source gives hunting or detection guidance, naming the log source and the event names it gives.
5. One closing sentence: the principle a defender should keep.
6. A line naming what the full write-up adds (framework mapping, sources, hunting guidance), then the
   link {link} on its own line, then three to five specific hashtags on the last line.
- 1,400 to 2,200 characters. Plain text only: no markdown, no bullet symbols other than "-".

<example> shows the structure and voice to match. It is about a different subject: never reuse its facts,
numbers or wording.
<example>
{example}
</example>
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


def source_from_note(cfg: dict, stem: str | None = None) -> dict:
    notes = sorted((ROOT / "data" / "notes").glob("*.md"), reverse=True)
    if stem:
        notes = [n for n in notes if n.stem == stem]
    if not notes:
        raise SystemExit("no analyst notes in data/notes/")
    f = notes[0]
    raw = f.read_text()
    _, fm, body = raw.split("---", 2)
    meta = yaml.safe_load(fm)
    return {"kind": "note", "title": meta["title"], "summary": meta.get("summary", ""),
            "text": f"{meta.get('summary', '')}\n\n{body[:9000]}", "raw": raw,
            "visual": post_visual.spec_from_note(meta),
            "link": f"{_site(cfg)}/notes/{f.stem}/", "urls": URL_RE.findall(raw)}


def note_source(cfg: dict, stem: str) -> dict | None:
    """The source for a draft made from a note, re-read from the repo (drafts made before images existed)."""
    f = ROOT / "data" / "notes" / f"{stem}.md"
    if not f.exists():
        return None
    raw = f.read_text()
    meta = yaml.safe_load(raw.split("---", 2)[1])
    return {"raw": raw, "visual": post_visual.spec_from_note(meta)}


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
            "text": "\n".join(lines), "raw": json.dumps(b, ensure_ascii=False),
            "visual": {"kicker": "Daily threat brief", "title": f"Threat brief {b['run_date']}",
                       "detail": b.get("executive_pulse", "")},
            "link": f"{_site(cfg)}/brief/{b['run_date']}/", "urls": URL_RE.findall(json.dumps(b))}


def source_from_file(cfg: dict, path: str) -> dict:
    text = Path(path).read_text()
    return {"kind": "file", "title": Path(path).stem, "text": text[:9000], "raw": text, "link": _site(cfg) + "/",
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
    if (m := EMPLOYMENT_RISK.search(text)):
        problems.append(f"employment-sensitive wording: {m.group(0)!r} (no job-seeking, consulting or workplace references)")
    if len(re.findall(r"(?<!\w)#\w+", text)) > 5:
        problems.append("more than five hashtags")
    return problems + craft(text, src)


OPENING_MAX = 210                      # LinkedIn shows about this much before "see more"


def craft(text: str, src: dict) -> list[str]:
    """Structure an expert post needs. Applied to model drafts of notes and briefs; not to the
    plain fallback, and not at publish time, so a post you edited by hand is never blocked on style."""
    if src.get("kind") not in ("note", "brief") or src.get("no_craft"):
        return []
    problems = []
    opening = text.strip().split("\n\n", 1)[0]
    if len(opening) > OPENING_MAX:
        problems.append(f"opening paragraph is {len(opening)} characters; keep it under 200 so it shows "
                        "in full before 'see more'")
    actions = [ln for ln in text.splitlines() if re.match(r"^- (Patch|Inventory|Contain|Hunt|Detect|Harden|"
                                                          r"Restrict|Rotate|Monitor|Mitigate)\b", ln)]
    if len(actions) < 2:
        problems.append("the action list needs two to five lines that start with a verb and a colon "
                        "(Patch:, Inventory:, Contain:, Hunt:)")
    if re.search(r"(?mi)^#+\s*hunt|\*\*hunt", src.get("text", "")) and not re.search(r"(?m)^- Hunt\b", text):
        problems.append("the source gives hunting guidance: add a '- Hunt:' line naming its log source and events")
    if len(text) > 2300:
        problems.append(f"{len(text)} characters: cut to 2,200 or fewer by tightening, not by dropping a caveat "
                        "or the second part of a fix step")
    for ln in text.splitlines():
        if ln.startswith("- ") and len(ln) > 280:
            problems.append(f"this line is {len(ln)} characters; keep each line under 280 (split or tighten): "
                            f"{ln[:60]}...")
    tags = re.findall(r"(?<!\w)#\w+", text)
    if len(tags) < 3:
        problems.append("end with three to five specific hashtags")
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
    example = (Path(__file__).parent / "linkedin_example.txt").read_text().strip()
    system = SYSTEM.format(name=p["name"], headline=p["headline"], link=src["link"], example=example)
    user = f"<source title={json.dumps(src['title'])}>\n{src['text']}\n</source>\nWrite the post."
    lc = cfg["llm"]
    plain = {**lc, "providers": {k: {**v, "json": None} for k, v in lc["providers"].items()}}
    text, provider, problems = None, "fallback", []
    image_text = post_visual.numbers(src["visual"]) if src.get("visual") else ""
    verdict = None
    for name in llm.chain(lc):
        if name == "local" and not llm.local_up(lc):
            continue
        try:
            # Write, check, judge, revise: up to three drafts. Problems from the code checks and the judge's
            # findings go back to the writer, the way an editor would hand a draft back.
            for attempt in range(3):
                text = llm.complete(name, plain, system, user).strip()
                problems = check(text, src, cfg)
                verdict = None
                if not problems:
                    verdict = post_judge.judge(text, image_text, src.get("raw", src["text"]), cfg, name)
                    if verdict["verdict"] in ("pass", "unavailable"):
                        break
                notes = problems + (verdict.get("facts", []) if verdict else []) + \
                    [f"{i['kind']}: \"{i['quote']}\" - {i['why']}" for i in (verdict or {}).get("issues", [])]
                log.info("draft %d from %s sent back: %s", attempt + 1, name, "; ".join(notes)[:300])
                user += ("\n\nAn editor sent your previous draft back. Fix every point, keep everything else, "
                         "and return the whole post again:\n- " + "\n- ".join(notes) +
                         f"\n\n<previous_draft>\n{text}\n</previous_draft>")
            provider = name
            break
        except Exception as e:  # noqa: BLE001
            log.warning("%s failed: %s", name, e)
    if not text or problems:
        text, provider, verdict = fallback_post(src), "fallback", None
        problems = check(text, {**src, "no_craft": True}, cfg)
    did = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M") + "-" + hashlib.sha1(text.encode()).hexdigest()[:6]
    d = {"id": did, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "status": "draft",
         "source": {k: src[k] for k in ("kind", "title", "link")}, "provider": provider,
         "problems": problems, "text": text, "source_raw": src.get("raw", src["text"])}
    STORE.mkdir(parents=True, exist_ok=True)
    attach_image(d, src.get("visual"))
    d["judge"] = verdict or post_judge.judge(text, d.get("image_text", ""), d["source_raw"], cfg, provider)
    (STORE / f"{did}.json").write_text(json.dumps(d, indent=1, ensure_ascii=False))
    return d


def attach_image(d: dict, spec: dict | None) -> None:
    """Draw the post image from the source's own words and keep its text for the judge."""
    if not spec:
        return
    out = post_visual.render(spec, STORE / f"{d['id']}.png")
    d["image"], d["image_text"] = str(out), post_visual.numbers(spec)
    d["alt"] = (spec.get("title", "") + ". " + "; ".join(spec.get("steps") or [])).strip()[:1000]


def complete_draft(d: dict, cfg: dict) -> dict:
    """Older drafts: fill in the source snapshot and image from the note they were drafted from."""
    if d["source"]["kind"] == "note" and not (d.get("source_raw") and d.get("image")):
        src = note_source(cfg, d["source"]["link"].rstrip("/").rsplit("/", 1)[-1])
        if src:
            d.setdefault("source_raw", src["raw"])
            if not d.get("image") or not Path(d["image"]).exists():
                attach_image(d, src["visual"])
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
    if d.get("judge"):
        head += "\n" + post_judge.report(d["judge"])
    if d.get("image") and Path(d["image"]).exists():
        with open(d["image"], "rb") as fh:
            requests.post(f"https://api.telegram.org/bot{tok}/sendPhoto", data={"chat_id": chat,
                          "caption": f"Image for draft {d['id']}"}, files={"photo": fh}, timeout=60)
    msg = (f"{head}\n\n{d['text']}\n\nTo publish, reply:  /post {d['id']}\nTo drop it, reply:  /skip {d['id']}\n"
           "(or on the Mac: ./mac/linkedin.sh publish ID)")
    requests.post(f"https://api.telegram.org/bot{tok}/sendMessage",
                  json={"chat_id": chat, "text": msg[:4000], "disable_web_page_preview": True}, timeout=20)


# ---------- publishing ----------

def _headers(token: str, version: str) -> dict:
    return {"Authorization": f"Bearer {token}", "LinkedIn-Version": version,
            "X-Restli-Protocol-Version": "2.0.0", "Content-Type": "application/json"}


def upload_image(path: str, token: str, author: str, version: str) -> str:
    """LinkedIn Images API: register an upload for this author, PUT the bytes, return the image URN."""
    r = requests.post(f"{API}/rest/images?action=initializeUpload", headers=_headers(token, version),
                      json={"initializeUploadRequest": {"owner": author}}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"LinkedIn image init HTTP {r.status_code}: {r.text[:300]}")
    v = r.json()["value"]
    with open(path, "rb") as fh:
        u = requests.put(v["uploadUrl"], data=fh, timeout=120, headers={"Authorization": f"Bearer {token}"})
    if u.status_code not in (200, 201):
        raise RuntimeError(f"LinkedIn image upload HTTP {u.status_code}: {u.text[:300]}")
    return v["image"]


def post(text: str, token: str, author: str, version: str, image: str | None = None, alt: str = "") -> str:
    body = {"author": author, "commentary": little_text(text), "visibility": "PUBLIC",
            "distribution": {"feedDistribution": "MAIN_FEED", "targetEntities": [],
                             "thirdPartyDistributionChannels": []},
            "lifecycleState": "PUBLISHED", "isReshareDisabledByAuthor": False}
    if image:
        body["content"] = {"media": {"id": image, "altText": alt[:4086]}}
    r = requests.post(f"{API}/rest/posts", json=body, timeout=30, headers=_headers(token, version))
    if r.status_code != 201:
        raise RuntimeError(f"LinkedIn HTTP {r.status_code}: {r.text[:300]}")
    return r.headers.get("x-restli-id", "")


def edit_post(cfg: dict, did: str, text: str) -> str:
    """Replace the text of a post that is already live (image, reactions and link stay). Judge first."""
    f = STORE / f"{did}.json"
    d = json.loads(f.read_text())
    if d.get("status") != "published" or not d.get("post_urn"):
        raise SystemExit(f"{did} is not a published post")
    problems = check(text, {**d["source"], "urls": URL_RE.findall(text), "no_craft": True}, cfg)
    if problems:
        raise SystemExit("fix first:\n- " + "\n- ".join(problems))
    complete_draft(d, cfg)
    trial = {**d, "text": text}
    v = run_judge(cfg, trial)
    if v["verdict"] != "pass":
        raise SystemExit("Not edited:\n" + post_judge.report(v))
    token = secret("linkedin-access-token")
    if not token:
        raise SystemExit("not signed in: run `./mac/linkedin.sh auth`")
    version = cfg.get("linkedin", {}).get("api_version", "202608")
    r = requests.post(f"{API}/rest/posts/{urllib.parse.quote(d['post_urn'], safe='')}", timeout=30,
                      headers={**_headers(token, version), "X-RestLi-Method": "PARTIAL_UPDATE"},
                      json={"patch": {"$set": {"commentary": little_text(text)}}})
    if r.status_code not in (200, 204):
        raise RuntimeError(f"LinkedIn edit HTTP {r.status_code}: {r.text[:300]}")
    d.update(text=text, judge=v, edited=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
    return d.get("url") or d["post_urn"]


def run_judge(cfg: dict, d: dict) -> dict:
    d["judge"] = post_judge.judge(d["text"], d.get("image_text", ""), d.get("source_raw", ""), cfg, d.get("provider"))
    d["judged_text"] = hashlib.sha1(d["text"].encode()).hexdigest()
    return d["judge"]


def publish(cfg: dict, did: str, yes: bool = False, skip_judge: bool = False) -> None:
    f = STORE / f"{did}.json"
    if not f.exists():
        raise SystemExit(f"no draft {did}; run `list`")
    d = json.loads(f.read_text())
    if d["status"] == "published":
        raise SystemExit(f"{did} was already published: {d.get('url')}")
    problems = check(d["text"], {**d["source"], "urls": URL_RE.findall(d["text"]), "no_craft": True}, cfg)
    if problems:
        raise SystemExit("fix the draft first (edit the JSON file):\n- " + "\n- ".join(problems))
    token, author = secret("linkedin-access-token"), secret("linkedin-person-urn")
    if not (token and author):
        raise SystemExit("not signed in: run `python -m digest.linkedin auth`")
    complete_draft(d, cfg)
    if not d.get("source_raw"):
        raise SystemExit("this draft has no source to judge against; draft it again")
    v = run_judge(cfg, d)
    f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
    print(post_judge.report(v))
    if v["verdict"] == "fail":
        raise SystemExit("Not published: fix the draft (edit the JSON file), then run `judge` or `publish` again.")
    if v["verdict"] == "unavailable" and not skip_judge:
        raise SystemExit("Not published: no second model answered. Try again later, or pass --skip-judge "
                         "if you have checked the post against the source yourself.")
    print("-" * 60 + f"\n{d['text']}\n" + "-" * 60)
    if d.get("image"):
        print(f"Image: {d['image']}")
        if sys.platform == "darwin" and not yes:
            subprocess.run(["open", d["image"]], check=False)
    if not yes and input("Publish this to your LinkedIn profile? [y/N] ").strip().lower() != "y":
        print("Not published.")
        return
    version = cfg.get("linkedin", {}).get("api_version", "202608")
    image = upload_image(d["image"], token, author, version) if d.get("image") else None
    urn = post(d["text"], token, author, version, image, d.get("alt", ""))
    d.update(status="published", published=datetime.now(timezone.utc).isoformat(timespec="seconds"),
             post_urn=urn, image_urn=image, url=f"https://www.linkedin.com/feed/update/{urn}/" if urn else None)
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


# ---------- autopilot: Telegram approval ----------

CMD = re.compile(r"^/(post|skip)\s+([0-9]{8}-[0-9]{4}-[0-9a-f]{6})\s*$")
NOTE_CMD = re.compile(r"^/note\s+(ok|drop)\s+([0-9]{4}-[0-9]{2}-[0-9]{2}-ai-(?:daily|spotlight|topic)-[a-z0-9-]{1,60})\s*$")


def _tg(method: str, **kw) -> dict:
    tok = os.environ.get("TELEGRAM_BOT_TOKEN") or secret("telegram-bot-token")
    if not tok:
        log.warning("telegram: no bot token (Keychain telegram-bot-token)")
        return {}
    r = requests.post(f"https://api.telegram.org/bot{tok}/{method}", json=kw, timeout=40)
    if not r.ok:
        log.warning("telegram %s: HTTP %s %s", method, r.status_code, r.text[:200])
        return {}
    return r.json()


def owner_commands(updates: list[dict], chat: str) -> list[tuple[str, str]]:
    """(/post|/skip, id) from the owner's private chat only. Anything else, from anyone else, is ignored."""
    out = []
    for u in updates:
        m = u.get("message") or {}
        if str(m.get("chat", {}).get("id")) != str(chat) or m.get("chat", {}).get("type") != "private":
            log.info("ignored a message from chat %s (%s): not the owner's private chat %s",
                     m.get("chat", {}).get("id"), m.get("chat", {}).get("type"), chat)
            continue
        text = (m.get("text") or "").strip()
        if (c := CMD.match(text)):
            out.append((c.group(1), c.group(2)))
        elif (c := NOTE_CMD.match(text)):
            out.append(("note-" + c.group(1), c.group(2)))
    return out


def autopilot(cfg: dict) -> None:
    """Draft new notes, then act on /post and /skip replies. /post publishes only after the judge passes."""
    STORE.mkdir(parents=True, exist_ok=True)
    chat = os.environ.get("TELEGRAM_CHAT_ID") or secret("telegram-chat-id")
    def say(text: str) -> None:
        """Reply to the owner in Telegram (nothing is printed: messages can quote drafts and ids)."""
        if chat:
            _tg("sendMessage", chat_id=chat, text=text, disable_web_page_preview=True)

    # 1. every note from the last three days with no draft yet (a news note and a topic note can share a day);
    #    at most two per run so one busy day cannot flood Telegram
    drafted = {json.loads(f.read_text()).get("source", {}).get("link") for f in STORE.glob("*.json")}
    today = datetime.now(timezone.utc).date()
    made = 0
    for f in sorted((ROOT / "data" / "notes").glob("*.md"), reverse=True):
        try:
            if (today - datetime.fromisoformat(f.stem[:10]).date()).days > 3:
                break
        except ValueError:
            continue
        link = f"{_site(cfg)}/notes/{f.stem}/"
        if link in drafted or (STORE / f".skip-{f.stem}").exists() or made >= 2:
            continue
        try:
            notify_draft(draft(cfg, source_from_note(cfg, f.stem)))
            made += 1
        except SystemExit as e:
            log.info("could not draft %s (%s)", f.stem, e)

    # 2. token expiry
    exp = secret("linkedin-token-expires")
    if exp and (datetime.fromisoformat(exp).date() - datetime.now(timezone.utc).date()).days == 7:
        flag = STORE / f".expiry-{exp}"
        if not flag.exists():
            flag.touch()
            say(f"LinkedIn sign-in expires {exp}. On the Mac run: ./mac/linkedin.sh auth")

    # 3. replies
    if not chat:
        return
    off_f = STORE / ".tg_offset"
    offset = int(off_f.read_text()) if off_f.exists() else 0
    res = _tg("getUpdates", offset=offset, timeout=0, allowed_updates=["message"])
    updates = res.get("result") or []
    log.info("telegram: %d new message(s)", len(updates))
    if updates:
        off_f.write_text(str(updates[-1]["update_id"] + 1))
    for cmd, did in owner_commands(updates, chat):
        if cmd.startswith("note-"):
            from . import ai_notes  # noqa: PLC0415
            try:
                if cmd == "note-ok":
                    say(f"Published: {ai_notes.publish(did)}\nThe LinkedIn draft follows within 10 minutes.")
                else:
                    (ai_notes.DRAFTS / f"{did}.md").rename(ai_notes.DRAFTS / f"{did}.dropped")
                    say(f"Dropped note {did}. Nothing was published.")
            except (SystemExit, OSError) as e:
                say(f"Note {did}: {e}")
            continue
        f = STORE / f"{did}.json"
        if not f.exists():
            say(f"No draft {did}.")
            continue
        if cmd == "skip":
            d = json.loads(f.read_text())
            d["status"] = "skipped"
            f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
            say(f"Dropped draft {did}. Nothing was posted.")
            continue
        try:
            publish(cfg, did, yes=True)
            d = json.loads(f.read_text())
            say(f"Posted to LinkedIn: {d.get('url') or d.get('post_urn')}")
        except SystemExit as e:
            j = json.loads(f.read_text()).get("judge")
            say(f"Not posted ({did}):\n{e}" + (f"\n\n{post_judge.report(j)}" if j else ""))
        except Exception as e:  # noqa: BLE001
            say(f"Not posted ({did}): {str(e)[:300]}")


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
    p.add_argument("--skip-judge", action="store_true", help="publish even if no second model is available "
                   "(a FAIL still blocks)")
    j = sub.add_parser("judge")
    j.add_argument("id")
    sub.add_parser("auth")
    sub.add_parser("status")
    sub.add_parser("autopilot")
    a = ap.parse_args()
    cfg = load_config()
    if a.cmd == "draft":
        src = {"note": source_from_note, "brief": source_from_brief}.get(a.src)
        src = src(cfg) if src else source_from_file(cfg, a.path or sys.exit("draft --from file needs a path"))
        dr = draft(cfg, src)
        print(dr["text"] + f"\n\n[{dr['id']}] provider={dr['provider']}"
              + (f"\nNEEDS ATTENTION: {dr['problems']}" if dr["problems"] else "\nchecks passed")
              + (f"\nimage: {dr['image']}" if dr.get("image") else "") + "\n" + post_judge.report(dr["judge"]))
        if not a.no_notify:
            notify_draft(dr)
    elif a.cmd == "list":
        for f in sorted(STORE.glob("*.json")):
            x = json.loads(f.read_text())
            print(f"{x['id']}  {x['status']:<9} {x['source']['title'][:60]}")
    elif a.cmd == "show":
        print(json.loads((STORE / f"{a.id}.json").read_text())["text"])
    elif a.cmd == "publish":
        publish(cfg, a.id, a.yes, a.skip_judge)
    elif a.cmd == "judge":
        f = STORE / f"{a.id}.json"
        d = complete_draft(json.loads(f.read_text()), cfg)
        print(post_judge.report(run_judge(cfg, d)) + (f"\nimage: {d['image']}" if d.get("image") else ""))
        f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
    elif a.cmd == "auth":
        auth(cfg)
    elif a.cmd == "status":
        status()
    elif a.cmd == "autopilot":
        autopilot(cfg)


if __name__ == "__main__":
    main()
