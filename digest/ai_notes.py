"""AI Security notes on autopilot: a short daily note and a weekly Spotlight, drafted by the local model (cloud
models if it is down), approved by the owner in Telegram, then published to /notes/ (and from there to LinkedIn).

    python -m digest.ai_notes auto        # daily, or the weekly Spotlight on Wednesdays (Mac, after the brief)
    python -m digest.ai_notes daily|weekly [--dry-run]
    python -m digest.ai_notes publish ID  # what "/note ok ID" in Telegram runs

Rules that keep a model-written note publishable:
- Inputs are only what the brief collected (state/inputs/*.json.gz): every source must be one of those URLs.
- Every CVE, advisory id, version, percentage and number must appear in those inputs (render.ground_facts);
  a sentence that fails is sent back once, then removed.
- "confirmed" only for a claim backed by an authority or vendor source; everything else is "reported".
- No AI news worth a note means no note: a quiet day produces nothing, never filler.
- Nothing is published until the owner replies /note ok ID. Drafts stay on the Mac (~/.watchfloor/notes).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import re
import subprocess
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import llm
from .config import load_config
from .post_judge import tokens
from .render import CAN_CONFIRM, ground_facts, parse_json

ROOT = Path(__file__).resolve().parent.parent
INPUTS = ROOT / "state" / "inputs"
DRAFTS = Path(os.environ.get("WF_NOTES_DIR", Path.home() / ".watchfloor" / "notes"))
log = logging.getLogger("digest.ai_notes")

AI = re.compile(r"\b(AI|LLMs?|large language models?|agents?|agentic|MCP|model context protocol|prompt injection|"
                r"jailbreak|copilot|langflow|langchain|llama|openai|anthropic|claude|gemini|chatgpt|gpt-\d|"
                r"hugging ?face|machine learning|model (?:poisoning|theft|weights)|RAG|vector (?:db|database))\b", re.I)
BANNED = re.compile(r"\b(landscape|delve|elevate|paradigm|testament|furthermore|moreover|game-?changer)\b", re.I)

SYSTEM = """You are a senior detection and response architect writing an AI Security {kind} note for practitioners.
Write ONLY from the items in <items>. Never add a fact, number, CVE, version, product, date or name that is not
in them. If the items do not support a section, leave it out.

Status: a claim is "confirmed" only when an item from an authority or vendor source states it; anything from
press, research, honeypots or social posts is "reported". Keep every caveat an item attaches to a figure.
A fix step is copied whole (upgrade AND the rotation/restriction the item requires).

Voice: confident, specific, plain. No hype, no emojis, no rhetorical questions. Never use: landscape, delve,
elevate, paradigm, testament, furthermore, moreover, game-changer. Spell out a less common acronym the first time (MCP, RAG); "AI" and "LLM" need no expansion.

Return JSON only:
{{"title": "AI Security {label}: <specific finding, under 80 characters>",
 "summary": "<2-3 sentences: what happened and why a defender should care>",
 "body": [{{"heading": "What happened" | "How the attack works" | "Why it matters", "markdown": "<paragraphs>"}}],
 "actions": [{{"verb": "Patch|Inventory|Contain|Hunt|Detect", "text": "<one concrete step>"}}],
 "hunt": "<log source and event names to look for, only if an item gives them, else null>",
 "status": [{{"claim": "<short claim>", "state": "confirmed|reported", "note": "<who says so>"}}],
 "sources": [{{"title": "<item title>", "url": "<item url, exactly as given>"}}],
 "visual": {{"title": "<image headline, under 60 characters>", "steps": ["<only if the items describe a real sequence>"],
            "figures": [{{"value": "<a number from the items>", "label": "<what it counts>", "state": "confirmed|reported"}}]}}}}
{size}"""

SIZE = {"daily": "Length: 250 to 450 words in body. One to three items; lead with the most consequential.",
        "weekly": "Length: 700 to 1,100 words in body, with an attack walk-through when the items allow it. "
                  "Cover the week's three to five most consequential items as one story where they connect."}


def load_items(days: int, today: date | None = None) -> list[dict]:
    today = today or datetime.now(timezone.utc).date()
    seen, out = set(), []
    for i in range(days):
        f = INPUTS / f"{today - timedelta(days=i)}.json.gz"
        if not f.exists():
            continue
        for it in json.load(gzip.open(f, "rt")):
            if it["url"] not in seen:
                seen.add(it["url"])
                out.append(it)
    return out


def ai_items(items: list[dict]) -> list[dict]:
    hits = [it for it in items if AI.search(f"{it.get('title', '')} {str(it.get('text', ''))[:800]}")]
    rank = {"authority": 0, "vendor": 1, "research": 2, "press": 3}
    return sorted(hits, key=lambda it: (it.get("source_type") == "github_repo", rank.get(it.get("source_tier"), 4)))


def worth_a_note(items: list[dict]) -> bool:
    """At least one AI item that is not just a new GitHub repository."""
    return any(it.get("source_type") != "github_repo" for it in items)


def _user(items: list[dict]) -> str:
    rows = [{k: it.get(k) for k in ("title", "url", "source_name", "source_tier", "published", "cves", "kev")}
            | {"text": str(it.get("text", ""))[:9000 if it.get("source_type") == "reference" else 2500]} for it in items[:12]]
    return "<items>\n" + json.dumps(rows, ensure_ascii=False, indent=1).replace("</", "<\\/") + "\n</items>"


def check(note: dict, items: list[dict]) -> list[str]:
    allowed = {it["url"] for it in items} | {r for it in items for r in it.get("refs") or []}
    by_url = {it["url"]: it for it in items}
    known = tokens(json.dumps(items, ensure_ascii=False))
    problems = []
    if not note.get("title") or not note.get("summary") or not note.get("body"):
        problems.append("title, summary and body are required")
    for s in note.get("sources") or []:
        if s.get("url") not in allowed:
            problems.append(f"source not among the items, remove it: {s.get('url')}")
    for st in note.get("status") or []:
        if st.get("state") == "confirmed":
            backed = [by_url[s["url"]] for s in note.get("sources") or [] if s.get("url") in by_url]
            if not any(b.get("source_tier") in CAN_CONFIRM or b.get("kev") for b in backed):
                problems.append(f"'{st.get('claim')}' is marked confirmed but no authority or vendor source backs it")
    text = json.dumps(note, ensure_ascii=False)
    for t in sorted(tokens(text) - known):
        problems.append(f"{t} is not in the items: remove it or the sentence carrying it")
    if (m := BANNED.search(text)):
        problems.append(f"banned word: {m[0]}")
    return problems


def scrub(note: dict, items: list[dict]) -> list[str]:
    """Last line of defence: remove any sentence still carrying a figure that is not in the items."""
    known = tokens(json.dumps(items, ensure_ascii=False))
    notes = []
    allowed = {it["url"] for it in items} | {r for it in items for r in it.get("refs") or []}
    by_url = {it["url"]: it for it in items}
    bad = [s for s in note.get("sources") or [] if s.get("url") not in allowed]
    note["sources"] = [s for s in note.get("sources") or [] if s.get("url") in allowed]
    notes += [f"source removed (not among the inputs): {s.get('url')}" for s in bad]
    backed = any(by_url[s["url"]].get("source_tier") in CAN_CONFIRM or by_url[s["url"]].get("kev")
                 for s in note["sources"] if s["url"] in by_url)
    for st in note.get("status") or []:
        if st.get("state") == "confirmed" and not backed:
            st["state"] = "reported"
            notes.append(f"downgraded to reported: {st.get('claim')}")
    for sec in note.get("body") or []:
        e = {"summary": sec.get("markdown", ""), "headline": ""}
        notes += ground_facts(e, known)
        sec["markdown"] = e["summary"] or ""
    for a in note.get("actions") or []:
        e = {"action": a.get("text", ""), "headline": ""}
        notes += ground_facts(e, known)
        a["text"] = e["action"] or ""
    note["actions"] = [a for a in note.get("actions") or [] if a["text"]]
    e = {"summary": note.get("summary", ""), "hunt": note.get("hunt") or "", "headline": note.get("title", "")}
    notes += ground_facts(e, known)
    note.update(summary=e["summary"] or "", hunt=e["hunt"] or None, title=e["headline"])
    v = note.get("visual") or {}
    v["figures"] = [f for f in v.get("figures") or [] if not (tokens(f"{f.get('value')} {f.get('label')}") - known)]
    return notes


LABEL = {"daily": "AI Security Daily", "weekly": "AI Security Spotlight", "topic": "AI Security Topics"}
PREFIX = {"daily": "ai-daily", "weekly": "ai-spotlight", "topic": "ai-topic"}


def draft(kind: str, items: list[dict], cfg: dict, system: str | None = None) -> tuple[dict, str]:
    label = "Spotlight" if kind == "weekly" else "Daily"
    system = system or SYSTEM.format(kind=label.lower(), label=label, size=SIZE[kind])
    user = _user(items)
    lc = cfg["llm"]
    last_err = None
    for name in llm.chain(lc):
        if name == "local" and not llm.local_up(lc):
            continue
        try:
            note = parse_json(llm.complete(name, lc, system, user))
            for _ in range(2):
                problems = check(note, items)
                if not problems:
                    break
                log.info("%s draft sent back: %s", name, "; ".join(problems)[:300])
                note = parse_json(llm.complete(name, lc, system, user + "\n\nAn editor sent your draft back. Fix every "
                                  "point and return the whole JSON again:\n- " + "\n- ".join(problems) +
                                  "\n\n<previous>\n" + json.dumps(note, ensure_ascii=False) + "\n</previous>"))
            return note, name
        except Exception as e:  # noqa: BLE001
            last_err = e
            log.warning("%s failed: %s", name, str(e)[:200])
    raise SystemExit(f"no model produced a note ({last_err})")


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60].rstrip("-")


def to_markdown(note: dict, kind: str, day: date, provider: str, extra: dict | None = None) -> tuple[str, str]:
    label = LABEL[kind]
    title = note["title"] if note["title"].lower().startswith("ai security") else f"{label}: {note['title']}"
    slug = f"{day}-{PREFIX[kind]}-{slugify(title.split(':', 1)[-1])}"
    v = note.get("visual") or {}
    visual = {"kicker": label, "title": v.get("title") or title.split(":", 1)[-1].strip()}
    if v.get("steps"):
        visual["steps"] = v["steps"][:5]
    if v.get("figures"):
        visual["figures"] = v["figures"][:3]
    fm = {"title": title, "date": day.isoformat(), "summary": note["summary"], "tlp": "CLEAR",
          "tags": [label, "AI security", *(extra or {}).pop("tags", [])], **(extra or {}), "visual": visual,
          "status": note.get("status") or [], "sources": note.get("sources") or [],
          "drafted_by": f"{provider} (model), approved by the owner"}
    body = []
    for sec in note.get("body") or []:
        if sec.get("markdown", "").strip():
            body.append(f"## {sec.get('heading', 'What happened')}\n\n{sec['markdown'].strip()}\n")
    acts = note.get("actions") or []
    if acts or note.get("hunt"):
        body.append("## What to do\n")
        body += [f"- **{a['verb']}:** {a['text']}" for a in acts]
        if note.get("hunt"):
            body.append(f"\n**Hunt** (adapt to your logging): {note['hunt']}")
        body.append("")
    md = "---\n" + yaml.safe_dump(fm, sort_keys=False, allow_unicode=True, width=110) + "---\n\n" + "\n".join(body)
    return slug, md


def key(slug: str) -> str:
    """A short handle for a draft: Telegram button data is capped at 64 bytes, and slugs can be longer."""
    return hashlib.sha256(slug.encode()).hexdigest()[:12]


def slug_for(k: str) -> str | None:
    """The draft a button's handle points to, or None if no such draft is waiting."""
    if not re.fullmatch(r"[0-9a-f]{12}", k or ""):
        return None
    return next((f.stem for f in DRAFTS.glob("*.md") if key(f.stem) == k), None)


def telegram(text: str, buttons: list[list[tuple[str, str]]] | None = None) -> bool:
    """Send a message to the owner; True only when Telegram accepted it (failures are logged, never raised)."""
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (tok and chat):
        log.warning("telegram: no bot token or chat id in the environment; message not sent")
        return False
    import requests  # noqa: PLC0415
    body = {"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True}
    if buttons:
        body["reply_markup"] = {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in buttons]}
    try:
        r = requests.post(f"https://api.telegram.org/bot{tok}/sendMessage", timeout=30, json=body)
    except requests.RequestException as e:
        log.warning("telegram: send failed (%s)", type(e).__name__)
        return False
    if not r.ok:
        # Status and Telegram's own description only: the URL carries the token and is never logged.
        desc = (r.json().get("description") if r.headers.get("content-type", "").startswith("application/json") else "")
        log.warning("telegram: send failed: HTTP %s %s", r.status_code, (desc or "")[:120])
        return False
    log.info("telegram: draft notice sent")
    return True


def notify(slug: str, md: str, problems: list[str]) -> bool:
    fm = yaml.safe_load(md.split("---", 2)[1])
    msg = (f"Draft note: {fm['title']}\n\n{fm['summary']}\n\nSources: {len(fm['sources'])}. "
           + (f"Removed before you see it: {len(problems)} sentence(s) with figures not in the sources.\n" if problems else "")
           + f"\nFull draft on the Mac: ~/.watchfloor/notes/{slug}.md\n\nTap Publish or Drop below "
             f"(acted on within 10 minutes). Typed backup: /note ok {slug}")
    k = key(slug)
    return telegram(msg, [[("Publish", f"no:{k}"), ("Drop", f"nd:{k}")]])


def notify_failure(what: str, err: object) -> None:
    """Tell the owner a draft could not be made, so a missing post is never a mystery."""
    telegram(f"Watchfloor: the {what} draft could not be made today.\nReason: {str(err)[:300]}\n"
             "The brief is unaffected. Details: ~/Library/Logs/watchfloor.log on the Mac.")


def run(kind: str, dry: bool = False, today: date | None = None) -> Path | None:
    cfg = load_config()
    today = today or datetime.now(timezone.utc).date()
    items = ai_items(load_items(1 if kind == "daily" else 7, today))
    if not worth_a_note(items):
        log.info("no AI security news worth a %s note", kind)
        return None
    DRAFTS.mkdir(parents=True, exist_ok=True)
    if any(DRAFTS.glob(f"{today}-ai-{'spotlight' if kind == 'weekly' else 'daily'}-*.md")):
        log.info("a %s draft for %s already exists", kind, today)
        return None
    note, provider = draft(kind, items, cfg)
    removed = scrub(note, items)
    slug, md = to_markdown(note, kind, today, provider)
    if dry:
        print(md)
        return None
    f = DRAFTS / f"{slug}.md"
    f.write_text(md)
    log.info("draft %s (%s); %d sentence(s) removed", f, provider, len(removed))
    notify(slug, md, removed)
    return f


def publish(slug: str) -> str:
    """Move an approved draft into data/notes/ and push it (tools/publish.sh records it in the ledger)."""
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}-ai-(daily|spotlight|topic)-[a-z0-9-]+", slug):
        raise SystemExit(f"not a note draft id: {slug}")
    src = DRAFTS / f"{slug}.md"
    if not src.exists():
        raise SystemExit(f"no draft {slug}")
    dest = ROOT / "data" / "notes" / f"{slug}.md"
    dest.write_text(src.read_text())
    env = {**os.environ, "PYTHON": str(ROOT / ".venv" / "bin" / "python"), "PUBLISH_PREFER": "ours"}
    r = subprocess.run(["bash", "tools/publish.sh", f"note: {slug}"], cwd=ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"publish failed: {(r.stderr or r.stdout)[-300:]}")
    src.rename(src.with_suffix(".published"))
    from .linkedin import _site  # noqa: PLC0415
    return f"{_site(load_config())}/notes/{slug}/"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["auto", "daily", "weekly", "publish"])
    ap.add_argument("id", nargs="?")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.cmd == "publish":
        print(publish(a.id or ""))
        return
    kind = a.cmd if a.cmd != "auto" else ("weekly" if datetime.now(timezone.utc).weekday() == 2 else "daily")
    try:
        run(kind, a.dry_run)
    except Exception as e:  # noqa: BLE001  a failed draft must reach the owner, then still fail the step
        if not a.dry_run:
            notify_failure(f"AI {'Spotlight' if kind == 'weekly' else 'news'} note", e)
        raise


if __name__ == "__main__":
    main()
