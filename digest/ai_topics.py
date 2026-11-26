"""AI Security Topics: one explainer each weekday, drawn only from the topic's official text.

    python -m digest.ai_topics            # weekdays, on the Mac after the brief (skips weekends)
    python -m digest.ai_topics --topic owasp-llm06 --dry-run

The rotation is data/topics/ai_security.yaml (OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS
techniques with their mitigations). The reference text comes from OWASP's and MITRE's own published files
(cached in state/topic_refs/); the model may use nothing else, and every figure, id and version must appear
in that text. Drafts go through the same Telegram approval as the other AI notes (/note ok ID), then to
theparijat.com/notes/ and LinkedIn.
"""
from __future__ import annotations

import argparse
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

from . import ai_notes as A
from .config import load_config

ROOT = Path(__file__).resolve().parent.parent
TOPICS = ROOT / "data" / "topics" / "ai_security.yaml"
CACHE = ROOT / "state" / "topic_refs"
log = logging.getLogger("digest.ai_topics")

SYSTEM = """You are a senior detection and response architect writing a short explainer in a series called
AI Security Topics, for security engineers and their leaders. Topic: {code} {name} ({framework}).

Write ONLY from <items>, which hold the official text for this topic. Do not add attacks, incidents, products,
numbers, CVEs or vendors that are not in it. Explain it plainly for a practitioner who has not read the source.

Structure:
- "What it is": two or three sentences.
- "How the attack works": a concrete walk-through using the scenarios in the source.
- "Problem, risk, mitigation": three to five "- " lines, each "Problem: ... Risk: ... Mitigation: ..." taken
  from the source's prevention and mitigation guidance.
- actions: three to five concrete steps (Inventory, Contain, Harden, Detect, Hunt) from the source.
- hunt: what to look for in logs, only if the source's guidance supports it, else null.
Status: these are framework definitions, so status may be empty; never invent incidents to fill it.

Voice: confident, specific, plain. No hype, no emojis, no rhetorical questions. Never use: landscape, delve,
elevate, paradigm, testament, furthermore, moreover, game-changer.

Return JSON only:
{{"title": "AI Security Topics: {name}", "summary": "<2 sentences: what it is and why a defender should care>",
 "body": [{{"heading": "What it is" | "How the attack works" | "Problem, risk, mitigation", "markdown": "<text>"}}],
 "actions": [{{"verb": "...", "text": "..."}}], "hunt": null, "status": [],
 "sources": [{{"title": "...", "url": "<one of the item urls>"}}],
 "visual": {{"title": "<under 60 characters>", "steps": ["<the attack sequence from the source, 3 to 5 steps>"]}}}}
Length: 350 to 600 words in body."""


def topics() -> list[dict]:
    return yaml.safe_load(TOPICS.read_text())["topics"]


def done_ids() -> list[str]:
    """Topic ids already published, oldest first (from the notes' front matter)."""
    out = []
    for f in sorted((ROOT / "data" / "notes").glob("*-ai-topic-*.md")):
        meta = yaml.safe_load(f.read_text().split("---", 2)[1]) or {}
        if meta.get("topic_id"):
            out.append(meta["topic_id"])
    return out


def pending_ids() -> set[str]:
    out = set()
    for f in A.DRAFTS.glob("*-ai-topic-*.md"):
        meta = yaml.safe_load(f.read_text().split("---", 2)[1]) or {}
        out.add(meta.get("topic_id"))
    return out


def next_topic() -> dict:
    ts, done, pending = topics(), done_ids(), pending_ids()
    fresh = [t for t in ts if t["id"] not in done and t["id"] not in pending]
    if fresh:
        return fresh[0]
    # every topic covered: start again with the one published longest ago
    order = {tid: i for i, tid in enumerate(done)}
    return min((t for t in ts if t["id"] not in pending), key=lambda t: order.get(t["id"], -1))


def reference(t: dict) -> str:
    f = CACHE / f"{t['id']}.txt"
    if f.exists():
        return f.read_text()
    r = requests.get(t["ref_raw"], timeout=30)
    r.raise_for_status()
    text = r.text
    if t["framework"] == "MITRE ATLAS":
        m = yaml.safe_load(text)["matrices"][0]
        tech = next(x for x in m["techniques"] if x["id"] == t["code"])
        mits = [x for x in m["mitigations"] if any((y.get("id") if isinstance(y, dict) else y) == t["code"]
                                                    for y in x.get("techniques", []))]
        text = (f"MITRE ATLAS technique {t['code']}: {tech['name']}\n\n{tech.get('description', '')}\n\nMitigations:\n"
                + "\n".join(f"- {x['id']} {x['name']}: {x.get('description', '')}" for x in mits))
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    return text


def items_for(t: dict) -> list[dict]:
    """The topic's official text as the only input, under each of its source URLs."""
    text = reference(t)
    return [{"title": s["title"], "url": s["url"], "source_name": t["framework"], "source_tier": "authority",
             "source_type": "reference", "text": text if i == 0 else text[:1500]} for i, s in enumerate(t["sources"])]


def run(topic_id: str | None = None, dry: bool = False) -> Path | None:
    today = datetime.now(timezone.utc).date()
    if topic_id is None and today.weekday() >= 5:
        log.info("weekend: no topic post")
        return None
    A.DRAFTS.mkdir(parents=True, exist_ok=True)
    if topic_id is None and any(A.DRAFTS.glob(f"{today}-ai-topic-*.md")):
        log.info("a topic draft for %s already exists", today)
        return None
    t = next(x for x in topics() if x["id"] == topic_id) if topic_id else next_topic()
    items = items_for(t)
    system = SYSTEM.format(code=t["code"], name=t["name"], framework=t["framework"])
    note, provider = A.draft("topic", items, load_config(), system=system)
    note["title"] = f"AI Security Topics: {t['name']}"
    removed = A.scrub(note, items)
    slug, md = A.to_markdown(note, "topic", today, provider,
                             extra={"topic_id": t["id"], "framework": f"{t['framework']} {t['code']}",
                                    "tags": [t["framework"], re.sub(r":2025$", "", t["code"])]})
    if dry:
        print(md)
        return None
    f = A.DRAFTS / f"{slug}.md"
    f.write_text(md)
    log.info("topic draft %s (%s, %s); %d sentence(s) removed", f, t["id"], provider, len(removed))
    A.notify(slug, md, removed)
    return f


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic", help="a topic id from data/topics/ai_security.yaml")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    run(a.topic, a.dry_run)


if __name__ == "__main__":
    main()
