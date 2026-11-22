"""Static site build: data/*.json + site/templates -> _site/ (deployed to GitHub Pages).

  python site/build.py            # build into _site/
  python site/build.py --out DIR

No JavaScript framework and no build toolchain: pages are pre-rendered and auto-escaped,
so text from feeds or the model can never run as script on the page.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import date, datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import yaml
from markdown_it import MarkdownIt
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
DATA = ROOT / "data"
NOW = datetime.now(timezone.utc)

LABELS = {
    "sev": {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "INFO": "Info"},
    "x": {"EXPLOITED_CONFIRMED": "Exploited, confirmed", "EXPLOITED_REPORTED": "Exploitation reported",
          "POC_PUBLIC": "Public PoC", "NO_KNOWN_EXPLOIT": "No known exploit", "N/A": "Tooling"},
    "cat": {"ACTIVE_ATTACK": "Active attack", "VULNERABILITY": "Vulnerability", "SUPPLY_CHAIN": "Supply chain",
            "AI_THREAT": "AI threat", "GITHUB_REPO": "GitHub repo"},
    "kind": {"KEV": "KEV", "ADVISORY": "Vendor", "GHSA": "GitHub"},
}


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def ago(s: str | None) -> str:
    d = _dt(s)
    if not d:
        return "never"
    mins = int((NOW - d).total_seconds() // 60)
    if mins < 2:
        return "just now"
    if mins < 60:
        return f"{mins} min ago"
    if mins < 48 * 60:
        return f"{mins // 60} h ago"
    return f"{mins // 1440} days ago"


def longdate(s: str) -> str:
    d = date.fromisoformat(s[:10])
    return f"{d.strftime('%A')}, {d.day} {d.strftime('%B %Y')}"


def nicedate(s: str) -> str:
    d = date.fromisoformat(s[:10])
    return f"{d.day} {d.strftime('%b %Y')}"


def days_left(s: str) -> int:
    return max((date.fromisoformat(s[:10]) - NOW.date()).days, 0)


def safe_url(u: str | None) -> str:
    """Only http(s) links reach the page; javascript:, data: etc. become inert."""
    u = (u or "").strip()
    return u if urlparse(u).scheme in ("http", "https") else "#"


def env() -> Environment:
    e = Environment(loader=FileSystemLoader(SITE / "templates"), autoescape=select_autoescape(["html", "xml"]),
                    trim_blocks=True, lstrip_blocks=True)
    e.filters.update(
        sev=lambda v: LABELS["sev"].get(v, v), xlabel=lambda v: LABELS["x"].get(v, v),
        cat=lambda v: LABELS["cat"].get(v, v), kindlabel=lambda v: LABELS["kind"].get(v, v),
        host=lambda u: urlparse(u).netloc.removeprefix("www.") or u, safe_url=safe_url,
        ago=ago, longdate=longdate, nicedate=nicedate, days_left=days_left,
    )
    return e


def hourly_cells(entries: list[dict]) -> list[dict]:
    cells = []
    for h in range(23, -1, -1):
        start, end = NOW - timedelta(hours=h + 1), NOW - timedelta(hours=h)
        hits = [e for e in entries if (d := _dt(e.get("first_seen"))) and start < d <= end]
        cells.append({"n": len(hits), "kev": any(e["kind"] == "KEV" for e in hits),
                      "label": end.strftime("%H:00 UTC")})
    return cells


def rss(briefs: list[dict], p: dict, base: str) -> str:
    items = []
    for b in briefs[:30]:
        link = f"{base}/brief/{b['run_date']}/"
        pub = datetime.fromisoformat(b["run_date"]).replace(hour=12, tzinfo=timezone.utc)
        body = "".join(f"<p><b>{escape(e['headline'])}</b><br>{escape(e['summary'])}</p>" for e in b["items"])
        items.append(f"<item><title>Threat brief, {escape(longdate(b['run_date']))}</title><link>{link}</link>"
                     f"<guid isPermaLink=\"true\">{link}</guid><pubDate>{format_datetime(pub)}</pubDate>"
                     f"<description>{escape(b.get('executive_pulse', '') + body)}</description></item>")
    return ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
            f"<title>{escape(p['site_title'])}</title><link>{base}/</link>"
            f"<description>Daily source-checked threat brief</description>{''.join(items)}</channel></rss>")


MD = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")   # raw HTML in notes is escaped


def load_notes() -> list[dict]:
    """data/notes/*.md with YAML front matter -> dicts with rendered, escaped HTML."""
    notes = []
    for f in sorted((DATA / "notes").glob("*.md")) if (DATA / "notes").exists() else []:
        raw = f.read_text()
        if not raw.startswith("---"):
            continue
        _, front, body = raw.split("---", 2)
        meta = yaml.safe_load(front) or {}
        meta["date"] = str(meta.get("date", f.stem[:10]))
        if meta.get("updated"):
            meta["updated"] = str(meta["updated"])
        meta.update(slug=f.stem, html=Markup(MD.render(body)), tags=meta.get("tags", []), tlp=meta.get("tlp", "CLEAR"))
        notes.append(meta)
    return sorted(notes, key=lambda n: n["date"], reverse=True)


def gate_profile(p, preview: bool):
    """Items marked `confirm: true` are drafts: shown (flagged) in preview builds, never published."""
    if isinstance(p, dict):
        return {k: gate_profile(v, preview) for k, v in p.items()
                if preview or not (isinstance(v, dict) and v.get("confirm"))}
    if isinstance(p, list):
        return [gate_profile(x, preview) for x in p
                if preview or not (isinstance(x, dict) and x.get("confirm"))]
    return p


def build(out: Path) -> None:
    preview = os.environ.get("WF_PREVIEW") == "1"
    p = gate_profile(yaml.safe_load((SITE / "profile.yaml").read_text()), preview)
    p["preview"] = preview
    sys.path.insert(0, str(ROOT))
    from digest.config import load_config  # noqa: PLC0415
    cfg = load_config()
    base = (cfg.get("site", {}).get("url") or "").rstrip("/")
    p["site_url"] = base
    briefs = sorted((json.loads(f.read_text()) for f in (DATA / "briefs").glob("*.json")),
                    key=lambda b: b["run_date"], reverse=True) if (DATA / "briefs").exists() else []
    watch = json.loads((DATA / "watch.json").read_text()) if (DATA / "watch.json").exists() else {"entries": []}
    due_soon = sum(1 for e in watch["entries"] if e.get("kev_due") and 0 <= days_left(e["kev_due"]) <= 14)

    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(SITE / "static", out / "static")
    E = env()

    def page(tpl: str, path: str, page_key: str, **ctx):
        depth = path.count("/")
        root = "../" * depth if depth else "./"
        dest = out / path / "index.html" if path else out / "index.html"
        if tpl == "404.html":
            dest, root = out / "404.html", "/" if not base else base + "/"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(E.get_template(tpl).render(p=p, root=root, page=page_key, **ctx))

    today = briefs[0] if briefs else None
    cells = hourly_cells(watch["entries"])
    ld = {"@context": "https://schema.org", "@type": "Person", "name": p["name"], "jobTitle": p["headline"],
          "sameAs": [l["url"] for l in p.get("links", []) if l["url"].startswith("http") and "[" not in l["url"]],
          "knowsAbout": [n["title"] for n in p.get("niches", [])]}
    if p.get("photo") and base:
        ld["image"] = base + "/static/portrait-og.jpg"
    if base:
        ld["url"] = base + "/"
    page("home.html", "", "", brief=today, watch=watch, cells=cells, watch_due_soon=due_soon,
         brief_count=len(briefs), latest_note=(load_notes() or [None])[0], person_ld=Markup(json.dumps(ld).replace("</", "<\\/")))
    page("today.html", "today/", "today/", brief=today, watch=watch, cells=cells, watch_due_soon=due_soon)
    for b in briefs:
        page("brief.html", f"brief/{b['run_date']}/", "archive/", brief=b)
    page("archive.html", "archive/", "archive/", briefs=briefs)
    page("watch.html", "watch/", "watch/", watch=watch, retain_days=cfg.get("watch", {}).get("retain_days", 7))
    health = json.loads((DATA / "sources.json").read_text()) if (DATA / "sources.json").exists() else {}
    page("method.html", "method/", "method/", sources=cfg["sources"]["apis"] + cfg["sources"]["feeds"],
         health={k: v.get("status", "–") if isinstance(v, dict) else v for k, v in health.get("status", {}).items()})
    notes = load_notes()
    page("notes.html", "notes/", "notes/", notes=notes)
    for n in notes:
        page("note.html", f"notes/{n['slug']}/", "notes/", n=n)
    page("404.html", "", "")

    (out / "api").mkdir()
    (out / "api" / "latest.json").write_text(json.dumps(today or {}, indent=1, ensure_ascii=False))
    (out / "api" / "watch.json").write_text(json.dumps(watch, indent=1, ensure_ascii=False))
    (out / "feed.xml").write_text(rss(briefs, p, base))
    (out / "robots.txt").write_text("User-agent: *\nAllow: /\n")
    (out / ".nojekyll").write_text("")
    print(f"built {out} ({len(briefs)} briefs, {len(watch['entries'])} watch entries)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "_site"))
    build(Path(ap.parse_args().out))
