"""Static site build: data/*.json + site/templates -> _site/ (deployed to GitHub Pages).

  python site/build.py            # build into _site/
  python site/build.py --out DIR

No JavaScript framework and no build toolchain: pages are pre-rendered and auto-escaped,
so text from feeds or the model can never run as script on the page.
"""
from __future__ import annotations

import argparse
import json
import re
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


def _riskline(r):
    sys.path.insert(0, str(ROOT))
    from digest.render import risk_line
    return risk_line(r)


def env() -> Environment:
    e = Environment(loader=FileSystemLoader(SITE / "templates"), autoescape=select_autoescape(["html", "xml"]),
                    trim_blocks=True, lstrip_blocks=True)
    e.filters.update(
        sev=lambda v: LABELS["sev"].get(v, v), xlabel=lambda v: LABELS["x"].get(v, v),
        cat=lambda v: LABELS["cat"].get(v, v), kindlabel=lambda v: LABELS["kind"].get(v, v),
        host=lambda u: urlparse(u).netloc.removeprefix("www.") or u, safe_url=safe_url,
        ago=ago, longdate=longdate, nicedate=nicedate, days_left=days_left, riskline=_riskline,
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


def slugify(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")


AI_TOPIC = "AI Security"


def topic_feeds(briefs: list[dict], watch: dict, watchlist: list[str], base: str) -> dict[str, dict]:
    """One feed per watchlist product plus AI Security: brief items and watch entries tagged with it."""
    topics = {slugify(n): {"name": n, "items": []} for n in [*watchlist, AI_TOPIC]}
    by_name = {n.lower(): slugify(n) for n in watchlist}
    for b in briefs[:60]:
        pub = datetime.fromisoformat(b["run_date"]).replace(hour=12, tzinfo=timezone.utc)
        for e in b.get("items", []):
            keys = {by_name[m.lower()] for m in e.get("stack_match") or [] if m.lower() in by_name}
            if e.get("category") == "AI_THREAT" or "llm" in {m.lower() for m in e.get("stack_match") or []}:
                keys.add(slugify(AI_TOPIC))
            link = f"{base}/brief/{b['run_date']}/#item-{e['rank']}"
            for k in keys:
                topics[k]["items"].append({"title": e["headline"], "link": link, "pub": pub, "desc": e.get("summary", "")})
    for w in watch.get("entries", []):
        try:
            pub = datetime.fromisoformat((w.get("first_seen") or w.get("published") or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        for m in w.get("stack_match") or []:
            k = by_name.get(m.lower())
            if k:
                topics[k]["items"].append({"title": w.get("title", ""), "link": safe_url(w.get("url")) or f"{base}/watch/",
                                           "pub": pub, "desc": w.get("summary", "")})
    for t in topics.values():
        t["items"].sort(key=lambda i: i["pub"], reverse=True)
        t["items"] = t["items"][:40]
    return topics


def topic_rss(t: dict, slug: str, p: dict, base: str) -> str:
    items = "".join(
        f"<item><title>{escape(i['title'])}</title><link>{escape(i['link'])}</link>"
        f"<guid isPermaLink=\"false\">{escape(i['link'] + '|' + i['title'][:60])}</guid>"
        f"<pubDate>{format_datetime(i['pub'])}</pubDate><description>{escape(i['desc'])}</description></item>"
        for i in t["items"])
    return ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
            f"<title>{escape(p['site_title'])}: {escape(t['name'])}</title><link>{base}/feeds/</link>"
            f"<description>Exploited and critical issues touching {escape(t['name'])}, from the daily brief and hourly watch</description>"
            f"{items}</channel></rss>")


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
        n_tab = iter(range(1, 1000))
        rendered = re.sub(r"<table>", lambda _: f'<div class="scroll" tabindex="0" role="region" '
                          f'aria-label="Table {next(n_tab)}"><table>', MD.render(body))
        rendered = rendered.replace("</table>", "</table></div>").replace("<pre>", '<pre tabindex="0">')
        # ^ keyboard users can scroll wide tables and code; each region gets a unique label
        meta.update(slug=f.stem, html=Markup(rendered), tags=meta.get("tags", []), tlp=meta.get("tlp", "CLEAR"))
        notes.append(meta)
    return sorted(notes, key=lambda n: n["date"], reverse=True)


def _norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def _doi(u: str | None) -> str | None:
    m = re.search(r"doi\.org/(10\.\S+)", u or "", re.I)
    return m.group(1).lower() if m else None


def merge_publications(manual: list[dict], orcid: dict | None) -> list[dict]:
    """Hand-kept list first (authoritative); ORCID works not already listed (by DOI or title) added after it."""
    pubs = list(manual or [])
    seen_doi = {d for d in (_doi(w.get("url")) for w in pubs) if d}
    seen_title = {_norm_title(w.get("title", "")) for w in pubs}
    for w in (orcid or {}).get("works", []):
        if (w.get("doi") or "").lower() in seen_doi or _norm_title(w["title"]) in seen_title:
            continue
        pubs.append({"title": w["title"], "venue": w.get("venue") or (w.get("type") or "").capitalize() or "ORCID record",
                     "status": "published", "year": w.get("year") or "", "url": w.get("url"), "via_orcid": True})
    return pubs


def ledger_view(entries: list[dict]) -> dict:
    """What the corrections page shows: every replacement or correction, newest first, plus totals."""
    fixes = [e for e in entries if e.get("reason") in ("replaced", "correction")]
    return {"fixes": list(reversed(fixes)), "total": len(entries),
            "briefs": len({e["file"] for e in entries}), "head": entries[-1]["hash"] if entries else None}


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
    orcid = json.loads((DATA / "orcid.json").read_text()) if (DATA / "orcid.json").exists() else None
    p["publications"] = merge_publications(p.get("publications"), orcid)
    p["orcid_synced"] = orcid.get("fetched_at") if orcid else None
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
    shutil.copyfile(SITE / "static" / "favicon.ico", out / "favicon.ico")   # browsers ask for /favicon.ico
    E = env()
    tl = json.loads((DATA / "cve_timeline.json").read_text()) if (DATA / "cve_timeline.json").exists() else {"cves": {}}
    E.globals["cve_pages"] = set(tl["cves"])          # identifiers that link to a timeline page

    sitemap: list[tuple[str, str | None]] = []

    def page(tpl: str, path: str, page_key: str, lastmod: str | None = None, **ctx):
        if tpl != "404.html":
            sitemap.append((path, lastmod))
        depth = path.count("/")
        root = "../" * depth if depth else "./"
        dest = out / path / "index.html" if path else out / "index.html"
        if tpl == "404.html":
            dest, root = out / "404.html", "/" if not base else base + "/"
        dest.parent.mkdir(parents=True, exist_ok=True)
        canon = None if tpl == "404.html" else path
        dest.write_text(E.get_template(tpl).render(p=p, root=root, page=page_key, path=canon, **ctx))

    today = briefs[0] if briefs else None
    cells = hourly_cells(watch["entries"])
    ld = {"@context": "https://schema.org", "@type": "Person", "name": p["name"], "jobTitle": p["headline"],
          "sameAs": [l["url"] for l in p.get("links", []) if l["url"].startswith("http") and "[" not in l["url"]],
          "knowsAbout": [n["title"] for n in p.get("niches", [])]}
    if p.get("photo") and base:
        ld["image"] = base + "/static/portrait-og.jpg"
    if base:
        ld["url"] = base + "/"
    page("home.html", "", "", og_type="profile", brief=today, watch=watch, cells=cells, watch_due_soon=due_soon,
         brief_count=len(briefs), latest_note=(load_notes() or [None])[0], person_ld=Markup(json.dumps(ld).replace("</", "<\\/")))
    page("today.html", "today/", "today/", brief=today, watch=watch, cells=cells, watch_due_soon=due_soon,
         og_image=f"og/brief-{today['run_date']}.png" if today else None)
    sys.path.insert(0, str(SITE / "og"))
    from cards import TOOLING, card  # noqa: PLC0415
    card(out / "og" / "site.png", "Daily threat brief · hourly watch", "Exploited vulnerabilities and attacks, checked against their sources",
         "Free, public sources only. No trackers.")
    for b in briefs:
        n = len(b.get("items", []))
        ex = sum(e.get("exploitation") == "EXPLOITED_CONFIRMED" for e in b.get("items", []))
        top = b["items"][0]["headline"] if n else "Quiet day: nothing met the bar."
        detail = (f"{n} item{'s' if n != 1 else ''}" + (f", {ex} exploited (confirmed)" if ex else "") + f". {top}") if n else top
        card(out / "og" / f"brief-{b['run_date']}.png", "Threat brief", longdate(b["run_date"]), detail)
        page("brief.html", f"brief/{b['run_date']}/", "archive/", lastmod=b["run_date"], og_type="article", brief=b,
             og_image=f"og/brief-{b['run_date']}.png")
    page("archive.html", "archive/", "archive/", briefs=briefs)
    page("watch.html", "watch/", "watch/", watch=watch, retain_days=cfg.get("watch", {}).get("retain_days", 7))
    health = json.loads((DATA / "sources.json").read_text()) if (DATA / "sources.json").exists() else {}
    page("method.html", "method/", "method/", sources=cfg["sources"]["apis"] + cfg["sources"]["feeds"],
         health={k: v.get("status", "–") if isinstance(v, dict) else v for k, v in health.get("status", {}).items()})
    notes = load_notes()
    page("notes.html", "notes/", "notes/", notes=notes)
    for n in notes:
        card(out / "og" / f"note-{n['slug']}.png", "Analyst note", n["title"], n.get("summary", ""), accent=TOOLING)
        page("note.html", f"notes/{n['slug']}/", "notes/", lastmod=str(n["date"]), og_type="article", n=n,
             og_image=f"og/note-{n['slug']}.png")
    from digest.ledger import read as read_ledger  # noqa: PLC0415
    ledger = read_ledger(ROOT)
    page("corrections.html", "corrections/", "corrections/", ledger=ledger_view(ledger))
    page("security.html", "security/", "security/", ledger=ledger_view(ledger),
         repo=(p.get("repo_url") or "").removeprefix("https://github.com/").strip("/"))
    perf = json.loads((DATA / "perf.json").read_text()) if (DATA / "perf.json").exists() else None
    page("status.html", "status/", "status/", perf=perf)
    topics = topic_feeds(briefs, watch, cfg.get("stack_watchlist", []), base)
    page("feeds.html", "feeds/", "feeds/", topics=topics)
    sys.path.insert(0, str(ROOT))
    from digest.timeline import anatomy, axis, gaps, ordered_events  # noqa: PLC0415
    tracked = len(tl["cves"])
    for cid, rec in tl["cves"].items():
        page("cve.html", f"cve/{cid}/", "watch/", rec=rec, events=ordered_events(rec), an=anatomy(rec, tl["cves"]),
             ax=axis(rec), tracked=tracked, lastmod=(rec.get("epss") or [{}])[-1].get("date"))
    an_rows = sorted(({"cve": cid, "title": rec.get("title", ""), "gaps": gaps(rec)} for cid, rec in tl["cves"].items()),
                     key=lambda r: (r["gaps"].get("kev", 10**6), r["gaps"].get("poc", 10**6), r["cve"]))

    def _median(k):
        v = sorted(r["gaps"][k] for r in an_rows if k in r["gaps"])
        return v[len(v) // 2] if v else None
    page("cve_index.html", "cve/", "watch/", rows=an_rows, tracked=tracked,
         med={k: _median(k) for k in ("poc", "kev", "detect")})
    page("404.html", "", "")

    (out / "api").mkdir()
    (out / "api" / "latest.json").write_text(json.dumps(today or {}, indent=1, ensure_ascii=False))
    (out / "api" / "watch.json").write_text(json.dumps(watch, indent=1, ensure_ascii=False))
    if (DATA / "ledger.jsonl").exists():   # the public copy anyone can verify against
        shutil.copyfile(DATA / "ledger.jsonl", out / "api" / "ledger.jsonl")
    (out / "feed.xml").write_text(rss(briefs, p, base))
    (out / "feeds").mkdir(exist_ok=True)
    for slug, t in topics.items():
        (out / "feeds" / f"{slug}.xml").write_text(topic_rss(t, slug, p, base))
    robots = "User-agent: *\nAllow: /\n" + (f"Sitemap: {base}/sitemap.xml\n" if base else "")
    (out / "robots.txt").write_text(robots)
    if base:
        urls = "".join(f"<url><loc>{base}/{pth}</loc>" + (f"<lastmod>{lm}</lastmod>" if lm else "") + "</url>\n"
                       for pth, lm in sitemap)
        (out / "sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?>\n'
                                         '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + urls + "</urlset>\n")
    (out / ".nojekyll").write_text("")
    sc = p.get("security_contact")
    sc = sc.get("address") if isinstance(sc, dict) else sc
    if base and sc:
        # RFC 9116: tells researchers how to report a problem with this site
        expires = (NOW + timedelta(days=330)).strftime("%Y-%m-%dT00:00:00Z")
        (out / ".well-known").mkdir(exist_ok=True)
        (out / ".well-known" / "security.txt").write_text(
            f"Contact: {sc}\nExpires: {expires}\nPreferred-Languages: en\n"
            f"Canonical: {base}/.well-known/security.txt\nPolicy: {base}/method/\n")
    write_manifest(out)
    print(f"built {out} ({len(briefs)} briefs, {len(watch['entries'])} watch entries)")


def write_manifest(out: Path) -> None:
    """build.json: the commit this site was built from and a SHA-256 per file.
    tools/site_check.py compares the live site against it every day (tamper check)."""
    import hashlib
    import os
    import subprocess
    commit = os.environ.get("GITHUB_SHA") or subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    files = {str(f.relative_to(out)): hashlib.sha256(f.read_bytes()).hexdigest()
             for f in sorted(out.rglob("*")) if f.is_file() and f.name != "build.json"}
    sys.path.insert(0, str(ROOT))
    from digest.ledger import head as ledger_head
    (out / "build.json").write_text(json.dumps({"commit": commit, "built_at": NOW.isoformat(timespec="seconds"),
                                               "ledger_head": ledger_head(ROOT), "files": files}, indent=1))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "_site"))
    build(Path(ap.parse_args().out))
