"""Per-CVE exploit timelines and detection pointers (data/cve_timeline.json), updated by the hourly watch.

Tracked CVEs: every CVE in a brief from the last 90 days or in the watch. For each, the earliest known:
  published         NVD publication date (one NVD lookup per CVE, then cached)
  kev_added / due   CISA KEV catalogue, with known ransomware use
  vendor_advisory   first vendor or authority advisory naming the CVE, as seen by Watchfloor
  poc_first_seen    creation date of the earliest public PoC repository (nomi-sec/PoC-in-GitHub)
  watchfloor_first  first brief or watch entry that carried it
plus a daily EPSS series (last 60 days) and detection pointers: SigmaHQ rules and ProjectDiscovery nuclei
templates whose file path names the CVE (two repository-index reads a day, no code search).

Dates "as seen by Watchfloor" are when this project first observed something, not when it first happened;
the site labels them that way.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from . import collectors as C

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "cve_timeline.json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
log = logging.getLogger(__name__)
DETECTION_REPOS = {   # name: (repo, branch, url prefix for a file)
    "Sigma": ("SigmaHQ/sigma", "master", "https://github.com/SigmaHQ/sigma/blob/master/"),
    "Nuclei": ("projectdiscovery/nuclei-templates", "main", "https://github.com/projectdiscovery/nuclei-templates/blob/main/"),
}
ATTACK_RE = re.compile(r"^\s*-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.I | re.M)
MAX_RULE_FETCHES = 20         # Sigma rule bodies read per run, for their ATT&CK tags
MAX_NVD_LOOKUPS = 25          # per run, so a backlog never exhausts the NVD rate limit
MAX_POC_LOOKUPS = 40


def tracked_cves(root: Path, now: datetime, watch_entries: list[dict]) -> dict[str, dict]:
    """CVE -> {'title', 'briefs': [dates], 'watch_first'}."""
    out: dict[str, dict] = {}
    cut = (now - timedelta(days=90)).date().isoformat()
    for f in sorted((root / "data" / "briefs").glob("*.json")):
        if f.stem < cut:
            continue
        b = json.loads(f.read_text())
        for e in b.get("items", []):
            for c in {x.upper() for x in CVE_RE.findall(" ".join(e.get("identifiers") or []))}:
                t = out.setdefault(c, {"title": "", "briefs": []})
                t["title"] = t["title"] or e.get("headline", "")
                if b["run_date"] not in t["briefs"]:
                    t["briefs"].append(b["run_date"])
    for w in watch_entries:
        for c in {x.upper() for x in w.get("cves", [])}:
            t = out.setdefault(c, {"title": "", "briefs": []})
            t["title"] = t["title"] or w.get("title", "")
            fs = (w.get("first_seen") or "")[:10]
            if fs and (not t.get("watch_first") or fs < t["watch_first"]):
                t["watch_first"] = fs
    return out


def nvd_published(cve: str) -> str | None:
    hdr = {**C.UA, **({"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {})}
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, headers=hdr, timeout=30)
    r.raise_for_status()
    v = r.json().get("vulnerabilities") or []
    return (v[0]["cve"].get("published") or "")[:10] or None if v else None


def detection_index() -> dict[str, list[dict]]:
    """CVE -> [{'kind','path','url'}] from the two repositories' file trees (one API call each)."""
    hdr = {**C.UA, "Accept": "application/vnd.github+json",
           **({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"} if os.environ.get("GITHUB_TOKEN") else {})}
    out: dict[str, list[dict]] = {}
    for kind, (repo, branch, prefix) in DETECTION_REPOS.items():
        try:
            r = requests.get(f"https://api.github.com/repos/{repo}/git/trees/{branch}", params={"recursive": "1"},
                             headers=hdr, timeout=60)
            r.raise_for_status()
            tree = r.json()
        except (requests.RequestException, ValueError) as e:
            log.warning("detection index: %s unavailable (%s)", repo, e)
            continue
        if tree.get("truncated"):
            log.warning("detection index: %s tree truncated; some files missed", repo)
        for node in tree.get("tree", []):
            p = node.get("path", "")
            if node.get("type") != "blob" or not p.endswith((".yml", ".yaml")):
                continue
            for c in {x.upper() for x in CVE_RE.findall(p)}:
                out.setdefault(c, []).append({"kind": kind, "path": p, "url": prefix + p})
    return out


def attack_tags(path: str) -> list[str]:
    """ATT&CK technique ids a SigmaHQ rule declares in its own tags (e.g. attack.t1190). Read, never inferred."""
    try:
        r = requests.get(f"https://raw.githubusercontent.com/SigmaHQ/sigma/master/{path}", headers=C.UA, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        log.warning("sigma rule %s unavailable (%s)", path, e)
        return []
    return sorted({t.upper() for t in ATTACK_RE.findall(r.text)})


def update(now: datetime, kev: dict, items: list[dict], watch_entries: list[dict], tiers: dict,
           root: Path = ROOT, fetch: bool = True) -> dict:
    data = json.loads((root / "data" / "cve_timeline.json").read_text()) if (root / "data" / "cve_timeline.json").exists() \
        else {"cves": {}, "detections_checked": None}
    cves, today = data["cves"], now.date().isoformat()
    track = tracked_cves(root, now, watch_entries)
    for c, t in track.items():
        rec = cves.setdefault(c, {"cve": c, "events": {}, "epss": [], "briefs": [], "detections": []})
        rec["title"] = rec.get("title") or t["title"][:160]
        rec["briefs"] = sorted(set(rec["briefs"]) | set(t["briefs"]))
        ev = rec["events"]
        first = min([d for d in [*t["briefs"], t.get("watch_first")] if d] or [today])
        if not ev.get("watchfloor_first") or first < ev["watchfloor_first"]["date"]:
            ev["watchfloor_first"] = {"date": first}
        if (k := kev.get(c)) and not ev.get("kev_added"):
            ev["kev_added"] = {"date": k.get("dateAdded"), "due": k.get("dueDate"),
                               "ransomware": k.get("knownRansomwareCampaignUse"), "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}
    # facts that this run's collected items carry: vendor advisories, PoCs, EPSS
    for it in items:
        tier = tiers.get(it.get("source_name"), "")
        for c in {x.upper() for x in it.get("cves", [])} & cves.keys():
            ev = cves[c]["events"]
            day = (it.get("published") or today)[:10]
            if tier in ("vendor", "authority") and it.get("source_name") != "CISA KEV" and \
                    (not ev.get("vendor_advisory") or day < ev["vendor_advisory"]["date"]):
                ev["vendor_advisory"] = {"date": day, "source": it["source_name"], "url": it["url"]}
            if (it.get("public_poc") or {}).get("count") and not ev.get("poc_first_seen"):
                ev["poc_first_seen"] = {"date": it["public_poc"].get("first") or today, "count": it["public_poc"]["count"],
                                        "url": f"https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{c.split('-')[1]}/{c}.json"}
    if fetch:
        live = [c for c, r in cves.items() if c in track]
        need_pub = [c for c in live if not cves[c]["events"].get("published")][:MAX_NVD_LOOKUPS]
        for c in need_pub:
            try:
                if (d := nvd_published(c)):
                    cves[c]["events"]["published"] = {"date": d, "url": f"https://nvd.nist.gov/vuln/detail/{c}"}
            except requests.RequestException as e:
                log.info("NVD lookup %s: %s", c, e)
                break
        need_epss = [c for c in live if not (cves[c]["epss"] and cves[c]["epss"][-1]["date"] == today)]
        if need_epss:                                    # one EPSS point per CVE per day
            scores = C.epss_scores(need_epss)
            for c in need_epss:
                if c in scores:
                    cves[c]["epss"] = (cves[c]["epss"] + [{"date": today, "score": scores[c]["score"]}])[-60:]
        if data.get("detections_checked") != today:
            no_poc = [c for c in live if not cves[c]["events"].get("poc_first_seen")][:MAX_POC_LOOKUPS]
            for c, p in C.poc_counts(no_poc, limit=MAX_POC_LOOKUPS).items():
                if p.get("count"):
                    cves[c]["events"]["poc_first_seen"] = {"date": p.get("first") or today, "count": p["count"],
                                                          "url": f"https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{c.split('-')[1]}/{c}.json"}
            idx = detection_index()
            if idx:
                for c in live:
                    found = idx.get(c, [])
                    if found and not cves[c]["detections"]:
                        cves[c]["events"]["detection_seen"] = {"date": today, "count": len(found)}
                    old = {d["path"]: d for d in cves[c]["detections"]}
                    cves[c]["detections"] = [{**d, **({"attack": old[d["path"]]["attack"]} if "attack" in old.get(d["path"], {}) else {})}
                                             for d in found[:8]]
                budget = MAX_RULE_FETCHES
                for c in live:
                    for d in cves[c]["detections"]:
                        if d["kind"] == "Sigma" and "attack" not in d and budget > 0:
                            d["attack"], budget = attack_tags(d["path"]), budget - 1
                data["detections_checked"] = today
    data["updated"] = now.isoformat(timespec="seconds")
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "data" / "cve_timeline.json").write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    return data


def ordered_events(rec: dict) -> list[dict]:
    """Events oldest first, each with days since the first event (for the page)."""
    names = {"published": "CVE published", "vendor_advisory": "Vendor advisory seen", "kev_added": "Added to CISA KEV",
             "poc_first_seen": "First public PoC", "detection_seen": "Public detection seen", "watchfloor_first": "First in Watchfloor"}
    evs = [{"key": k, "label": names[k], **v} for k, v in rec.get("events", {}).items() if k in names and v.get("date")]
    evs.sort(key=lambda e: (e["date"], list(names).index(e["key"])))
    if evs:
        d0 = datetime.fromisoformat(evs[0]["date"])
        for e in evs:
            e["day"] = (datetime.fromisoformat(e["date"]) - d0).days
    return evs


# ---------- Anatomy of a bug: the gaps between milestones, compared with every tracked CVE ----------

GAPS = [  # (key, from-event, to-event, phrase)
    ("poc", "published", "poc_first_seen", "from publication to the first public proof of concept"),
    ("kev", "published", "kev_added", "from publication to CISA confirming exploitation"),
    ("detect", "published", "detection_seen", "from publication to the first public detection rule"),
    ("blind", "poc_first_seen", "detection_seen", "with public exploit code and no public detection"),
    ("deadline", "kev_added", "kev_due", "between the KEV listing and the federal due date"),
]


def _date(rec: dict, key: str) -> datetime | None:
    ev = rec.get("events", {})
    s = (ev.get("kev_added") or {}).get("due") if key == "kev_due" else (ev.get(key) or {}).get("date")
    try:
        return datetime.fromisoformat(s) if s else None
    except ValueError:
        return None


def gaps(rec: dict) -> dict[str, int]:
    out = {}
    for k, a, b, _ in GAPS:
        da, db = _date(rec, a), _date(rec, b)
        if da and db:
            out[k] = (db - da).days
    return out


def _say(n: int) -> str:
    return "the same day" if n == 0 else (f"{n} day{'' if n == 1 else 's'}" if n > 0 else f"{-n} day{'' if n == -1 else 's'} before")


def anatomy(rec: dict, all_recs: dict) -> dict:
    """Deterministic narrative and comparisons for one CVE. Every number is a date difference from the record."""
    g = gaps(rec)
    pool = {k: sorted(x for r in all_recs.values() if (x := gaps(r).get(k)) is not None) for k, *_ in GAPS}
    rows = []
    for k, _, _, phrase in GAPS:
        if k not in g:
            continue
        p = pool[k]
        faster = sum(1 for x in p if x > g[k])
        rows.append({"key": k, "days": g[k], "phrase": phrase, "median": p[len(p) // 2] if p else None, "n": len(p),
                     "faster_than": round(100 * faster / len(p)) if len(p) >= 5 and k != "deadline" else None})
    ev = rec.get("events", {})
    story = []
    if "published" in ev:
        story.append(f"NVD published the CVE on {datetime.fromisoformat(ev['published']['date']):%-d %B %Y}.")
    if "poc" in g:
        n = (ev.get("poc_first_seen") or {}).get("count")
        story.append(f"Public proof-of-concept code appeared {_say(g['poc'])}" + (" after that" if g["poc"] > 0 else "")
                     + (f" ({n} repositor{'y' if n == 1 else 'ies'} so far)." if n else "."))
    if "kev" in g:
        story.append(f"CISA confirmed exploitation in the wild {_say(g['kev'])}" + (" after publication" if g["kev"] > 0 else "")
                     + f", and set a federal due date {_say(g.get('deadline', 0))} after the listing." if "deadline" in g else ".")
    if "detect" in g:
        story.append(f"The first public detection rule showed up {_say(g['detect'])} after publication.")
    elif "poc_first_seen" in ev:
        story.append("No public Sigma rule or nuclei template names it yet, so defenders still write their own.")
    return {"gaps": g, "rows": rows, "story": story}


def axis(rec: dict, width: int = 760) -> dict | None:
    """Positions for a horizontal timeline drawing (SVG in the page): days on a shared scale."""
    evs = ordered_events(rec)
    due = _date(rec, "kev_due")
    if due and evs:
        d0 = datetime.fromisoformat(evs[0]["date"])
        evs = evs + [{"key": "kev_due", "label": "Federal due date", "date": due.date().isoformat(), "day": (due - d0).days}]
    if len(evs) < 2:
        return None
    span = max(e["day"] for e in evs) or 1
    pts = []
    for i, e in enumerate(evs):
        pts.append({**e, "x": 40 + round((width - 80) * e["day"] / span), "row": i % 2})
    return {"width": width, "span": span, "points": pts}
