"""Monthly CISA KEV trends: every figure computed from the KEV catalog itself, none from a model.

    python -m digest.kev_trends 2026-11        # one month (the current month is "month to date")
    python -m digest.kev_trends --last         # the month that just ended (run on the 1st)

Writes data/trends/YYYY-MM.json. The site renders /trends/ and /trends/YYYY-MM/; the LinkedIn agent can
draft a post from the page (digest/linkedin.py source_from_trends).
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import collectors as C

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "trends"
log = logging.getLogger("digest.kev_trends")

# Names for the weaknesses that appear most in KEV (MITRE CWE titles, shortened).
CWE = {
    "CWE-20": "Improper input validation", "CWE-22": "Path traversal", "CWE-77": "Command injection",
    "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting", "CWE-89": "SQL injection",
    "CWE-94": "Code injection", "CWE-119": "Memory buffer errors", "CWE-120": "Classic buffer overflow",
    "CWE-121": "Stack-based buffer overflow", "CWE-122": "Heap-based buffer overflow",
    "CWE-125": "Out-of-bounds read", "CWE-190": "Integer overflow", "CWE-200": "Information exposure",
    "CWE-269": "Improper privilege management", "CWE-276": "Incorrect default permissions",
    "CWE-284": "Improper access control", "CWE-285": "Improper authorization", "CWE-287": "Improper authentication",
    "CWE-288": "Authentication bypass by alternate path", "CWE-290": "Authentication bypass by spoofing",
    "CWE-306": "Missing authentication for critical function", "CWE-312": "Cleartext storage of sensitive data",
    "CWE-352": "Cross-site request forgery", "CWE-362": "Race condition", "CWE-416": "Use after free",
    "CWE-434": "Unrestricted file upload", "CWE-502": "Deserialization of untrusted data",
    "CWE-522": "Insufficiently protected credentials", "CWE-611": "XML external entity",
    "CWE-636": "Not failing securely", "CWE-668": "Exposure to the wrong sphere", "CWE-693": "Protection mechanism failure",
    "CWE-787": "Out-of-bounds write", "CWE-798": "Hard-coded credentials", "CWE-843": "Type confusion",
    "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization", "CWE-918": "Server-side request forgery",
    "CWE-1321": "Prototype pollution",
}


def _d(s: str) -> date | None:
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def month_entries(kev: dict, ym: str) -> list[dict]:
    return sorted((v for v in kev.values() if str(v.get("dateAdded", "")).startswith(ym)),
                  key=lambda v: (v["dateAdded"], v["cveID"]))


def _ym(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"


def _prev(ym: str, n: int = 1) -> str:
    y, m = map(int, ym.split("-"))
    m -= n
    while m < 1:
        y, m = y - 1, m + 12
    return f"{y:04d}-{m:02d}"


def compute(kev: dict, ym: str, today: date | None = None) -> dict:
    today = today or datetime.now(timezone.utc).date()
    rows = month_entries(kev, ym)
    year = int(ym[:4])
    partial = ym == _ym(today)
    prev = len(month_entries(kev, _prev(ym)))
    last12 = [len(month_entries(kev, _prev(ym, i))) for i in range(1, 13)]
    vendors = Counter(v["vendorProject"] for v in rows)
    products = Counter(f"{v['vendorProject']} {v['product']}" for v in rows)
    cwes = Counter(c for v in rows for c in (v.get("cwes") or []))
    from .affected import CATEGORIES, classify  # noqa: PLC0415
    cats = Counter(classify(v["vendorProject"], v["product"], v.get("vulnerabilityName", "")) for v in rows)
    ransomware = [v for v in rows if v.get("knownRansomwareCampaignUse") == "Known"]
    old = [v for v in rows if int(v["cveID"].split("-")[1]) <= year - 2]
    def windows(rs):
        w = sorted((_d(v["dueDate"]) - _d(v["dateAdded"])).days for v in rs if _d(v.get("dueDate")) and _d(v["dateAdded"]))
        return w[len(w) // 2] if w else None
    due_soon = sorted((v for v in rows if _d(v.get("dueDate")) and 0 <= (_d(v["dueDate"]) - today).days <= 7),
                      key=lambda v: v["dueDate"])
    top_vendor = vendors.most_common(1)[0] if vendors else None
    actions = []
    if due_soon:
        actions.append({"verb": "Patch", "text": f"{len(due_soon)} of this month's entries reach their federal due date "
                        f"within a week (first: {due_soon[0]['cveID']}, {due_soon[0]['vendorProject']} "
                        f"{due_soon[0]['product']}, due {due_soon[0]['dueDate']})."})
    if top_vendor and top_vendor[1] > 1:
        actions.append({"verb": "Inventory", "text": f"Check exposure to {top_vendor[0]} first: {top_vendor[1]} of "
                        f"{len(rows)} entries this month."})
    if old:
        actions.append({"verb": "Inventory", "text": f"{len(old)} entries carry CVE ids from {year - 2} or earlier: "
                        "old, unpatched systems are still being exploited, so include end-of-life assets in the scan."})
    if ransomware:
        actions.append({"verb": "Hunt", "text": "Known ransomware use: " + ", ".join(
            f"{v['cveID']} ({v['vendorProject']} {v['product']})" for v in ransomware[:5]) + "."})
    return {
        "month": ym, "partial": partial, "through": today.isoformat() if partial else None,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "total": len(rows), "previous_month": prev,
        "avg_12m": round(sum(last12) / 12, 1) if last12 else None,
        "vendors": vendors.most_common(8), "products": products.most_common(5),
        "cwes": [[c, CWE.get(c, ""), n] for c, n in cwes.most_common(6)],
        "categories": [[c, CATEGORIES[c], n] for c, n in cats.most_common(8)],
        "ransomware_known": len(ransomware), "old_cves": len(old), "old_cutoff_year": year - 2,
        "median_window": windows(rows), "median_window_prev": windows(month_entries(kev, _prev(ym))),
        "actions": actions,
        "entries": [{"cve": v["cveID"], "vendor": v["vendorProject"], "product": v["product"],
                     "name": v.get("vulnerabilityName", ""), "added": v["dateAdded"], "due": v.get("dueDate"),
                     "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "cwes": v.get("cwes") or [],
                     "category": classify(v["vendorProject"], v["product"], v.get("vulnerabilityName", ""))}
                    for v in rows],
    }


def visual(t: dict) -> dict:
    """The LinkedIn image for a trends post: figures only, all from the computed data."""
    label = datetime.strptime(t["month"], "%Y-%m").strftime("%B %Y")
    figs = [{"value": str(t["total"]), "label": f"CVEs added to CISA KEV{' so far' if t['partial'] else ''}",
             "state": "confirmed"}]
    figs.append({"value": str(t["ransomware_known"]), "label": "with known ransomware use (CISA)", "state": "confirmed"})
    figs.append({"value": str(t["old_cves"]), "label": f"with CVE ids from {t['old_cutoff_year']} or earlier",
                 "state": "confirmed"})
    return {"kicker": "Monthly KEV trends", "title": f"What attackers exploited in {label}",
            "bars_title": "Most listed vendors (CISA KEV entries)", "bars": [list(x) for x in t["vendors"][:6]],
            "figures": figs, "footer_left": "Every entry and the method in the full page"}


def write(t: dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    f = OUT / f"{t['month']}.json"
    f.write_text(json.dumps(t, indent=1, ensure_ascii=False) + "\n")
    return f


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("month", nargs="?", help="YYYY-MM (default: this month to date)")
    ap.add_argument("--last", action="store_true", help="the month that just ended")
    a = ap.parse_args()
    today = datetime.now(timezone.utc).date()
    ym = _ym(today.replace(day=1) - timedelta(days=1)) if a.last else (a.month or _ym(today))
    t = compute(C.load_kev(), ym, today)
    log.info("KEV %s: %d added (previous month %d, 12-month average %s) -> %s", ym, t["total"], t["previous_month"],
             t["avg_12m"], write(t).relative_to(ROOT))


if __name__ == "__main__":
    main()
