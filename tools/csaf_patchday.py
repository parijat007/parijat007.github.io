"""Oracle and Cisco patch-day editions (vendor_patchday.yml): facts-only, from the vendors' CSAF files.

Oracle publishes on the third Tuesday of every month: a quarterly Critical Patch Update (CPU) in January,
April, July and October, a monthly Critical Security Patch Update (CSPU) in the other months. Cisco has no
fixed day; it releases bundles of advisories together. A day with at least CISCO_BUNDLE new advisories
(by each advisory's own first-release date, so updates do not count) is treated as a bundle.

No model is involved. Counts, scores and products come from the vendor's CSAF record; "exploited" means
listed in CISA KEV when the edition is built; "remote, no login" is read from the CVSS vector (AV:N, PR:N).
Vendor entries marked not affected (VEX) are left out. Sends to Telegram and saves
data/patchday/<vendor>-<id>.json, which also marks the edition as sent.

    python tools/csaf_patchday.py oracle                       # acts only on the third Tuesday, once
    python tools/csaf_patchday.py oracle --month 2026-Nov      # a given release, any day
    python tools/csaf_patchday.py cisco [--day 2026-11-18]     # default: yesterday (UTC)
    python tools/csaf_patchday.py oracle --fixture f.json --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "patchday"
HDR = {"Accept": "application/json", "User-Agent": "watchfloor (+https://theparijat.com/method/)"}
KEV_URLS = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"]
ORACLE_CSAF = "https://www.oracle.com/docs/tech/security-alerts/{kind}{mon}{year}csaf.json"
ORACLE_PAGE = "https://www.oracle.com/security-alerts/{kind}{mon}{year}.html"
CPU_MONTHS = {1, 4, 7, 10}
CISCO_RSS = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
CISCO_CSAF = ("https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
              "{id}/csaf/{id}_csaf.json")
CISCO_BUNDLE = 5
AFFECTED = ("known_affected", "fixed", "first_fixed", "first_affected", "last_affected", "recommended")


# ---------- reading a CSAF 2.0 document ----------

def product_families(doc: dict) -> dict[str, str]:
    """product_id -> the top-level family or vendor branch it sits under (Oracle: 'Oracle Database Server')."""
    out: dict[str, str] = {}

    def walk(branches, family):
        for b in branches or []:
            fam = family
            if b.get("category") in ("product_family", "product_name") and family is None:
                fam = b.get("name")
            if b.get("product"):
                out[b["product"]["product_id"]] = fam or b["product"].get("name", "")
            walk(b.get("branches"), fam)
    for top in (doc.get("product_tree") or {}).get("branches") or []:
        walk(top.get("branches") if top.get("category") == "vendor" else [top], None)
    return out


def _cvss(v: dict) -> tuple[float | None, str, str]:
    best, sev, vec = None, "", ""
    for s in v.get("scores") or []:
        for k in ("cvss_v4", "cvss_v3", "cvss_v2"):
            c = s.get(k)
            if c and c.get("baseScore") is not None and (best is None or c["baseScore"] > best):
                best, sev, vec = float(c["baseScore"]), (c.get("baseSeverity") or "").title(), c.get("vectorString", "")
    if best is not None and not sev:
        sev = "Critical" if best >= 9 else "High" if best >= 7 else "Medium" if best >= 4 else "Low"
    return best, sev, vec


def summarize_csaf(docs: list[dict], kev: set[str]) -> dict:
    by_cve: dict[str, dict] = {}
    for doc in docs:
        fam = product_families(doc)
        for v in doc.get("vulnerabilities") or []:
            cve = v.get("cve") or ""
            if not cve.startswith("CVE-"):
                continue
            ps = v.get("product_status") or {}
            affected = {p for k in AFFECTED for p in ps.get(k) or []}
            if not affected and ps.get("known_not_affected"):
                continue                               # VEX: vendor says this product is not exploitable
            score, sev, vec = _cvss(v)
            title = (v.get("title") or next((n.get("text", "") for n in v.get("notes") or []
                                            if n.get("category") in ("summary", "description")), ""))
            m = by_cve.setdefault(cve, {"cve": cve, "title": "", "cvss": None, "severity": "", "remote_noauth": False,
                                        "families": set(), "exploited": cve in kev})
            if score is not None and (m["cvss"] is None or score > m["cvss"]):
                m["cvss"], m["severity"] = score, sev
            m["remote_noauth"] |= "AV:N" in vec and "PR:N" in vec
            m["title"] = m["title"] or re.sub(r"\s+", " ", title).strip()[:160]
            m["families"] |= {fam.get(p) for p in affected if fam.get(p)}
    vulns = sorted(by_cve.values(), key=lambda x: (not x["exploited"], -(x["cvss"] or 0), x["cve"]))
    fam_counts = Counter(f for x in vulns for f in x["families"])
    for x in vulns:
        x["families"] = sorted(x["families"])
    return {
        "total": len(vulns),
        "critical": sum(x["severity"] == "Critical" for x in vulns),
        "remote_noauth": sum(x["remote_noauth"] for x in vulns),
        "exploited": [x for x in vulns if x["exploited"]],
        "top": [x for x in vulns if not x["exploited"] and (x["severity"] == "Critical" or x["remote_noauth"])][:8],
        "families": fam_counts.most_common(6),
    }


# ---------- fetching ----------

def kev_ids() -> set[str]:
    for u in KEV_URLS:
        try:
            r = requests.get(u, headers=HDR, timeout=60)
            r.raise_for_status()
            return {x["cveID"] for x in r.json().get("vulnerabilities", [])}
        except (requests.RequestException, ValueError):
            continue
    print("WARNING: CISA KEV unreachable; exploited counts will read 0")
    return set()


def third_tuesday(d: date) -> date:
    first = d.replace(day=1)
    return first + timedelta(days=(1 - first.weekday()) % 7 + 14)


def oracle_release(month: date) -> tuple[str, str, str]:
    """(kind, csaf url, advisory page) for a release month; the CPU months first try 'cpu', others 'cspu'."""
    mon, year = month.strftime("%b").lower(), month.year
    kinds = ["cpu", "cspu"] if month.month in CPU_MONTHS else ["cspu", "cpu"]
    for kind in kinds:
        url = ORACLE_CSAF.format(kind=kind, mon=mon, year=year)
        r = requests.head(url, headers=HDR, timeout=30, allow_redirects=True)
        if r.status_code == 200:
            return kind, url, ORACLE_PAGE.format(kind=kind, mon=mon, year=year)
    return "", "", ""


def cisco_advisories_for(day: date) -> list[dict]:
    r = requests.get(CISCO_RSS, headers={**HDR, "Accept": "application/rss+xml"}, timeout=60)
    r.raise_for_status()
    ids = []
    for item in ET.fromstring(r.content).iter("item"):
        link = (item.findtext("link") or "").strip()
        m = re.search(r"(cisco-sa-[A-Za-z0-9-]+)", link)
        if m and m.group(1) not in ids:
            ids.append(m.group(1))
    docs = []
    for i in ids:
        try:
            d = requests.get(CISCO_CSAF.format(id=i), headers=HDR, timeout=30)
            d.raise_for_status()
            doc = d.json()
        except (requests.RequestException, ValueError):
            continue
        first = ((doc.get("document") or {}).get("tracking") or {}).get("initial_release_date", "")[:10]
        if first == day.isoformat():
            docs.append(doc)
    return docs


# ---------- message ----------

def message(vendor: str, label: str, s: dict, source: str, n_adv: int | None = None) -> str:
    def safe(t: str) -> str:
        return "".join(" " if ch in "*_`[]" else ch for ch in t)

    def line(v):
        bits = [b for b in (f"CVSS {v['cvss']:g}" if v["cvss"] is not None else "",
                            "remote, no login" if v["remote_noauth"] else "",
                            ", ".join(v["families"][:2])) if b]
        return f"• {v['cve']} {safe(v['title'][:70])}" + (f" ({safe('; '.join(bits))})" if bits else "")
    head = f"{s['total']} CVEs" + (f" in {n_adv} advisories" if n_adv else "")
    out = [f"*🩹 {vendor} {label}*",
           f"{head} · {s['critical']} critical · {s['remote_noauth']} exploitable remotely without login · "
           f"{len(s['exploited'])} in CISA KEV"]
    if s["families"]:
        out.append("Most fixes: " + ", ".join(f"{safe(f)} ({n})" for f, n in s["families"]))
    if s["exploited"]:
        out += ["", "*Exploited now (patch first):*", *[line(v) for v in s["exploited"]]]
    if s["top"]:
        out += ["", "*Critical or remote without login:*", *[line(v) for v in s["top"]]]
    out += ["", f"Source: {source}"]
    return "\n".join(out)


def deliver(text: str, out_f: Path, record: dict, dry: bool) -> None:
    print(text)
    if dry:
        return
    out_f.parent.mkdir(parents=True, exist_ok=True)
    out_f.write_text(json.dumps(record, indent=1, default=list) + "\n")
    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        from digest.notify import _telegram  # noqa: PLC0415
        _telegram([text], 0)


def run_oracle(args, now: datetime) -> int:
    month = datetime.strptime(args.month, "%Y-%b").date() if args.month else now.date()
    rid = month.strftime("%Y-%b")
    out_f = OUT / f"oracle-{rid}.json"
    if not (args.month or args.fixture):
        if now.date() != third_tuesday(now.date()):
            print(f"{now.date()} is not Oracle's release day ({third_tuesday(now.date())})")
            return 0
        if out_f.exists():
            print(f"Oracle {rid} already sent")
            return 0
    if args.fixture:
        kind, page, docs = "cspu", "fixture", [json.loads(Path(args.fixture).read_text())]
    else:
        kind, url, page = oracle_release(month)
        if not url:
            print(f"Oracle has not published a CSAF file for {rid} yet")
            return 0
        r = requests.get(url, headers=HDR, timeout=120)
        r.raise_for_status()
        docs = [r.json()]
    s = summarize_csaf(docs, set() if args.fixture else kev_ids())
    name = "Critical Patch Update" if kind == "cpu" else "Critical Security Patch Update"
    label = f"{name}, {month.strftime('%B %Y')}"
    deliver(message("Oracle", label, s, page), out_f, {"vendor": "oracle", "id": rid, "kind": kind, "source": page, **s}, args.dry_run)
    return 0


def run_cisco(args, now: datetime) -> int:
    day = date.fromisoformat(args.day) if args.day else (now - timedelta(days=1)).date()
    out_f = OUT / f"cisco-{day.isoformat()}.json"
    if out_f.exists() and not (args.day or args.fixture):
        print(f"Cisco {day} already sent")
        return 0
    docs = [json.loads(Path(args.fixture).read_text())] if args.fixture else cisco_advisories_for(day)
    if len(docs) < (1 if args.fixture else args.min_advisories):
        print(f"Cisco {day}: {len(docs)} new advisories, below the bundle threshold of {args.min_advisories}")
        return 0
    s = summarize_csaf(docs, set() if args.fixture else kev_ids())
    label = f"security advisory bundle, {day.strftime('%d %B %Y')}"
    src = "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
    advs = [((d.get("document") or {}).get("tracking") or {}).get("id") for d in docs]
    deliver(message("Cisco", label, s, src, n_adv=len(docs)), out_f,
            {"vendor": "cisco", "id": day.isoformat(), "advisories": advs, "source": src, **s}, args.dry_run)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("vendor", choices=["oracle", "cisco"])
    ap.add_argument("--month", help="Oracle release month, e.g. 2026-Nov")
    ap.add_argument("--day", help="Cisco publication day, YYYY-MM-DD")
    ap.add_argument("--fixture")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--min-advisories", type=int, default=CISCO_BUNDLE, help="Cisco bundle threshold (tests)")
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    return run_oracle(args, now) if args.vendor == "oracle" else run_cisco(args, now)


if __name__ == "__main__":
    sys.exit(main())
