"""Patch Tuesday edition (patchday.yml): a facts-only summary of Microsoft's monthly release.

Reads Microsoft's public CVRF API (no key), counts what was fixed, and lists the CVEs Microsoft
marks as exploited or publicly disclosed, then the critical ones. No model is involved: every line
comes from Microsoft's own record. Sends it to Telegram and saves data/patchday/<YYYY-Mon>.json.

    python tools/patchday.py                    # only acts on the second Tuesday (UTC), once
    python tools/patchday.py --month 2026-Nov   # a given month, any day
    python tools/patchday.py --fixture f.json --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
API = "https://api.msrc.microsoft.com/cvrf/v3.0"
HDR = {"Accept": "application/json", "User-Agent": "watchfloor (+https://theparijat.com/method/)"}
THREAT_IMPACT, THREAT_EXPLOIT, THREAT_SEVERITY = 0, 1, 3
NOTE_ACTION, NOTE_CNA = 6, 8     # "Customer Action Required" Yes/No; the CNA that assigned the CVE


def is_patch_tuesday(d: datetime) -> bool:
    return d.weekday() == 1 and 8 <= d.day <= 14


def _val(x) -> str:
    return (x or {}).get("Value", "") if isinstance(x, dict) else str(x or "")


def summarize(doc: dict, month_id: str) -> dict:
    vulns = []
    for v in doc.get("Vulnerability", []) or []:
        cve = v.get("CVE", "")
        if not cve.startswith("CVE-"):
            continue                        # skip advisories (ADV...)
        notes = v.get("Notes", []) or []
        cna = [n.get("Title") for n in notes if n.get("Type") == NOTE_CNA]
        if cna and "Microsoft" not in cna:
            continue                        # Azure Linux packages, Chromium, other CNAs: not Microsoft's own fixes
        action = next((n.get("Value") for n in notes if n.get("Type") == NOTE_ACTION), None)
        threats = v.get("Threats", []) or []
        desc = lambda t: [_val(x.get("Description")) for x in threats if x.get("Type") == t]  # noqa: E731
        exploit = ";".join(desc(THREAT_EXPLOIT))
        sev = desc(THREAT_SEVERITY)
        scores = [s.get("BaseScore") for s in v.get("CVSSScoreSets", []) or [] if s.get("BaseScore") is not None]
        vulns.append({
            "cve": cve, "title": _val(v.get("Title")),
            "impact": (desc(THREAT_IMPACT) or [""])[0],
            "severity": "Critical" if "Critical" in sev else (sev[0] if sev else ""),
            "cvss": max(scores) if scores else None,
            "exploited": "Exploited:Yes" in exploit,
            "disclosed": "Publicly Disclosed:Yes" in exploit,
            "action": None if action is None else action != "No",   # None: this entry does not say
        })
    by_cve: dict[str, dict] = {}                # a CVE can repeat (per product): merge, never overwrite
    for v in vulns:
        m = by_cve.setdefault(v["cve"], dict(v))
        m["exploited"] |= v["exploited"]
        m["disclosed"] |= v["disclosed"]
        if v["action"] is not None:
            m["action"] = v["action"] or bool(m["action"])
        m["cvss"] = max(filter(None, (m["cvss"], v["cvss"])), default=None)
        if v["severity"] == "Critical" or not m["severity"]:
            m["severity"] = v["severity"] or m["severity"]
        m["impact"] = m["impact"] or v["impact"]
        m["title"] = m["title"] or v["title"]
    for m in by_cve.values():
        m["action"] = True if m["action"] is None else m["action"]   # unstated: assume you must act
    vulns = sorted(by_cve.values(), key=lambda v: (-(v["cvss"] or 0), v["cve"]))
    return {
        "month": month_id, "title": _val(doc.get("DocumentTitle")),
        "release_notes": f"https://msrc.microsoft.com/update-guide/releaseNote/{month_id}",
        "total": len(vulns),
        "critical": sum(v["severity"] == "Critical" for v in vulns),
        "action_required": sum(v["action"] for v in vulns),
        "exploited": [v for v in vulns if v["exploited"]],
        "disclosed": [v for v in vulns if v["disclosed"] and not v["exploited"]],
        "critical_list": [v for v in vulns if v["severity"] == "Critical" and not v["exploited"] and v["action"]][:8],
    }


def message(s: dict) -> str:
    def safe(t: str) -> str:            # Telegram Markdown: these characters would break the message
        return "".join(" " if ch in "*_`[]" else ch for ch in t)

    def line(v):
        bits = [b for b in (v["impact"], f"CVSS {v['cvss']}" if v["cvss"] else "") if b]
        return f"• {v['cve']} {safe(v['title'][:80])}" + (f" ({', '.join(bits)})" if bits else "")
    out = [f"*🩹 Microsoft Patch Tuesday, {s['month']}*",
           f"{s['total']} Microsoft CVEs · {s['action_required']} need you to install or configure something · "
           f"{s['critical']} critical · {len(s['exploited'])} exploited · {len(s['disclosed'])} publicly disclosed before the fix",
           "Fixes Microsoft applied to its own cloud services are counted but need no action."]
    if s["exploited"]:
        out += ["", "*Exploited now (patch first):*", *[line(v) for v in s["exploited"]]]
    if s["disclosed"]:
        out += ["", "*Publicly disclosed:*", *[line(v) for v in s["disclosed"][:6]]]
    if s["critical_list"]:
        out += ["", "*Critical:*", *[line(v) for v in s["critical_list"]]]
    out += ["", f"Source: Microsoft release notes {s['release_notes']}"]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--month", help="CVRF id such as 2026-Nov (default: this month)")
    ap.add_argument("--fixture")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--inspect", action="store_true", help="print the note/tag structure, then stop")
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    month_id = args.month or now.strftime("%Y-%b")
    out_f = ROOT / "data" / "patchday" / f"{month_id}.json"

    if not (args.month or args.fixture):
        if not is_patch_tuesday(now):
            print(f"{now.date()} is not Patch Tuesday; nothing to do")
            return 0
        if out_f.exists():
            print(f"{month_id} already sent")
            return 0

    if args.fixture:
        doc = json.loads(Path(args.fixture).read_text())
    else:
        r = requests.get(f"{API}/cvrf/{month_id}", headers=HDR, timeout=60)
        if r.status_code == 404:
            print(f"Microsoft has not published {month_id} yet")
            return 0
        r.raise_for_status()
        doc = r.json()

    if args.inspect:
        from collections import Counter
        vs = doc.get("Vulnerability", [])
        print("vulns", len(vs), "first keys", sorted(vs[0].keys()) if vs else None)
        print("note titles/types", Counter((n.get("Title"), n.get("Type")) for v in vs for n in v.get("Notes", []) or []).most_common(15))
        print("tag values", Counter(_val(n) if isinstance(n, dict) and "Value" in n else n.get("Value") for v in vs for n in v.get("Notes", []) or [] if n.get("Type") == 7).most_common(25))
        ms = [v for v in vs if any(n.get("Type") == 8 and n.get("Title") == "Microsoft" for n in v.get("Notes", []) or [])]
        print("ms release dates", Counter((v.get("ReleaseDate") or "")[:10] for v in ms).most_common(8))
        print("ms revisions", Counter(len(v.get("RevisionHistory") or []) for v in ms).most_common(5))
        print("sample notes", json.dumps((vs[0].get("Notes") or [])[:6])[:1500])
        return 0
    s = summarize(doc, month_id)
    text = message(s)
    print(text)
    if args.dry_run:
        return 0
    out_f.parent.mkdir(parents=True, exist_ok=True)
    out_f.write_text(json.dumps(s, indent=1))
    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        from digest.notify import _telegram
        _telegram([text], 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
