"""Pull public works from ORCID into data/orcid.json (orcid.yml, weekly).

    python tools/orcid_sync.py                 # fetch from the ORCID public API
    python tools/orcid_sync.py --from FILE     # parse a saved /works response (tests)

Only public fields are read: title, journal, year, DOI or URL, type. The site merges these with the
hand-kept list in site/profile.yaml, which stays authoritative: a work already there (same DOI or title)
is not repeated, and nothing in ORCID can change or hide an entry you wrote by hand.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "orcid.json"
ORCID_ID = "0009-0000-9233-3352"
API = f"https://pub.orcid.org/v3.0/{ORCID_ID}/works"


def _v(d, *path):
    for k in path:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def parse(works: dict) -> list[dict]:
    out = []
    for g in works.get("group") or []:
        s = (g.get("work-summary") or [{}])[0]          # ORCID lists the preferred version first
        title = (_v(s, "title", "title", "value") or "").strip()
        if not title:
            continue
        doi = next((e.get("external-id-value") for e in _v(s, "external-ids", "external-id") or []
                    if (e.get("external-id-type") or "").lower() == "doi"), None)
        doi = re.sub(r"^(https?://(dx\.)?doi\.org/|doi:)", "", (doi or "").strip(), flags=re.I) or None
        url = f"https://doi.org/{doi}" if doi else (_v(s, "url", "value") or None)
        if url and not url.startswith("https://"):
            url = None
        year = _v(s, "publication-date", "year", "value")
        out.append({"title": title, "venue": (_v(s, "journal-title", "value") or "").strip() or None,
                    "year": int(year) if year and str(year).isdigit() else None,
                    "doi": doi, "url": url, "type": (s.get("type") or "").replace("-", " ") or None,
                    "put_code": s.get("put-code")})
    return sorted(out, key=lambda w: (-(w["year"] or 0), w["title"].lower()))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src")
    args = ap.parse_args()
    if args.src:
        raw = json.loads(Path(args.src).read_text())
    else:
        import requests  # noqa: PLC0415
        r = requests.get(API, headers={"Accept": "application/json",
                                       "User-Agent": "watchfloor-orcid-sync (+https://theparijat.com/)"}, timeout=30)
        r.raise_for_status()
        raw = r.json()
    works = parse(raw)
    if not works and OUT.exists():
        print("ORCID returned no works; keeping the previous file")       # never wipe the list on a bad response
        return 0
    data = {"orcid": ORCID_ID, "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "works": works}
    old = json.loads(OUT.read_text()) if OUT.exists() else {}
    if old.get("works") == works:
        print(f"no change ({len(works)} works)")
        return 0
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(works)} works")
    return 0


if __name__ == "__main__":
    sys.exit(main())
