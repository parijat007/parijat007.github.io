"""Hourly Watch: deterministic, no LLM. Facts from authoritative sources only.

Writes data/watch.json (rolling window) and sends an immediate alert when a newly
KEV-listed CVE touches your stack watchlist.

  python -m digest.watch            # run
  python -m digest.watch --no-alert # update data only
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import collectors as C
from .config import load_config
from .notify import send
from .playbook import remediation_for

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "watch.json"
log = logging.getLogger("digest.watch")


def _entry(it: dict, kind: str, now: str) -> dict:
    return {
        "id": it["id"], "kind": kind, "title": it["title"][:200], "summary": it.get("text", "")[:280],
        "source": it["source_name"], "url": it["url"], "published": it.get("published"),
        "cves": it.get("cves", [])[:4], "cvss": it.get("cvss"), "epss": it.get("epss"),
        "poc": (it.get("public_poc") or {}).get("count", 0),
        "kev_due": (it.get("kev") or {}).get("dueDate"), "ransomware": (it.get("kev") or {}).get("ransomware"),
        "stack_match": it.get("stack_match", []), "first_seen": now,
        "required_action": it.get("required_action"),
        "fix": remediation_for(it),
    }


def run(no_alert: bool = False) -> int:
    cfg = load_config()
    w = cfg.get("watch", {})
    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    since = now - timedelta(hours=w.get("lookback_hours", 48))

    kev = C.load_kev()
    items = [dict(it, _kind="KEV") for it in C.kev_items(kev, since)]
    status = {"CISA KEV": "ok"}
    try:
        items += [dict(it, _kind="GHSA") for it in C.ghsa_items({"severities": ["critical"], "max_results": 30}, since)]
        status["GitHub Advisory"] = "ok"
    except Exception as e:  # noqa: BLE001
        status["GitHub Advisory"] = f"error: {type(e).__name__}"
    feeds = [f for f in cfg["feeds"] if f.get("tier") in ("vendor", "authority")]
    items += [dict(it, _kind="ADVISORY") for it in C.rss_items(feeds, since, 10, status)]
    C.enrich(items, kev, cfg["stack_watchlist"])
    if not getattr(locals().get("args"), "items_fixture", None):
        _src = ROOT / "data" / "sources.json"
        _old = json.loads(_src.read_text()) if _src.exists() else {"status": {}}
        _now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        _old["status"].update({k: {"status": v, "checked": _now} for k, v in status.items()})
        _src.parent.mkdir(parents=True, exist_ok=True)
        _src.write_text(json.dumps(_old, indent=1))

    old = json.loads(OUT.read_text()) if OUT.exists() else {"entries": []}
    known = {e["id"]: e for e in old.get("entries", [])}
    fresh = []
    for it in items:
        if it["id"] in known:
            # keep first_seen; refresh enrichment (EPSS/PoC can change)
            e = known[it["id"]]
            e.update({k: v for k, v in _entry(it, it["_kind"], e["first_seen"]).items() if k != "first_seen"})
        else:
            known[it["id"]] = _entry(it, it["_kind"], stamp)
            fresh.append(known[it["id"]])

    keep_after = (now - timedelta(days=w.get("retain_days", 7))).isoformat()
    entries = sorted((e for e in known.values() if e["first_seen"] >= keep_after),
                     key=lambda e: (e["first_seen"], e["kind"] == "KEV"), reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"updated": stamp, "sources": status, "entries": entries},
                              indent=1, ensure_ascii=False))
    log.info("watch: %d entries (%d new)", len(entries), len(fresh))

    hot = [e for e in fresh if e["kind"] == "KEV" and e["stack_match"]]
    if hot and not no_alert and w.get("alert_on_stack_kev", True):
        lines = [f"*🚨 New KEV touching your stack*"]
        for e in hot[:5]:
            lines.append(f"{', '.join(e['cves'])} {e['title'][:90]}\n📌 {', '.join(e['stack_match'])} · due {e['kev_due']}\n🔗 {e['url']}")
        send(["\n\n".join(lines)], cfg, "KEV alert")
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-alert", action="store_true")
    raise SystemExit(run(ap.parse_args().no_alert))


if __name__ == "__main__":
    main()
