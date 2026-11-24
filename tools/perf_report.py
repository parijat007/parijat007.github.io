"""Daily performance report (perf.yml): site speed + pipeline health -> data/perf.json.

Inputs:
  lh/<page>.json           Lighthouse JSON for each audited page (perf.yml writes them)
  GitHub Actions API       run durations, success rate and schedule delay (GITHUB_TOKEN, actions: read)
  data/briefs/*.json       which model wrote each brief and how long it took (meta.perf)
Output:
  data/perf.json           today's numbers, read by the status page
  data/perf_history.json   one line a day (90 days), for trends
Alerts on Telegram when a threshold is crossed. Exit code is always 0: a slow day is not a failed job.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
NOW = datetime.now(timezone.utc)

THRESHOLDS = {"performance": 0.90, "accessibility": 0.95, "best-practices": 0.90, "seo": 0.90}
WATCH_MAX_DELAY_MIN = 90
SLOTS = {"brief.yml": [(11, 20), (12, 20), (13, 20)], "watch.yml": [(h, 15) for h in range(24)],
         "health.yml": [(h, 50) for h in range(24)]}


def lighthouse(dir_: Path) -> dict:
    out = {}
    for f in sorted(dir_.glob("*.json")):
        try:
            d = json.loads(f.read_text())
        except ValueError:
            continue
        a = d.get("audits", {})
        num = lambda k: (a.get(k) or {}).get("numericValue")  # noqa: E731
        out[f.stem] = {
            "url": d.get("finalDisplayedUrl") or d.get("requestedUrl"),
            "scores": {k: v.get("score") for k, v in d.get("categories", {}).items()},
            "lcp_ms": round(num("largest-contentful-paint") or 0),
            "cls": round(num("cumulative-layout-shift") or 0, 3),
            "tbt_ms": round(num("total-blocking-time") or 0),
            "bytes": round(num("total-byte-weight") or 0),
        }
    return out


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _delay(started: datetime, slots: list[tuple[int, int]]) -> int:
    cands = []
    for h, m in slots:
        slot = started.replace(hour=h, minute=m, second=0, microsecond=0)
        if slot > started:
            slot -= timedelta(days=1)
        cands.append((started - slot).total_seconds() / 60)
    return int(min(cands))


def runs(days: int = 7) -> dict:
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    if not (token and repo):
        return {}
    out = {}
    since = (NOW - timedelta(days=days)).strftime("%Y-%m-%d")
    for wf, slots in SLOTS.items():
        r = requests.get(f"https://api.github.com/repos/{repo}/actions/workflows/{wf}/runs",
                         params={"created": f">={since}", "per_page": 100, "branch": "main"},
                         headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                         timeout=30)
        if not r.ok:
            continue
        rs = [x for x in r.json().get("workflow_runs", []) if x.get("status") == "completed"]
        if not rs:
            continue
        durs = [(_ts(x["updated_at"]) - _ts(x["run_started_at"])).total_seconds() for x in rs]
        sched = [_delay(_ts(x["run_started_at"]), slots) for x in rs if x.get("event") == "schedule"]
        ok = sum(x.get("conclusion") == "success" for x in rs)
        out[wf.removesuffix(".yml")] = {
            "runs": len(rs), "success_rate": round(ok / len(rs), 3),
            "p50_s": round(statistics.median(durs)), "max_s": round(max(durs)),
            "scheduled_runs": len(sched),
            "schedule_delay_p50_min": round(statistics.median(sched)) if sched else None,
            "schedule_delay_max_min": max(sched) if sched else None,
        }
    return out


def models(days: int = 30) -> dict:
    cut = (NOW - timedelta(days=days)).date().isoformat()
    briefs = []
    for f in sorted((ROOT / "data" / "briefs").glob("*.json")):
        if f.stem >= cut:
            try:
                briefs.append(json.loads(f.read_text()).get("meta") or {})
            except ValueError:
                pass
    by = {}
    for m in briefs:
        key = m.get("provider") or ("facts-only" if m.get("mode") == "fallback" else "unknown")
        by[key] = by.get(key, 0) + 1
    timed = [m["perf"] for m in briefs if m.get("perf")]
    fails = {}
    for p in timed:
        for a in p.get("attempts", []):
            if not a.get("ok"):
                k = f"{a.get('provider')}: {a.get('error')}"
                fails[k] = fails.get(k, 0) + 1
    return {"briefs": len(briefs), "written_by": by,
            "analyst_rate": round(sum(m.get("mode") == "analyst" for m in briefs) / len(briefs), 3) if briefs else None,
            "llm_s_p50": round(statistics.median([p["llm_s"] for p in timed])) if timed else None,
            "total_s_p50": round(statistics.median([p["total_s"] for p in timed])) if timed else None,
            "top_failures": dict(sorted(fails.items(), key=lambda kv: -kv[1])[:5])}


def alerts(report: dict) -> list[str]:
    out = []
    for page, v in report["site"].items():
        for cat, floor in THRESHOLDS.items():
            s = v["scores"].get(cat)
            if s is not None and s < floor:
                out.append(f"Site {page}: {cat} score {s:.2f} (below {floor:.2f})")
    for wf, v in report["pipeline"].items():
        if v["success_rate"] < 0.95:
            out.append(f"{wf}: {v['success_rate']:.0%} of runs succeeded in the last 7 days")
    w = report["pipeline"].get("watch", {})
    if (w.get("schedule_delay_max_min") or 0) > WATCH_MAX_DELAY_MIN:
        out.append(f"Hourly watch: GitHub started a run {w['schedule_delay_max_min']} min late this week")
    return out


def main() -> int:
    lh_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "lh"
    report = {"updated": NOW.isoformat(timespec="seconds"), "site": lighthouse(lh_dir),
              "pipeline": runs(), "models": models()}
    report["alerts"] = alerts(report)
    data = ROOT / "data"
    (data / "perf.json").write_text(json.dumps(report, indent=1))
    hist_f = data / "perf_history.json"
    hist = json.loads(hist_f.read_text()) if hist_f.exists() else []
    hist = [h for h in hist if h.get("date") != NOW.date().isoformat()]
    hist.append({"date": NOW.date().isoformat(),
                 "site": {p: {**v["scores"], "lcp_ms": v["lcp_ms"], "bytes": v["bytes"]} for p, v in report["site"].items()},
                 "pipeline": {k: {"success_rate": v["success_rate"], "p50_s": v["p50_s"],
                                  "delay_max_min": v["schedule_delay_max_min"]} for k, v in report["pipeline"].items()},
                 "analyst_rate": report["models"]["analyst_rate"]})
    hist_f.write_text(json.dumps(hist[-90:], indent=1))

    lines = ["| page | perf | a11y | best practices | SEO | LCP | weight |", "|---|---|---|---|---|---|---|"]
    for p, v in report["site"].items():
        s = v["scores"]
        lines.append(f"| {p} | {s.get('performance')} | {s.get('accessibility')} | {s.get('best-practices')} | "
                     f"{s.get('seo')} | {v['lcp_ms']} ms | {v['bytes'] // 1024} KB |")
    lines += ["", "| workflow | runs | success | p50 | max | schedule delay p50 / max |", "|---|---|---|---|---|---|"]
    for k, v in report["pipeline"].items():
        lines.append(f"| {k} | {v['runs']} | {v['success_rate']:.0%} | {v['p50_s']} s | {v['max_s']} s | "
                     f"{v['schedule_delay_p50_min']} / {v['schedule_delay_max_min']} min |")
    lines += ["", f"Briefs (30 days): {report['models']}"]
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n")

    if report["alerts"] and os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        from digest.notify import _telegram
        try:
            _telegram(["Watchfloor performance\n\n" + "\n".join(f"- {a}" for a in report["alerts"])], 0)
        except Exception as e:  # noqa: BLE001
            print(f"::warning title=Perf alert not sent::{e}")
    for a in report["alerts"]:
        print(f"::warning title=Performance::{a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
