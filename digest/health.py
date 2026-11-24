"""Health check: is today's brief an analyst brief, and is the hourly watch fresh?

Runs in GitHub Actions (health.yml). It never writes data. It prints what needs
re-running to $GITHUB_OUTPUT (rerun_brief, rerun_watch) and sends a Telegram
alert when something is missing, so a sleeping laptop or a dropped GitHub
schedule never goes unnoticed.

    python -m digest.health            # check, alert if needed
    python -m digest.health --dry-run  # print the alert instead of sending
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("digest.health")

BRIEF_DUE_UTC = 14        # 9 AM EST / 10 AM EDT: brief should exist by now
BRIEF_RECHECK_UTC = (16,) # remind again if it is still not fixed
WATCH_STALE_H = 3.0
WATCH_REMIND_UTC = (2, 14)  # if the watch stays stale, remind twice a day


def brief_status(run_date: str, root: Path = ROOT) -> str:
    """'analyst', 'fallback', 'missing' or 'unreadable'."""
    f = root / "data" / "briefs" / f"{run_date}.json"
    if not f.exists():
        return "missing"
    try:
        meta = json.loads(f.read_text()).get("meta") or {}
        gen = meta.get("generated_at") or ""
        if len(gen) >= 13 and gen[11:13].isdigit() and not 10 <= int(gen[11:13]) < 17:
            return "stale"     # written by a schedule GitHub ran hours late; the morning run replaces it
        return meta.get("mode") or "unreadable"
    except (OSError, ValueError):
        return "unreadable"


def watch_age_hours(now: datetime, root: Path = ROOT) -> float | None:
    f = root / "data" / "watch.json"
    try:
        ts = datetime.fromisoformat(json.loads(f.read_text())["updated"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds() / 3600


def evaluate(now: datetime, brief: str, watch_age: float | None) -> dict:
    """Decide what to re-run and what to say. Pure function, so it is tested directly."""
    out = {"rerun_brief": False, "rerun_watch": False, "alerts": []}
    h = now.hour
    if h >= BRIEF_DUE_UTC and brief != "analyst":
        out["rerun_brief"] = True
        if h == BRIEF_DUE_UTC or h in BRIEF_RECHECK_UTC:
            what = {"missing": "has not been published",
                    "fallback": "is facts-only (analyst models were unavailable)",
                    "stale": "was written last night by a late schedule, not this morning"}.get(brief, f"is {brief}")
            out["alerts"].append(f"Today's brief {what}. A new cloud run has been started; "
                                 "it replaces a facts-only brief only if a model answers.")
    stale = watch_age is None or watch_age >= WATCH_STALE_H
    if stale:
        out["rerun_watch"] = True
        first = watch_age is not None and watch_age < WATCH_STALE_H + 1
        if watch_age is None or first or h in WATCH_REMIND_UTC:
            age = "unknown" if watch_age is None else f"{watch_age:.1f} h"
            out["alerts"].append(f"Hourly watch is stale (last update {age} ago). A watch run has been started.")
    return out


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    brief, age = brief_status(now.date().isoformat()), watch_age_hours(now)
    res = evaluate(now, brief, age)
    log.info("brief=%s watch_age=%s -> %s", brief, None if age is None else round(age, 2), res)

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as fh:
            fh.write(f"rerun_brief={str(res['rerun_brief']).lower()}\n")
            fh.write(f"rerun_watch={str(res['rerun_watch']).lower()}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"| check | state |\n|---|---|\n| brief {now.date()} | {brief} |\n"
                     f"| watch age | {'n/a' if age is None else f'{age:.1f} h'} |\n")

    if not res["alerts"]:
        return
    text = "Watchfloor health\n\n" + "\n\n".join(f"- {a}" for a in res["alerts"])
    if args.dry_run or not (os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")):
        print(text)
        return
    from .notify import _telegram
    try:
        _telegram([text], 0)
    except Exception as e:  # noqa: BLE001  the re-runs still happen
        print(f"::warning title=Health alert not sent::{e}")


if __name__ == "__main__":
    main()
