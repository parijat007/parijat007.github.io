"""Public Telegram channel: one short post per day linking to the published brief.

Needs TELEGRAM_BOT_TOKEN (the existing bot) and the channel handle, set in config.yaml as
delivery.telegram_channel (e.g. "@watchfloor"; the bot must be an admin of the channel). Plain text, no Markdown, so nothing in a headline can break or inject formatting.
Posts once per brief date: state/channel_posted.json records it, so a replaced brief or a second runner
does not post again. Readers' details are never seen or stored; Telegram handles subscriptions.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import requests

from .render import EXPLOIT_LABEL

log = logging.getLogger(__name__)
MAX = 3500


def message(digest: dict, run_date: str, base: str) -> str:
    date = datetime.fromisoformat(run_date).strftime("%A %-d %B %Y")
    lines = [f"Watchfloor threat brief, {date}", "", (digest.get("executive_pulse") or "").strip()]
    items = digest.get("items") or []
    if items:
        lines.append("")
        for e in items[:6]:
            tag = EXPLOIT_LABEL.get(e.get("exploitation"), "")
            lines.append(f"• {e.get('headline', '').strip()}" + (f" ({tag})" if tag and e.get("exploitation") != "N/A" else ""))
    else:
        lines += ["", "Quiet day: nothing met the bar for exploitation or exposure."]
    lines += ["", f"Full brief and sources: {base}/brief/{run_date}/"]
    text = "\n".join(lines)
    return text if len(text) <= MAX else text[:MAX - 1] + "…"


def post(digest: dict, run_date: str, base: str, root: Path, dry_run: bool = False) -> bool:
    chan, token = os.environ.get("TELEGRAM_CHANNEL_ID"), os.environ.get("TELEGRAM_BOT_TOKEN")
    if not (chan and token and base):
        return False
    marker = root / "state" / "channel_posted.json"
    done = json.loads(marker.read_text()) if marker.exists() else {}
    if run_date in done:
        log.info("channel: brief %s already posted", run_date)
        return False
    text = message(digest, run_date, base)
    if dry_run:
        print(text)
        return False
    r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=60,
                      json={"chat_id": chan, "text": text, "disable_web_page_preview": False})
    if r.status_code >= 300:
        log.warning("channel post failed: HTTP %s %s", r.status_code, r.text[:200])
        return False
    done[run_date] = datetime.now().astimezone().isoformat(timespec="seconds")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(dict(sorted(done.items())[-60:]), indent=1))
    return True
