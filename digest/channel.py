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


WELCOME = """Watchfloor: a daily, source-checked cyber threat brief, plus an hourly watch for newly exploited vulnerabilities.

One post a day: the top items, whether each is confirmed exploited, and a link to the full brief with its sources.

Facts come from CISA KEV, vendor advisories and other public sources. Nothing is posted without a source, and corrections are logged publicly.

Site: https://theparijat.com"""


def can_post(chan: str, token: str) -> str:
    """'ok' when the bot is an admin of the channel allowed to post; otherwise what is wrong."""
    api = f"https://api.telegram.org/bot{token}"
    me = requests.get(f"{api}/getMe", timeout=30).json().get("result", {})
    r = requests.get(f"{api}/getChatMember", params={"chat_id": chan, "user_id": me.get("id")}, timeout=30).json()
    if not r.get("ok"):
        return f"cannot see the channel: {r.get('description', 'unknown error')}"
    m = r["result"]
    if m.get("status") != "administrator":
        return f"bot is '{m.get('status')}', not an admin"
    return "ok" if m.get("can_post_messages") else "bot is an admin but cannot post messages"


def main() -> int:
    import argparse  # noqa: PLC0415
    import sys  # noqa: PLC0415
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from digest.config import load_config  # noqa: PLC0415
    ap = argparse.ArgumentParser()
    ap.add_argument("--welcome", action="store_true", help="post the channel's welcome message")
    args = ap.parse_args()
    chan = os.environ.get("TELEGRAM_CHANNEL_ID") or load_config().get("delivery", {}).get("telegram_channel")
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not (chan and token):
        print("channel or bot token not configured")
        return 1
    status = can_post(chan, token)
    print(f"{chan}: {status}")
    if status != "ok" or not args.welcome:
        return 0 if status == "ok" else 1
    r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=60,
                      json={"chat_id": chan, "text": WELCOME, "disable_web_page_preview": True})
    print("welcome posted" if r.ok else f"welcome failed: HTTP {r.status_code} {r.text[:200]}")
    return 0 if r.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
