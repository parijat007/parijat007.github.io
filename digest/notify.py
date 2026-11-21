"""Delivery adapters. Secrets come only from environment variables."""
from __future__ import annotations

import logging
import os
import smtplib
import time
from email.message import EmailMessage

import requests

from .render import pack

log = logging.getLogger("digest.notify")


def _callmebot(msgs: list[str], pause: float) -> None:
    phone, key = os.environ["CALLMEBOT_PHONE"], os.environ["CALLMEBOT_APIKEY"]
    for i, m in enumerate(msgs):
        r = requests.get("https://api.callmebot.com/whatsapp.php",
                         params={"phone": phone, "apikey": key, "text": m}, timeout=60)
        # CallMeBot returns 200 with an HTML body; treat explicit error text as failure.
        body = r.text.lower()
        if not 200 <= r.status_code < 300 or any(t in body for t in ("apikey is invalid", "invalid apikey",
                                                             "not activated", "error:")):
            raise RuntimeError(f"CallMeBot send failed (status {r.status_code}) on message {i + 1}")
        if i < len(msgs) - 1:
            time.sleep(pause)


def _telegram(msgs: list[str], pause: float) -> None:
    token, chat = os.environ["TELEGRAM_BOT_TOKEN"], os.environ["TELEGRAM_CHAT_ID"]
    for m in msgs:
        # Plain text: WhatsApp-style *bold* shows literally, but nothing breaks.
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=60,
                          json={"chat_id": chat, "text": m, "disable_web_page_preview": True})
        r.raise_for_status()
        time.sleep(pause / 4)


def _email(msgs: list[str], subject: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, os.environ["SMTP_FROM"], os.environ["SMTP_TO"]
    msg.set_content("\n\n".join(msgs))
    with smtplib.SMTP(os.environ.get("SMTP_HOST", "smtp.gmail.com"),
                      int(os.environ.get("SMTP_PORT", "587"))) as s:
        s.starttls()
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)


def send(blocks: list[str], cfg: dict, subject: str, dry_run: bool = False,
         digest: dict | None = None, run_date: str = "") -> list[str]:
    """Send to every configured channel; one channel failing does not stop the others."""
    d = cfg["delivery"]
    errors = []
    needs = {"callmebot": ["CALLMEBOT_PHONE", "CALLMEBOT_APIKEY"], "teams": ["TEAMS_WEBHOOK_URL"],
             "telegram": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"], "email": ["SMTP_USER", "SMTP_PASSWORD"]}
    for ch in d.get("channels", []):
        if not dry_run and not all(os.environ.get(v) for v in needs.get(ch, [])):
            log.info("skipping %s: not configured (set %s)", ch, ", ".join(needs.get(ch, [])))
            continue
        limit = d.get(f"{ch}_max_chars", 3800) if ch != "email" else 100_000
        msgs = pack(blocks, limit)
        if ch == "teams":
            from . import teams
            site = (cfg.get("site", {}).get("url") or "").rstrip("/")
            card = teams.brief_card(digest, run_date, site) if digest else teams.text_card(blocks)
            if dry_run:
                import json
                print(f"\n===== DRY RUN: teams (Adaptive Card, {len(json.dumps(card))} bytes) =====")
                continue
            try:
                teams.post(card)
                log.info("delivered via teams")
            except Exception as e:  # noqa: BLE001
                log.error("delivery via teams failed: %s", e)
                errors.append(ch)
            continue
        if dry_run:
            print(f"\n===== DRY RUN: {ch} ({len(msgs)} message(s)) =====")
            for i, m in enumerate(msgs, 1):
                print(f"--- message {i} [{len(m)} chars] ---\n{m}")
            continue
        try:
            if ch == "callmebot":
                _callmebot(msgs, d.get("pause_seconds", 4))
            elif ch == "telegram":
                _telegram(msgs, d.get("pause_seconds", 4))
            elif ch == "email":
                _email(msgs, subject)
            else:
                raise ValueError(f"unknown channel {ch}")
            log.info("delivered via %s (%d message(s))", ch, len(msgs))
        except Exception as e:  # noqa: BLE001
            log.error("delivery via %s failed: %s", ch, e)
            errors.append(ch)
    return errors
