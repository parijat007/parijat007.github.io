"""End-to-end self-test: every model, every provider, delivery credentials. Sends nothing, writes nothing.

    python -m digest.selftest            # all providers in the chain
    python -m digest.selftest --quick    # pings only (no full brief per provider)

Stages
  1. Sources     collect the real feeds once, as the daily run does
  2. Models      list what each provider offers; ping every configured model with a tiny JSON request
  3. Briefs      for each provider alone: write a full brief, then validate it (URLs, labels, KEV
                 coverage, CVE-to-product), exactly as publishing would, but keep it in memory
  4. Delivery    Telegram: getMe + getChat (checks the token and chat id without sending a message)

Writes a Markdown report to $GITHUB_STEP_SUMMARY when run in GitHub Actions. Exit code 1 if no
provider can write a valid brief, so the workflow shows red.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

from . import llm
from .config import load_config

log = logging.getLogger("digest.selftest")
PING = 'Reply with exactly this JSON and nothing else: {"ok": true}'


def _key(pc: dict) -> str | None:
    return next((os.environ[k] for k in pc.get("api_key_env", []) if os.environ.get(k)), None)


def list_models(pc: dict) -> tuple[str, list[str]]:
    key = _key(pc)
    if pc.get("api_key_env") and not key:
        return "no key", []
    try:
        r = requests.get(pc["base_url"].rstrip("/") + "/models", timeout=30,
                         headers={"Authorization": f"Bearer {key}"} if key else {})
        if r.status_code != 200:
            return f"HTTP {r.status_code}", []
        ids = [m.get("id", "") for m in r.json().get("data", [])]
        return "ok", sorted(i.removeprefix("models/") for i in ids)
    except requests.RequestException as e:
        return type(e).__name__, []


def ping(name: str, pc: dict, model: str) -> tuple[str, float]:
    t = time.monotonic()
    try:
        text, _ = llm._openai_compat(name, {**pc, "model": model, "max_output_tokens": 400,
                                            "timeout_seconds": 60}, "You are a test endpoint.", PING)
        ok = "ok" in text and "true" in text
        return ("pass" if ok else f"odd reply: {text[:60]!r}"), time.monotonic() - t
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {str(e)[:110]}", time.monotonic() - t


def full_brief(name: str, cfg: dict, items: list[dict], ctx: dict) -> dict:
    from .main import call_llm
    from .render import parse_json, validate
    from .main import sources_by_name, must_report
    one = {**cfg, "llm": {**cfg["llm"], "chain": [name]}}
    os.environ["WF_LLM_CHAIN"] = name
    t = time.monotonic()
    try:
        raw, _ = call_llm(one, items, ctx)
        digest, problems = validate(parse_json(raw), items, sources_by_name(cfg))
        kev = must_report(items[: cfg["llm"]["providers"][name].get("max_items", 40)])
        blob = json.dumps(digest["items"]).upper()
        return {"result": "pass", "seconds": round(time.monotonic() - t, 1),
                "model": cfg["llm"]["providers"][name].get("_used_model"),
                "items": len(digest["items"]), "kev_covered": f"{sum(c in blob for c in kev)}/{len(kev)}",
                "fixes": len(problems)}
    except Exception as e:  # noqa: BLE001
        return {"result": f"fail: {str(e)[:160]}", "seconds": round(time.monotonic() - t, 1)}


def telegram() -> str:
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (tok and chat):
        return "not configured"
    try:
        me = requests.get(f"https://api.telegram.org/bot{tok}/getMe", timeout=20).json()
        if not me.get("ok"):
            return f"token rejected: {me.get('description')}"
        ch = requests.get(f"https://api.telegram.org/bot{tok}/getChat", params={"chat_id": chat}, timeout=20).json()
        return f"pass (bot @{me['result'].get('username')}, chat found)" if ch.get("ok") \
            else f"chat id wrong: {ch.get('description')}"
    except requests.RequestException as e:
        return type(e).__name__


def main() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    chain = llm.chain(cfg["llm"])
    out = [f"# Watchfloor self-test — {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", "",
           f"Chain: `{' → '.join(chain)}`", ""]

    out += ["## Models", "", "| Provider | Model | Listed by provider | Ping | Seconds |", "|---|---|---|---|---|"]
    for name in chain:
        pc = cfg["llm"]["providers"][name]
        if name == "local" and not llm.local_up(cfg["llm"]):
            out.append("| local | — | — | not running here | — |")
            continue
        status, offered = list_models(pc)
        models = list(pc.get("models") or [pc.get("model")])
        if pc.get("discover_free"):
            found = llm.discover_free_models(pc)
            out.append(f"| {name} | discovered: {', '.join(f'`{m}`' for m in found) or 'none'} | — | — | — |")
            models = found + models
        for m in models:
            listed = "yes" if m in offered else ("unknown" if status != "ok" else "**no**")
            res, secs = ping(name, pc, m)
            out.append(f"| {name} | `{m}` | {listed} | {res} | {secs:.1f} |")
        if name == "gemini" and offered:
            flash = [m for m in offered if "flash" in m and "image" not in m and "tts" not in m][:12]
            out += ["", f"Gemini flash models this key can use: {', '.join(f'`{m}`' for m in flash)}", ""]

    any_pass = False
    if not args.quick:
        from .main import collect as main_collect   # same path the daily run uses
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=cfg["weekend_hours"] if now.weekday() == 0 else cfg["window_hours"])
        items, status = main_collect(cfg, since, now)
        bad = {k: v for k, v in status.items() if not str(v).startswith("ok")}
        out += ["", "## Sources", "", f"{len(items)} items collected from {len(status)} sources. "
                + ("All sources OK." if not bad else "Problems: " + ", ".join(f"{k} ({v})" for k, v in bad.items()))]
        ctx = {"RUN_DATE": now.date().isoformat(), "WINDOW_START": since.strftime("%Y-%m-%d %H:%M UTC"),
               "WINDOW_END": now.strftime("%Y-%m-%d %H:%M UTC"),
               "STACK_WATCHLIST": ", ".join(cfg["stack_watchlist"]), "PREVIOUSLY_REPORTED_IDS": "none"}
        out += ["", "## Full brief per provider (validated, not published)", "",
                "| Provider | Result | Model used | Items | KEV covered | Auto-fixes | Seconds |",
                "|---|---|---|---|---|---|---|"]
        for name in chain:
            if name == "local" and not llm.local_up(cfg["llm"]):
                continue
            r = full_brief(name, cfg, items, ctx)
            any_pass |= r["result"] == "pass"
            out.append(f"| {name} | {r['result']} | `{r.get('model') or '—'}` | {r.get('items', '—')} | "
                       f"{r.get('kev_covered', '—')} | {r.get('fixes', '—')} | {r['seconds']} |")
            time.sleep(5)

    out += ["", "## Delivery", "", f"- Telegram: {telegram()}",
            f"- CallMeBot: {'configured' if os.environ.get('CALLMEBOT_APIKEY') else 'not configured'}",
            f"- Teams: {'configured' if os.environ.get('TEAMS_WEBHOOK_URL') else 'not configured'}"]
    report = "\n".join(out)
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(report + "\n")
    return 0 if (args.quick or any_pass) else 1


if __name__ == "__main__":
    sys.exit(main())
