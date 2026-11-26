"""Turn one GitHub event into one Telegram message for the owner (run by .github/workflows/events.yml).

Standard library only, and it reads the event from GITHUB_EVENT_PATH: nothing from a pull request's code runs,
and no event text is ever interpolated into a shell command. Messages sent between 22:00 and 07:00 New York
time arrive silently (no sound).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from zoneinfo import ZoneInfo


def _short(s: str, n: int = 160) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def message(event: str, e: dict) -> str | None:
    repo = e.get("repository", {}).get("full_name", "")
    if event in ("pull_request", "pull_request_target"):
        pr, act = e["pull_request"], e.get("action")
        who = pr["user"]["login"]
        if act == "opened" or act == "ready_for_review":
            if pr.get("draft"):
                return None
            note = ("Dependabot update: needs your review and merge." if who.startswith("dependabot")
                    else "Changes a workflow, so only you can merge it." if any(
                        f.startswith(".github/workflows/") for f in e.get("_files", []))
                    else "The unblock agent merges it about an hour after its checks pass, unless you comment hold.")
            return f"New PR #{pr['number']}: {_short(pr['title'])}\nby {who}\n{note}\n{pr['html_url']}"
        if act == "closed":
            if pr.get("merged"):
                return f"Merged PR #{pr['number']}: {_short(pr['title'])}\nby {pr.get('merged_by', {}).get('login', '?')}\n{pr['html_url']}"
            return f"Closed without merging: PR #{pr['number']} {_short(pr['title'])}\n{pr['html_url']}"
        return None
    if event == "workflow_run":
        r = e["workflow_run"]
        if r.get("conclusion") not in ("failure", "timed_out", "startup_failure"):
            return None
        return (f"Failed: {r['name']} on {r['head_branch']} ({r['event']})\n{_short(r.get('display_title', ''), 100)}\n"
                f"{r['html_url']}")
    if event == "discussion":
        d = e["discussion"]
        return f"New discussion by {d['user']['login']}: {_short(d['title'])}\n{d['html_url']}"
    if event == "discussion_comment":
        c, d = e["comment"], e["discussion"]
        return f"New comment by {c['user']['login']} on \"{_short(d['title'], 80)}\":\n{_short(c['body'], 300)}\n{c['html_url']}"
    if event == "issues" and e.get("action") == "opened":
        i = e["issue"]
        return f"New issue #{i['number']} by {i['user']['login']}: {_short(i['title'])}\n{i['html_url']}"
    if event == "watch":
        n = e.get("repository", {}).get("stargazers_count")
        return f"{e['sender']['login']} starred {repo}" + (f" ({n} stars)" if n else "")
    if event == "fork":
        return f"{e['sender']['login']} forked {repo}: {e['forkee']['html_url']}"
    return None


def quiet(now: datetime | None = None) -> bool:
    h = (now or datetime.now(ZoneInfo("America/New_York"))).hour
    return h >= 22 or h < 7


def send(text: str) -> None:
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (tok and chat):
        print("::notice::Telegram not configured; message not sent")
        return
    body = urllib.parse.urlencode({"chat_id": chat, "text": text[:4000], "disable_web_page_preview": "true",
                                   "disable_notification": "true" if quiet() else "false"}).encode()
    with urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data=body, timeout=30) as r:
        r.read()


def main() -> int:
    event = os.environ["GITHUB_EVENT_NAME"]
    e = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
    files = os.environ.get("PR_FILES", "")
    e["_files"] = [f for f in files.split("\n") if f]
    text = message(event, e)
    if text:
        send(text)
        print(text.splitlines()[0])
    else:
        print(f"{event}/{e.get('action')}: nothing to send")
    return 0


if __name__ == "__main__":
    sys.exit(main())
