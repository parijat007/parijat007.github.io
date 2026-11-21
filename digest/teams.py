"""Microsoft Teams delivery via a Workflows (Power Automate) webhook, as an Adaptive Card.

Office 365 connector webhooks are retired; create the URL in Teams: channel > Workflows >
"Post to a channel when a webhook request is received". Store it as TEAMS_WEBHOOK_URL.
"""
from __future__ import annotations

import os
import re

import requests

SEV_COLOR = {"CRITICAL": "Attention", "HIGH": "Warning", "MEDIUM": "Accent", "INFO": "Good"}
X_LABEL = {"EXPLOITED_CONFIRMED": "Exploited, confirmed", "EXPLOITED_REPORTED": "Exploitation reported",
           "POC_PUBLIC": "Public PoC", "NO_KNOWN_EXPLOIT": "No known exploit", "N/A": "Tooling"}
MAX_BYTES = 26_000   # Teams rejects cards above ~28 KB


def _plain(s: str) -> str:
    return re.sub(r"[*_~`]", "", s or "")


def brief_card(digest: dict, run_date: str, site_url: str = "") -> dict:
    body = [
        {"type": "TextBlock", "text": f"Watchfloor threat brief — {run_date}", "weight": "Bolder", "size": "Large", "wrap": True},
        {"type": "TextBlock", "text": digest.get("executive_pulse", ""), "wrap": True, "spacing": "Small"},
    ]
    for e in digest.get("items", []):
        facts = [{"title": "Status", "value": f"{e.get('severity', '').title()} · {X_LABEL.get(e.get('exploitation'), '')}"},
                 {"title": "Affected", "value": e.get("target", "")}]
        if e.get("kev_due_date"):
            facts.append({"title": "KEV due", "value": e["kev_due_date"]})
        if e.get("identifiers"):
            facts.append({"title": "IDs", "value": ", ".join(e["identifiers"][:4])})
        facts.append({"title": "Do this", "value": e.get("action", "")})
        rm = e.get("remediation")
        if rm:
            facts.append({"title": "Patch", "value": rm.get("fixed_versions") or "No fixed version in source; see vendor advisory"})
            facts.append({"title": "Until patched", "value": "; ".join(rm["compensating_controls"][:2])})
        if e.get("hunt"):
            facts.append({"title": "Hunt", "value": e["hunt"]})
        body.append({
            "type": "Container", "separator": True, "spacing": "Medium",
            "style": "emphasis" if e.get("exploitation") == "EXPLOITED_CONFIRMED" else "default",
            "selectAction": {"type": "Action.OpenUrl", "url": e.get("primary_source", site_url or "https://github.com")},
            "items": [
                {"type": "TextBlock", "text": f"{e.get('rank')}. {e.get('headline', '')}", "weight": "Bolder",
                 "wrap": True, "color": SEV_COLOR.get(e.get("severity"), "Default")},
                {"type": "TextBlock", "text": e.get("summary", ""), "wrap": True, "spacing": "Small"},
                {"type": "FactSet", "facts": facts},
            ],
        })
    actions = []
    if site_url:
        actions.append({"type": "Action.OpenUrl", "title": "Open full brief", "url": f"{site_url}/brief/{run_date}/"})
        actions.append({"type": "Action.OpenUrl", "title": "Hourly watch", "url": f"{site_url}/watch/"})
    return {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4", "msteams": {"width": "Full"}, "body": body, "actions": actions}


def text_card(blocks: list[str]) -> dict:
    return {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": _plain(b), "wrap": True, "separator": i > 0}
                     for i, b in enumerate(blocks)]}


def post(card: dict) -> None:
    import json

    payload = {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}
    raw = json.dumps(payload)
    if len(raw.encode()) > MAX_BYTES:   # trim items until it fits
        card["body"] = card["body"][: max(3, len(card["body"]) - 2)]
        return post(card)
    r = requests.post(os.environ["TEAMS_WEBHOOK_URL"], data=raw,
                      headers={"Content-Type": "application/json"}, timeout=60)
    if r.status_code >= 300:
        raise RuntimeError(f"Teams webhook HTTP {r.status_code}")
