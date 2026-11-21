"""Validate model output against the input set and render WhatsApp-native text."""
from __future__ import annotations

import json
import re

from .playbook import grounded_versions, remediation_for

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}
EXPLOIT_LABEL = {
    "EXPLOITED_CONFIRMED": "Exploited (confirmed)",
    "EXPLOITED_REPORTED": "Exploitation reported",
    "POC_PUBLIC": "Public PoC",
    "NO_KNOWN_EXPLOIT": "No known exploit",
    "N/A": "Tooling",
}
CAT_LABEL = {"ACTIVE_ATTACK": "Active attack", "VULNERABILITY": "Vulnerability",
             "SUPPLY_CHAIN": "Supply chain", "AI_THREAT": "AI threat", "GITHUB_REPO": "GitHub repo"}
BANNED = re.compile(r"\b(landscape|delve|elevate|paradigm|testament|substrate|furthermore|moreover)\b", re.I)


def parse_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("model output contained no JSON object")
    return json.loads(text[start:end + 1])


CAN_CONFIRM = {"authority", "vendor"}


def validate(digest: dict, items: list[dict], tiers: dict | None = None) -> tuple[dict, list[str]]:
    """Drop any entry whose URL was not collected; enforce caps; cap claims to what the sources can prove."""
    tiers = tiers or {}
    allowed = {it["url"] for it in items} | {r for it in items for r in it.get("refs", [])}
    by_url = {}
    for it in items:
        for u in [it["url"], *it.get("refs", [])]:
            by_url.setdefault(u, []).append(it)
    problems, kept = [], []
    threats = repos = 0
    for e in digest.get("items", []):
        if e.get("primary_source") not in allowed:
            problems.append(f"dropped (URL not in input): {e.get('headline', '?')[:60]}")
            continue
        e["corroborating_sources"] = [u for u in e.get("corroborating_sources", []) if u in allowed][:2]
        cited = [it for u in [e["primary_source"], *e["corroborating_sources"]] for it in by_url.get(u, [])]
        cited_tiers = {tiers.get(it["source_name"], "press") for it in cited}
        kev_backed = any(it.get("kev") for it in cited)
        if e.get("exploitation") == "EXPLOITED_CONFIRMED" and not kev_backed and not (cited_tiers & CAN_CONFIRM):
            e["exploitation"] = "EXPLOITED_REPORTED"
            problems.append(f"downgraded to reported (no authority/vendor/KEV source): {e.get('headline', '?')[:50]}")
        # Headline must not claim exploitation the (verified) label doesn't support
        if not str(e.get("exploitation", "")).startswith("EXPLOITED") and re.search(
                r"\b(actively |widely )?exploit(ed|ation)\b|in the wild|under attack", e.get("headline", ""), re.I):
            e["headline"] = re.sub(r"\b(actively |widely )?exploit(ed|ation)\b( in the wild)?|in the wild|under attack",
                                   "disclosed", e["headline"], flags=re.I)
            problems.append(f"headline toned down to match label: {e['headline'][:50]}")
        # A "Public PoC" label needs evidence: a PoC index hit, or the source itself saying so
        poc_text = re.search(r"proof[- ]of[- ]concept|\bpoc\b|exploit code|publicly available exploit",
                             " ".join(f"{it.get('title', '')} {it.get('text', '')}" for it in cited), re.I)
        if e.get("exploitation") == "POC_PUBLIC" and not (any(it.get("public_poc") for it in cited) or poc_text):
            e["exploitation"] = "NO_KNOWN_EXPLOIT"
            problems.append(f"PoC label removed (no PoC evidence in sources): {e.get('headline', '?')[:50]}")
        if cited_tiers and cited_tiers <= {"press"} and e.get("confidence") == "HIGH":
            e["confidence"] = "MEDIUM"
        e["source_tiers"] = sorted(cited_tiers)
        evidence = " ".join(f"{it.get('title', '')} {it.get('text', '')} {it.get('required_action', '')}" for it in cited)
        claimed = e.get("fixed_versions")
        e["fixed_versions"] = grounded_versions(claimed, evidence)
        if claimed and not e["fixed_versions"]:
            problems.append(f"fixed version not in source text, removed: {e.get('headline', '?')[:50]}")
        rem = remediation_for({**e, "cwes": sorted({w for it in cited for w in it.get("cwes", [])})}, evidence)
        if e.get("category") != "GITHUB_REPO":
            e["remediation"] = {**rem, "fixed_versions": e["fixed_versions"]}
        is_repo = e.get("category") == "GITHUB_REPO"
        if (is_repo and repos >= 3) or (not is_repo and threats >= 5):
            problems.append(f"dropped (cap): {e.get('headline', '?')[:60]}")
            continue
        repos += is_repo
        threats += not is_repo
        kept.append(e)
    digest["items"] = kept[:8]
    for i, e in enumerate(digest["items"], 1):
        e["rank"] = i
    for field in ("executive_pulse",):
        if BANNED.search(digest.get(field, "")):
            problems.append("banned word in pulse")
    return digest, problems


def _wa_safe(s: str) -> str:
    # Stray *, _, ~ from source text would toggle WhatsApp formatting
    return re.sub(r"[*_~`]", "", str(s or "")).strip()


def render_item(e: dict) -> str:
    sev = e.get("severity", "INFO")
    status = [f"{SEV_ICON.get(sev, '⚪')} {sev.title()}",
              EXPLOIT_LABEL.get(e.get("exploitation"), e.get("exploitation", ""))]
    if e.get("kev_due_date"):
        status.append(f"KEV due {e['kev_due_date']}")
    if e.get("is_update"):
        status.append("UPDATE")
    lines = [
        f"*{e.get('rank', '•')}. {_wa_safe(e.get('headline'))}*",
        f"{CAT_LABEL.get(e.get('category'), e.get('category'))} · " + " · ".join(status),
        f"🎯 {_wa_safe(e.get('target'))}",
    ]
    if e.get("identifiers"):
        lines.append(f"🆔 {', '.join(map(_wa_safe, e['identifiers'][:5]))}")
    if e.get("stack_match"):
        lines.append(f"📌 Your stack: {', '.join(map(_wa_safe, e['stack_match']))}")
    lines += [_wa_safe(e.get("summary")),
              f"➡️ _{_wa_safe(e.get('action'))}_",
              *([f"🩹 Patch: {_wa_safe(e['remediation']['fixed_versions'] or 'no fixed version in source; see vendor advisory')}",
                 f"🛡️ Until patched: {_wa_safe(e['remediation']['compensating_controls'][0])}"] if e.get("remediation") else []),
              *([f"🔎 Hunt: {_wa_safe(e['hunt'])}"] if e.get("hunt") else []),
              f"🔗 {e.get('primary_source')}"]
    lines += [f"   ↳ {u}" for u in e.get("corroborating_sources", [])]
    return "\n".join(lines)


def render(digest: dict, run_date: str, footer: str = "") -> list[str]:
    """Return a list of message blocks (header first, then one block per item)."""
    head = [f"*🛡️ Threat & Tooling Digest — {run_date}*", "",
            f"*Pulse:* {_wa_safe(digest.get('executive_pulse'))}"]
    if digest.get("items"):
        head += ["", *[f"{e.get('rank')}. {_wa_safe(e.get('headline'))}" for e in digest["items"]]]
    else:
        head += ["", "No items met the bar today."]
    blocks = ["\n".join(head)] + [render_item(e) for e in digest.get("items", [])]
    if footer:
        blocks.append(f"```{footer}```")
    return blocks


def pack(blocks: list[str], max_chars: int) -> list[str]:
    """Join blocks into as few messages as possible, never splitting an item."""
    msgs, cur = [], ""
    for b in blocks:
        if len(b) > max_chars:  # single oversized block: hard split on lines
            b = b[: max_chars - 3] + "..."
        if cur and len(cur) + 2 + len(b) > max_chars:
            msgs.append(cur)
            cur = b
        else:
            cur = f"{cur}\n\n{b}" if cur else b
    if cur:
        msgs.append(cur)
    return msgs


def to_markdown(digest: dict, run_date: str) -> str:
    """Archive copy, committed to the repo for search and weekly review."""
    out = [f"# Threat & Tooling Digest — {run_date}", "", f"**Pulse:** {digest.get('executive_pulse', '')}", ""]
    for e in digest.get("items", []):
        out += [f"## {e.get('rank')}. {e.get('headline')}",
                f"- **Category:** {e.get('category')} | **Severity:** {e.get('severity')} | "
                f"**Exploitation:** {e.get('exploitation')} | **Confidence:** {e.get('confidence')}",
                f"- **Target:** {e.get('target')}",
                f"- **Identifiers:** {', '.join(e.get('identifiers', []))}",
                f"- **Summary:** {e.get('summary')}",
                f"- **Action:** {e.get('action')}"]
        if e.get("hunt"):
            out.append(f"- **Hunt:** {e['hunt']}")
        if e.get("remediation"):
            rm = e["remediation"]
            out.append(f"- **Patch:** {rm.get('fixed_versions') or 'No fixed version in source; see vendor advisory'}")
            out += [f"  - Until patched: {c}" for c in rm["compensating_controls"]]
            out.append(f"  - Verify: {rm['verify']}")
        out += [f"- **Source:** {e.get('primary_source')}",
                *[f"  - {u}" for u in e.get("corroborating_sources", [])], ""]
    return "\n".join(out)
