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
NULLISH = {"", "null", "none", "n/a", "na", "-", "unknown"}
TRACKING = re.compile(r"^(utm_|vs_|mc_|fbclid$|gclid$)", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _nullish(v):
    return None if v is None or (isinstance(v, str) and v.strip().lower() in NULLISH) else v


def clean_url(u: str) -> str:
    """Drop tracking query parameters (utm_*, Cisco's vs_*) so links stay short and readable."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    if not u:
        return u
    p = urlsplit(u)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


def _authority_index(items: list[dict], tiers: dict) -> dict:
    """CVE -> URL of the best official record that mentions it (authority first, then vendor)."""
    idx: dict[str, tuple[int, str]] = {}
    for it in items:
        rank = {"authority": 0, "vendor": 1}.get(tiers.get(it.get("source_name"), "press"))
        if rank is None:
            continue
        blob = f"{it.get('id', '')} {it.get('title', '')} {it.get('text', '')} {it.get('url', '')}"
        for c in {c.upper() for c in CVE_RE.findall(blob)}:
            if c not in idx or rank < idx[c][0]:
                idx[c] = (rank, it["url"])
    return {c: u for c, (_, u) in idx.items()}


GENERIC = {"server", "series", "software", "platform", "suite", "application", "applications", "web",
           "and", "the", "for", "multiple", "products", "management", "center", "client", "service"}


def _product_tokens(product: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]{4,}", product.lower()) if t not in GENERIC}


def kev_product_map(items: list[dict]) -> dict[str, set[str]]:
    """CVE -> distinctive words of the product CISA lists for it."""
    m: dict[str, set[str]] = {}
    for it in items:
        if it.get("source_name") == "CISA KEV" and it.get("kev_product"):
            m[it["id"].upper()] = _product_tokens(it["kev_product"])
        k = it.get("kev") or {}
        if k.get("cve") and k.get("product"):
            m.setdefault(k["cve"].upper(), _product_tokens(k["product"]))
    return {c: t for c, t in m.items() if t}


def fix_cve_product(e: dict, kmap: dict[str, set[str]]) -> str | None:
    """A KEV CVE must sit with CISA's product. Swap in the right CVE, or drop it. Returns a note."""
    text = " ".join(str(e.get(f) or "") for f in ("headline", "target", "summary")).lower()
    ids = {i.upper() for i in (e.get("identifiers") or [])} | {c.upper() for c in CVE_RE.findall(e.get("headline", ""))}
    for cve in ids:
        if cve not in kmap or kmap[cve] & set(re.findall(r"[a-z0-9]{4,}", text)):
            continue
        right = [c for c, t in kmap.items() if t & set(re.findall(r"[a-z0-9]{4,}", text))]
        new = right[0] if len(right) == 1 else None

        def swap(v):
            return re.sub(re.escape(cve), new, v, flags=re.I) if new else re.sub(rf"\s*\(?{re.escape(cve)}\)?", "", v, flags=re.I)
        for f in ("headline", "summary", "action"):
            if isinstance(e.get(f), str):
                e[f] = swap(e[f])
        e["identifiers"] = [new if i.upper() == cve and new else i for i in (e.get("identifiers") or [])
                            if new or i.upper() != cve]
        return f"{cve} belongs to another product per CISA KEV; " + (f"replaced with {new}" if new else "removed")
    return None


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
    official = _authority_index(items, tiers)
    kmap = kev_product_map(items)
    for e in digest.get("items", []):
        for f in ("hunt", "fixed_versions", "action", "target", "kev_due_date"):
            e[f] = _nullish(e.get(f))
        if e.get("primary_source") not in allowed:
            problems.append(f"dropped (URL not in input): {e.get('headline', '?')[:60]}")
            continue
        if (note := fix_cve_product(e, kmap)):
            problems.append(note)
        e["corroborating_sources"] = [u for u in (e.get("corroborating_sources") or []) if u in allowed]
        # Cite the official record first when one was collected for the same CVE
        primary_tier = {tiers.get(it["source_name"], "press") for it in by_url.get(e["primary_source"], [])}
        if not primary_tier & CAN_CONFIRM:
            ids = [str(i).upper() for i in e.get("identifiers") or []] + \
                  [c.upper() for c in CVE_RE.findall(e.get("headline", ""))]
            off = next((official[i] for i in ids if i in official), None)
            if off and off != e["primary_source"]:
                e["corroborating_sources"] = [e["primary_source"]] + [u for u in e["corroborating_sources"] if u != off]
                e["primary_source"] = off
                problems.append(f"primary source switched to official record: {e.get('headline', '?')[:50]}")
        e["corroborating_sources"] = e["corroborating_sources"][:2]
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
        e["risk"] = risk_for(e, cited, items)
        e["primary_source"] = clean_url(e["primary_source"])
        e["corroborating_sources"] = [clean_url(u) for u in e["corroborating_sources"]]
        kept.append(e)
    digest["items"] = kept[:8]
    for i, e in enumerate(digest["items"], 1):
        e["rank"] = i
    for field in ("executive_pulse",):
        if BANNED.search(digest.get(field, "")):
            problems.append("banned word in pulse")
    return digest, problems


def risk_for(e: dict, cited: list[dict], items: list[dict]) -> dict | None:
    """Deterministic risk facts for an entry, from the collected data only (never from the model):
    CISA KEV, EPSS, CISA SSVC, VulnCheck KEV. Matched by the entry's CVEs, else by its cited items."""
    ids = {str(i).upper() for i in e.get("identifiers") or []} | {c.upper() for c in CVE_RE.findall(e.get("headline", ""))}
    related = [it for it in items if ids & {c.upper() for c in it.get("cves", [])}] or cited
    r = {}
    if any(it.get("kev") for it in related):
        r["kev"] = True
    epss = [it["epss"] for it in related if it.get("epss")]
    if epss:
        r["epss"] = max(epss, key=lambda x: x["score"])
    if (ss := next((it["ssvc"] for it in related if it.get("ssvc")), None)):
        r["ssvc"] = ss
    if not r.get("kev") and any(it.get("vulncheck_kev") for it in related):
        r["vulncheck_kev"] = True
    return r or None


def risk_line(r: dict | None) -> str:
    """One plain line, e.g. "CISA KEV · EPSS 94% (top 1%) · SSVC: active, automatable, total impact"."""
    if not r:
        return ""
    parts = []
    if r.get("kev"):
        parts.append("CISA KEV")
    elif r.get("vulncheck_kev"):
        parts.append("Exploited per VulnCheck (not yet in CISA KEV)")
    if r.get("epss"):
        top = max(1, round((1 - r["epss"]["percentile"]) * 100))
        parts.append(f"EPSS {r['epss']['score'] * 100:.0f}% (top {top}%)" if top <= 10
                     else f"EPSS {r['epss']['score'] * 100:.1f}%")
    if r.get("ssvc"):
        ss = r["ssvc"]
        words = [ss.get("exploitation"), "automatable" if ss.get("automatable") == "yes" else None,
                 f"{ss['technical_impact']} impact" if ss.get("technical_impact") else None]
        parts.append("SSVC: " + ", ".join(w for w in words if w))
    return " · ".join(parts)


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
    if (rl := risk_line(e.get("risk"))):
        lines.append(f"⚖️ Risk: {rl}")
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
                *([f"- **Risk:** {risk_line(e['risk'])}"] if e.get("risk") else []),
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
