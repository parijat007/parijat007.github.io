"""Watchfloor priority: Act, Attend or Track, worked out from public data only (never from a model).

The three outcomes follow CISA's SSVC wording. CISA's full tree also needs mission and well-being impact, which only
the reader knows, so this is a general-audience starting point and the method page says so.

  Act     exploitation is confirmed: CISA KEV, VulnCheck KEV, SSVC exploitation "active", or a brief item whose
          sources confirm exploitation.
  Attend  not confirmed yet, but likely to be soon: exploitation reported by the brief's sources but not
          confirmed, public exploit code (SSVC "poc", PoC repositories or a brief source),
          EPSS of 10% or more, EPSS in the top 5%, or CVSS 9.0+ with SSVC "automatable: yes".
  Track   everything else.
  (none)  brief items about tools or repositories rather than a flaw get no priority.

Every verdict carries its reasons, each a plain fact from the data, so readers can check it.
"""
from __future__ import annotations

LEVELS = {
    "act": ("Act", "Exploitation is confirmed. Patch or mitigate now."),
    "attend": ("Attend", "Not confirmed exploited, but likely soon. Schedule the fix ahead of routine patching."),
    "track": ("Track", "No sign of exploitation. Handle in routine patching."),
}
EPSS_SCORE = 0.10
EPSS_PCTL = 0.95


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%" if x >= 0.01 else f"{x * 100:.1f}%"


def verdict(*, kev: bool = False, vulncheck: bool = False, exploited: bool = False, ssvc: dict | None = None,
            epss: dict | None = None, poc: int = 0, cvss: float | None = None, ransomware: bool = False,
            kev_due: str | None = None, reported: bool = False, poc_public: bool = False,
            severity: str | None = None) -> dict:
    ssvc = ssvc or {}
    act, attend, notes = [], [], []
    if kev:
        act.append("listed in CISA KEV" + (f", federal due date {kev_due}" if kev_due else ""))
    if vulncheck:
        act.append("listed in VulnCheck KEV")
    if ssvc.get("exploitation") == "active":
        act.append("CISA SSVC: exploitation active")
    if exploited and not act:
        act.append("sources confirm exploitation")
    if ransomware:
        notes.append("known ransomware use (CISA KEV)")
    if reported:
        attend.append("sources report exploitation, not yet confirmed")
    if poc_public and not poc:
        attend.append("public proof of concept reported")
    if ssvc.get("exploitation") == "poc":
        attend.append("CISA SSVC: public proof of concept")
    if poc:
        attend.append(f"public exploit code ({poc} repositor{'y' if poc == 1 else 'ies'})")
    if epss and epss.get("score") is not None:
        s, p = float(epss["score"]), float(epss.get("percentile") or 0)
        if s >= EPSS_SCORE or p >= EPSS_PCTL:
            attend.append(f"EPSS {_pct(s)} chance of exploitation in 30 days (top {max(1, round((1 - p) * 100))}%)"
                          if p else f"EPSS {_pct(s)} chance of exploitation in 30 days")
    if cvss is not None and cvss >= 9.0 and ssvc.get("automatable") == "yes":
        attend.append(f"CVSS {cvss:.1f} and automatable")
    if ssvc.get("technical_impact") == "total":
        notes.append("CISA SSVC: total technical impact")
    level = "act" if act else "attend" if attend else "track"
    label, advice = LEVELS[level]
    if level == "track" and severity in ("CRITICAL", "HIGH"):
        notes.append(f"rated {severity.lower()} severity, no sign of exploitation")
    reasons = act + attend + notes if level != "track" else notes + ([f"CVSS {cvss:.1f}"] if cvss is not None else [])
    return {"level": level, "label": label, "advice": advice, "reasons": reasons, "ransomware": ransomware}


def for_watch(e: dict, ransom: set[str] | None = None) -> dict:
    ransom = ransom or set()
    return verdict(kev=e.get("kind") == "KEV" or bool(e.get("kev_due")), epss=e.get("epss"), poc=e.get("poc") or 0,
                   cvss=e.get("cvss"), kev_due=e.get("kev_due"),
                   ransomware=e.get("ransomware") == "Known" or any(c in ransom for c in e.get("cves") or []))


def for_item(e: dict, ransom: set[str] | None = None) -> dict | None:
    """None for items about tools or repositories (exploitation N/A): there is nothing to patch."""
    if e.get("category") == "GITHUB_REPO" or e.get("exploitation") == "N/A":
        return None
    ransom, r, x = ransom or set(), e.get("risk") or {}, e.get("exploitation")
    return verdict(kev=bool(r.get("kev")), vulncheck=bool(r.get("vulncheck_kev")), ssvc=r.get("ssvc"),
                   exploited=x == "EXPLOITED_CONFIRMED", reported=x == "EXPLOITED_REPORTED",
                   poc_public=x == "POC_PUBLIC", severity=e.get("severity"), epss=r.get("epss"),
                   kev_due=e.get("kev_due_date"), ransomware=any(c in ransom for c in e.get("identifiers") or []))


def for_cve(rec: dict, ransom: set[str] | None = None) -> dict:
    ransom, ev = ransom or set(), rec.get("events") or {}
    k = ev.get("kev_added") or {}
    ep = (rec.get("epss") or [None])[-1]
    return verdict(kev=bool(k), kev_due=k.get("due"), epss={"score": ep["score"]} if ep else None,
                   poc=(ev.get("poc_first_seen") or {}).get("count", 0),
                   ransomware=k.get("ransomware") == "Known" or rec.get("cve") in ransom)


def write_ransomware(kev: dict, out) -> int:
    """data/kev_ransomware.json: CVE ids CISA marks as used in ransomware campaigns, so every page can badge them."""
    import json  # noqa: PLC0415
    ids = sorted(c for c, v in kev.items() if (v.get("knownRansomwareCampaignUse") or "").lower() == "known")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ids, separators=(",", ":")) + "\n")
    return len(ids)
