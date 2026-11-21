"""Deterministic collectors. No LLM here: every item carries its own source URL."""
from __future__ import annotations

import html
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import feedparser
import requests

log = logging.getLogger("digest.collect")
UA = {"User-Agent": "threat-digest/1.0 (personal daily digest)"}
TIMEOUT = 30
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _clean(text: str | None, limit: int = 600) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _get_json(url: str, **kw):
    r = requests.get(url, headers={**UA, **kw.pop("headers", {})}, timeout=TIMEOUT, **kw)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------- CISA KEV
def load_kev() -> dict:
    """Full KEV catalog keyed by CVE. Falls back to the official GitHub mirror."""
    for url in (KEV_URL, KEV_MIRROR):
        try:
            data = _get_json(url)
            return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
        except Exception as e:  # noqa: BLE001
            log.warning("KEV fetch failed from %s: %s", url, e)
    raise RuntimeError("CISA KEV unavailable from both primary and mirror")


def _kev_title(v: dict) -> str:
    """KEV names usually repeat the vendor ('Cisco X: Cisco X Use of ...'); keep the descriptive part."""
    name = (v.get("vulnerabilityName") or "").strip()
    prod = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
    return name if v.get("product", "").lower() in name.lower() else f"{prod}: {name}"


def kev_items(kev: dict, since: datetime) -> list[dict]:
    items = []
    for cve, v in kev.items():
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if added < since.replace(hour=0, minute=0, second=0, microsecond=0):
            continue
        refs = re.findall(r"https?://[^\s;]+", v.get("notes", ""))[:3]
        items.append({
            "id": cve,
            "source_type": "kev",
            "source_name": "CISA KEV",
            "title": _kev_title(v),
            "text": _clean(v.get("shortDescription")),
            "required_action": _clean(v.get("requiredAction"), 300),
            "product": f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
            "cwes": v.get("cwes", []) or [],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "refs": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", *refs],
            "published": v.get("dateAdded"),
            "cves": [cve],
        })
    return items


# ---------------------------------------------------------------- NVD
def nvd_items(cfg: dict, since: datetime, until: datetime) -> list[dict]:
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out = []
    for sev in cfg.get("severities", ["CRITICAL"]):
        data = _get_json(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers=headers,
            params={"pubStartDate": since.strftime(fmt), "pubEndDate": until.strftime(fmt),
                    "cvssV3Severity": sev, "resultsPerPage": cfg.get("max_results", 40)},
        )
        for v in data.get("vulnerabilities", []):
            c = v["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            score = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                if c.get("metrics", {}).get(key):
                    score = c["metrics"][key][0]["cvssData"].get("baseScore")
                    break
            out.append({
                "id": c["id"], "source_type": "nvd", "source_name": "NVD",
                "title": c["id"], "text": _clean(desc),
                "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                "refs": [r["url"] for r in c.get("references", [])[:3]],
                "published": c.get("published"), "cves": [c["id"]], "cvss": score,
                "cwes": sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                                if d.get("value", "").startswith("CWE-")}),
            })
    return out


# ---------------------------------------------------------------- GitHub Security Advisories
def ghsa_items(cfg: dict, since: datetime) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    out = []
    for sev in cfg.get("severities", ["critical"]):
        data = _get_json("https://api.github.com/advisories", headers=headers, params={
            "type": "reviewed", "severity": sev, "per_page": cfg.get("max_results", 30),
            "published": f">={since.date().isoformat()}"})
        for a in data:
            pkgs = [f"{(p.get('package') or {}).get('ecosystem')}:{(p.get('package') or {}).get('name')}"
                    for p in a.get("vulnerabilities", [])][:4]
            cve = a.get("cve_id")
            out.append({
                "id": a["ghsa_id"], "source_type": "ghsa", "source_name": "GitHub Advisory",
                "title": a.get("summary", ""),
                "text": _clean(f"Packages: {', '.join(pkgs)}. {a.get('description', '')}"),
                "url": a["html_url"], "refs": [], "published": a.get("published_at"),
                "cves": [cve] if cve else [], "severity": a.get("severity"),
                "cvss": (a.get("cvss") or {}).get("score"),
                "cwes": [w.get("cwe_id") for w in a.get("cwes", []) if w.get("cwe_id")],
            })
    return out


# ---------------------------------------------------------------- GitHub repos
def repo_items(cfg: dict) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    since = (datetime.now(timezone.utc) - timedelta(days=cfg.get("created_within_days", 14))).date()
    seen, out = set(), []
    for q in cfg.get("queries", []):
        query = f"{q} created:>={since} stars:>={cfg.get('min_stars', 40)} archived:false fork:false"
        try:
            data = _get_json("https://api.github.com/search/repositories", headers=headers, params={
                "q": query, "sort": "stars", "order": "desc", "per_page": cfg.get("max_per_query", 8)})
        except Exception as e:  # noqa: BLE001
            log.warning("repo search failed for %s: %s", q, e)
            continue
        for r in data.get("items", []):
            name = r["full_name"]
            # Pre-filter low-signal repos before the model sees them
            if name in seen or not r.get("description") or not r.get("license"):
                continue
            if re.search(r"awesome|cheat-?sheet|list", name, re.I):
                continue
            seen.add(name)
            out.append({
                "id": name, "source_type": "repo", "source_name": "GitHub",
                "title": name, "text": _clean(r.get("description"), 300),
                "url": r["html_url"], "refs": [], "published": r.get("created_at"),
                "cves": CVE_RE.findall(f"{name} {r.get('description')}"),
                "stars": r.get("stargazers_count"), "license": (r.get("license") or {}).get("spdx_id"),
                "pushed_at": r.get("pushed_at"), "topics": r.get("topics", [])[:8],
                "language": r.get("language"),
            })
    return out


# ---------------------------------------------------------------- RSS
def _entry_time(e) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        if e.get(key):
            return datetime(*e[key][:6], tzinfo=timezone.utc)
    for key in ("published", "updated"):
        if e.get(key):
            try:
                return parsedate_to_datetime(e[key]).astimezone(timezone.utc)
            except (TypeError, ValueError):
                pass
    return None


def rss_items(feeds: list[dict], since: datetime, per_feed: int, status: dict) -> list[dict]:
    out = []
    for f in feeds:
        try:
            resp = requests.get(f["url"], headers=UA, timeout=TIMEOUT)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
        except Exception as e:  # noqa: BLE001
            status[f["name"]] = f"error: {type(e).__name__}"
            continue
        n = off = 0
        allowed = tuple(f.get("domains", []))
        for e in parsed.entries[: per_feed * 3]:
            t = _entry_time(e)
            if not t or t < since or not e.get("link"):
                continue
            host = urlparse(e["link"]).netloc.lower()
            if urlparse(e["link"]).scheme != "https" or (allowed and not any(
                    host == d or host.endswith("." + d) for d in allowed)):
                off += 1   # feed points somewhere it shouldn't: hijacked feed or redirector
                continue
            text = _clean(e.get("summary") or e.get("description"))
            out.append({
                "id": e.get("id") or e["link"], "source_type": "rss", "source_name": f["name"],
                "source_tier": f.get("tier", "press"), "title": _clean(e.get("title"), 200),
                "text": text, "url": e["link"], "refs": [], "published": t.isoformat(),
                "cves": sorted({c.upper() for c in CVE_RE.findall(f"{e.get('title')} {text}")}),
            })
            n += 1
            if n >= per_feed:
                break
        status[f["name"]] = f"ok ({n})" + (f", {off} off-domain dropped" if off else "")
    return out


# ---------------------------------------------------------------- Enrichment
def epss_scores(cves: list[str]) -> dict:
    out = {}
    cves = sorted(set(cves))
    for i in range(0, len(cves), 80):
        try:
            data = _get_json("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves[i:i + 80])})
            for d in data.get("data", []):
                out[d["cve"].upper()] = {"score": round(float(d["epss"]), 4),
                                         "percentile": round(float(d["percentile"]), 3)}
        except Exception as e:  # noqa: BLE001
            log.warning("EPSS lookup failed: %s", e)
    return out


def poc_counts(cves: list[str], limit: int = 40) -> dict:
    """Public PoC repos per CVE from nomi-sec/PoC-in-GitHub (CC0, no key needed)."""
    out = {}
    for cve in sorted(set(cves))[:limit]:
        year = cve.split("-")[1]
        try:
            r = requests.get(f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json",
                             headers=UA, timeout=15)
            if r.status_code == 200:
                repos = r.json()
                out[cve] = {"count": len(repos),
                            "top_repo_stars": max((p.get("stargazers_count", 0) for p in repos), default=0)}
            else:
                out[cve] = {"count": 0}
        except Exception as e:  # noqa: BLE001
            log.debug("PoC lookup failed for %s: %s", cve, e)
    return out


def enrich(items: list[dict], kev: dict, watchlist: list[str]) -> None:
    all_cves = [c.upper() for it in items for c in it.get("cves", [])]
    epss = epss_scores(all_cves)
    # Deterministic corroboration: how many independent sources mention each CVE
    sources_per_cve: dict[str, set] = {}
    for it in items:
        for c in it.get("cves", []):
            sources_per_cve.setdefault(c.upper(), set()).add(it["source_name"])
    # PoC lookups only for CVEs that matter (KEV, high EPSS, or multi-source)
    hot = [c for c in set(all_cves) if c in kev or (epss.get(c, {}).get("score", 0) >= 0.1)
           or len(sources_per_cve.get(c, ())) >= 2]
    pocs = poc_counts(hot)
    for it in items:
        cves = [c.upper() for c in it.get("cves", [])]
        if cves:
            it["source_count"] = max(len(sources_per_cve.get(c, ())) for c in cves)
            hits = [pocs[c] for c in cves if pocs.get(c, {}).get("count")]
            if hits:
                it["public_poc"] = max(hits, key=lambda h: h["count"])
        kev_hits = [c for c in it.get("cves", []) if c.upper() in kev]
        if kev_hits:
            v = kev[kev_hits[0].upper()]
            it["kev"] = {"listed": True, "cve": kev_hits[0], "dateAdded": v.get("dateAdded"),
                         "dueDate": v.get("dueDate"),
                         "ransomware": v.get("knownRansomwareCampaignUse")}
        scores = [epss[c.upper()] for c in it.get("cves", []) if c.upper() in epss]
        if scores:
            it["epss"] = max(scores, key=lambda s: s["score"])
        blob = f"{it.get('title')} {it.get('text')} {' '.join(it.get('topics', []))}".lower()
        it["stack_match"] = [w for w in watchlist if re.search(rf"\b{re.escape(w.lower())}\b", blob)]


def prerank(items: list[dict]):
    """Cheap heuristic to cap tokens; the model does the real ranking."""
    def score(it):
        s = 0.0
        if it.get("kev"):
            s += 100
        s += (it.get("epss") or {}).get("score", 0) * 40
        s += (it.get("cvss") or 0) * 2
        s += 10 * len(it.get("stack_match", []))
        s += 8 * (it.get("source_count", 1) - 1)
        s += 10 if it.get("public_poc") else 0
        s += {"authority": 25, "vendor": 20, "research": 15, "press": 5}.get(it.get("source_tier", ""), 0)
        if it["source_type"] == "repo":
            s += min((it.get("stars") or 0) / 20, 15)
        return s
    return score
