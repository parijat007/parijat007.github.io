"""Deterministic remediation playbook.

The patch itself (fixed version) must come from the vendor or source text. When no fix is published,
or until it is applied, these compensating controls reduce exposure. Keyed by CWE (from NVD/KEV)
with keyword fallbacks, so guidance never depends on the model being right.
"""
from __future__ import annotations

import re

# CWE -> (weakness name, compensating controls, how to verify)
CWE_PLAYBOOK: dict[str, tuple[str, list[str], str]] = {
    "auth": ("Authentication bypass", [
        "Restrict management and admin interfaces to a dedicated admin network or VPN; block them from the internet",
        "Require phishing-resistant MFA for administrative access where the product supports it",
        "Rotate admin credentials and API keys, and remove unknown admin accounts",
    ], "Review admin and auth logs since the disclosure date for logins without a matching MFA or SSO event"),
    "deserialization": ("Unsafe deserialization", [
        "Block or filter untrusted network access to the affected endpoint (WAF rule or network ACL)",
        "Run the service with least privilege and no outbound internet access where possible",
    ], "Hunt for unexpected child processes spawned by the application server process"),
    "hardcoded": ("Hard-coded credentials", [
        "Restrict network access to the affected service to known management hosts",
        "Change any credentials the vendor allows you to change and monitor for logins by built-in accounts",
    ], "Search authentication logs for logins by built-in or service accounts from unexpected sources"),
    "injection": ("Command or code injection", [
        "Remove internet exposure of the affected interface until patched",
        "Apply WAF or IPS signatures from your vendor for the CVE, in blocking mode",
        "Run the service as a non-privileged user and restrict outbound connections",
    ], "Hunt for shells or scripting engines spawned by the affected service, and new scheduled tasks or cron entries"),
    "sqli": ("SQL injection", [
        "Apply WAF rules for SQL injection on the affected application paths",
        "Use a least-privilege database account for the application",
    ], "Review web logs for SQL syntax in parameters and database logs for errors from the application account"),
    "traversal": ("Path traversal", [
        "Block requests containing traversal sequences at the WAF or reverse proxy",
        "Restrict the service account's file system permissions",
    ], "Search web logs for '../' and encoded variants against the affected paths"),
    "ssrf": ("Server-side request forgery", [
        "Restrict the server's outbound traffic to required destinations only",
        "Block access to cloud instance metadata from the application (for example IMDSv2 with hop limit 1 on AWS)",
    ], "Review egress and metadata-service access logs from the affected host"),
    "xss": ("Cross-site scripting", [
        "Enforce a strict Content-Security-Policy on the affected application",
        "Limit administrative sessions and require re-authentication for sensitive actions",
    ], "Review web logs for script payloads in parameters"),
    "memory": ("Memory corruption", [
        "Remove internet exposure of the affected service until patched",
        "Enable platform exploit mitigations and restart the service after patching",
    ], "Monitor for crashes or unexpected restarts of the affected service"),
    "upload": ("Unrestricted file upload", [
        "Disable or restrict the upload feature, or block it at the WAF",
        "Prevent execution in upload directories",
    ], "Search web roots for recently created script files"),
    "default": ("Vulnerability", [
        "Reduce exposure: remove internet access to the affected service or interface until patched",
        "Apply vendor-provided mitigations or IPS/WAF signatures where published",
    ], "Confirm the installed version on every instance after patching"),
}

CWE_MAP = {
    "CWE-287": "auth", "CWE-288": "auth", "CWE-306": "auth", "CWE-290": "auth", "CWE-862": "auth", "CWE-863": "auth",
    "CWE-502": "deserialization",
    "CWE-798": "hardcoded", "CWE-259": "hardcoded", "CWE-1392": "hardcoded",
    "CWE-77": "injection", "CWE-78": "injection", "CWE-94": "injection", "CWE-95": "injection", "CWE-917": "injection",
    "CWE-89": "sqli",
    "CWE-22": "traversal", "CWE-23": "traversal", "CWE-36": "traversal",
    "CWE-918": "ssrf",
    "CWE-79": "xss",
    "CWE-787": "memory", "CWE-119": "memory", "CWE-416": "memory", "CWE-120": "memory", "CWE-122": "memory",
    "CWE-434": "upload",
}

KEYWORDS = [
    (r"authenticat\w* bypass|missing authentication|improper authentication|alternate path or channel", "auth"),
    (r"deserializ", "deserialization"),
    (r"hard-?coded (credential|password|key)", "hardcoded"),
    (r"sql injection", "sqli"),
    (r"(os |command |code )injection|remote code execution|code execution", "injection"),
    (r"path traversal|directory traversal", "traversal"),
    (r"server-side request forgery|\bssrf\b", "ssrf"),
    (r"cross-site scripting|\bxss\b", "xss"),
    (r"buffer overflow|out-of-bounds write|use-after-free|heap overflow|memory corruption", "memory"),
    (r"file upload", "upload"),
]
EDGE = re.compile(r"firewall|vpn|gateway|appliance|router|load balancer|expressway|vcenter|esxi|netscaler|"
                  r"fortios|pan-os|ivanti|citrix|edge|ssl ?vpn|remote access", re.I)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}[a-z0-9-]*\b", re.I)


def classify(cwes: list[str], text: str) -> str:
    for c in cwes or []:
        if c.upper() in CWE_MAP:
            return CWE_MAP[c.upper()]
    for pat, key in KEYWORDS:
        if re.search(pat, text or "", re.I):
            return key
    return "default"


def remediation_for(item_or_entry: dict, source_text: str = "") -> dict:
    """Compensating controls + verification for an item, plus an edge-device control when relevant."""
    text = f"{item_or_entry.get('title', '')} {item_or_entry.get('headline', '')} {item_or_entry.get('text', '')} " \
           f"{item_or_entry.get('summary', '')} {item_or_entry.get('target', '')} {source_text}"
    key = classify(item_or_entry.get("cwes", []), text)
    name, controls, verify = CWE_PLAYBOOK[key]
    controls = list(controls)
    if EDGE.search(text) and not any("management interface" in c or "admin network" in c for c in controls):
        controls.insert(0, "Restrict the device's management interface to an admin network; check for new admin accounts and config changes")
    return {"weakness": name, "compensating_controls": controls[:3], "verify": verify}


def grounded_versions(fixed: str | None, evidence: str) -> str | None:
    """Keep a fixed-version claim only if every version number in it appears in the source text."""
    if not fixed:
        return None
    versions = VERSION_RE.findall(fixed)
    if not versions:
        return None
    return fixed if all(v in evidence for v in versions) else None
