"""Daily live-site check (security.yml).

Fails (exit 1) when the live site is not what we deployed:
  - build.json's commit is not on main
  - a live file's SHA-256 differs from build.json
  - http:// does not redirect to https://, or the Content-Security-Policy is missing
Warns only (exit 0) on broken source links in the latest brief: many sites refuse bots.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
SITE = os.environ.get("WF_SITE_URL", "https://theparijat.com").rstrip("/")
SAMPLE = ["index.html", "today/index.html", "watch/index.html", "static/style.css",
          ".well-known/security.txt", "feed.xml", "api/latest.json"]
UA = {"User-Agent": "watchfloor-site-check (+https://theparijat.com/method/)"}


def get(url: str, **kw) -> requests.Response:
    return requests.get(url, headers=UA, timeout=20, **kw)


def main() -> int:
    problems, warnings, rows = [], [], []

    try:
        manifest = get(f"{SITE}/build.json").json()
    except (requests.RequestException, ValueError) as e:
        print(f"::error::cannot read {SITE}/build.json: {e}")
        return 1
    commit = manifest.get("commit", "")
    on_main = subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=ROOT).returncode == 0
    rows.append(("deployed commit", f"{commit[:10]} built {manifest.get('built_at')}", "ok" if on_main else "NOT ON MAIN"))
    if not on_main:
        problems.append(f"live site built from {commit!r}, which is not a commit on main")

    for path in SAMPLE:
        want = manifest.get("files", {}).get(path)
        if not want:
            continue
        r = get(f"{SITE}/{path.removesuffix('index.html')}")
        got = hashlib.sha256(r.content).hexdigest() if r.ok else f"HTTP {r.status_code}"
        ok = got == want
        rows.append((path, got[:12], "ok" if ok else "CHANGED"))
        if not ok:
            problems.append(f"{path}: live content differs from the deployed build")

    r = requests.get(SITE.replace("https://", "http://"), headers=UA, timeout=20, allow_redirects=False)
    https_ok = 300 <= r.status_code < 400 and r.headers.get("location", "").startswith("https://")
    rows.append(("http -> https", str(r.status_code), "ok" if https_ok else "NO REDIRECT"))
    if not https_ok:
        problems.append("http:// does not redirect to https://")

    home = get(f"{SITE}/").text
    csp_ok = "Content-Security-Policy" in home
    rows.append(("CSP present", "", "ok" if csp_ok else "MISSING"))
    if not csp_ok:
        problems.append("Content-Security-Policy missing from the home page")

    latest = json.loads((ROOT / "data" / "briefs" / sorted(os.listdir(ROOT / "data" / "briefs"))[-1]).read_text())
    for it in latest.get("items", []):
        for src in (it.get("sources") or [])[:1]:
            url = src.get("url") if isinstance(src, dict) else src
            if not url:
                continue
            try:
                s = requests.head(url, headers=UA, timeout=15, allow_redirects=True)
                if s.status_code in (403, 405, 429):
                    continue                    # bot walls, not broken links
                if s.status_code >= 400:
                    warnings.append(f"{s.status_code} {url}")
            except requests.RequestException as e:
                warnings.append(f"{type(e).__name__} {url}")

    out = ["| check | value | result |", "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in rows]
    if warnings:
        out += ["", "Source links that did not load (warning only):", *[f"- {w}" for w in warnings]]
    text = "\n".join(out)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n")
    for w in warnings:
        print(f"::warning title=Source link::{w}")
    for p in problems:
        print(f"::error title=Live site check::{p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
