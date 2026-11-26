"""End-to-end tests run against a built copy of the site (default) or the live site (E2E_BASE_URL).

    python site/build.py --out _site && E2E_SITE_DIR=_site python -m pytest -q tests/e2e      # before deploy
    E2E_BASE_URL=https://theparijat.com python -m pytest -q tests/e2e -m live                 # after deploy
"""
from __future__ import annotations

import functools
import http.server
import os
import threading
from pathlib import Path

import pytest


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D102
        pass

def pytest_configure(config):
    config.addinivalue_line("markers", "live: safe to run against the live site (read-only)")


@pytest.fixture(scope="session")
def site_dir() -> Path | None:
    d = os.environ.get("E2E_SITE_DIR")
    return Path(d).resolve() if d else None


@pytest.fixture(scope="session")
def base_url(site_dir):
    if os.environ.get("E2E_BASE_URL"):
        yield os.environ["E2E_BASE_URL"].rstrip("/")
        return
    if not site_dir:
        pytest.skip("set E2E_SITE_DIR (a built site) or E2E_BASE_URL")
    handler = functools.partial(Quiet, directory=str(site_dir))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(scope="session")
def browser():
    pw_mod = pytest.importorskip("playwright.sync_api")
    with pw_mod.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


# Collects CSP violations and script errors from every page.
WATCH_JS = """
window.__problems = [];
document.addEventListener('securitypolicyviolation', e =>
  window.__problems.push('CSP blocked ' + e.violatedDirective + ': ' + (e.blockedURI || 'inline')));
window.addEventListener('error', e => window.__problems.push('script error: ' + e.message));
"""


@pytest.fixture
def page_with_checks(browser, base_url):
    """A page that records console errors, failed same-origin requests, CSP violations and script errors."""
    ctx = browser.new_context()
    ctx.add_init_script(WATCH_JS)
    page = ctx.new_page()
    problems: list[str] = []
    page.on("console", lambda m: m.type == "error" and problems.append(f"console: {m.text}"))
    page.on("pageerror", lambda e: problems.append(f"page error: {e}"))
    page.on("response", lambda r: r.url.startswith(base_url) and r.status >= 400 and problems.append(f"HTTP {r.status} {r.url}"))
    page.on("requestfailed", lambda r: r.url.startswith(base_url) and problems.append(f"failed {r.url}"))
    page.problems = problems
    yield page
    ctx.close()
