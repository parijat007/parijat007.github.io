"""Browser and link tests for theparijat.com. See conftest.py for how to run them."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import pytest

KEY_PAGES = ["/", "/today/", "/watch/", "/notes/", "/archive/", "/method/", "/trends/", "/cve/", "/feeds/",
             "/status/", "/security/", "/corrections/"]


def sitemap_paths(site_dir: Path) -> list[str]:
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [e.text for e in ET.parse(site_dir / "sitemap.xml").getroot().findall("s:url/s:loc", ns)]
    return sorted({urlparse(u).path or "/" for u in locs})


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "src"):
            if a.get(k) and not (tag == "link" and a.get("rel") in ("canonical", "alternate") and k == "href"):
                self.refs.append(a[k])


def _resolve(site_dir: Path, page: Path, ref: str) -> Path | None:
    """The file an internal link points at, or None for external/anchor/mailto links."""
    u = urlparse(ref)
    if u.scheme in ("http", "https", "mailto", "tel", "data") or ref.startswith(("#", "//")):
        return None
    rel = page.parent.relative_to(site_dir).as_posix()
    target = urljoin(f"/{rel}/" if rel != "." else "/", u.path)
    f = site_dir / target.lstrip("/")
    return f / "index.html" if target.endswith("/") else f


# ---------- static: every page, every link, every feed ----------

def test_every_internal_link_resolves(site_dir):
    if not site_dir:
        pytest.skip("needs E2E_SITE_DIR")
    broken = []
    for page in site_dir.rglob("*.html"):
        p = Links()
        p.feed(page.read_text(errors="replace"))
        for ref in p.refs:
            f = _resolve(site_dir, page, ref)
            if f is not None and not f.exists():
                broken.append(f"{page.relative_to(site_dir)} -> {ref}")
    assert not broken, "broken internal links:\n" + "\n".join(sorted(set(broken))[:40])


def test_sitemap_feeds_and_api_are_valid(site_dir):
    if not site_dir:
        pytest.skip("needs E2E_SITE_DIR")
    paths = sitemap_paths(site_dir)
    assert len(paths) > 20
    missing = [p for p in paths if not (site_dir / p.lstrip("/") / "index.html").exists() and not (site_dir / p.lstrip("/")).is_file()]
    assert not missing, f"sitemap lists pages that were not built: {missing[:10]}"
    for f in [site_dir / "feed.xml", *(site_dir / "feeds").glob("*.xml")]:
        ET.parse(f)                                            # RSS parses
    for f in (site_dir / "api").rglob("*.json"):
        json.loads(f.read_text())
    json.loads((site_dir / "build.json").read_text())


# ---------- browser: every page loads clean ----------

def test_every_page_loads_without_errors(site_dir, base_url, page_with_checks):
    if not site_dir:
        pytest.skip("needs E2E_SITE_DIR")
    page, failures = page_with_checks, []
    for path in sitemap_paths(site_dir):
        page.problems.clear()
        resp = page.goto(base_url + path, wait_until="load")
        problems = list(page.problems) + page.evaluate("window.__problems || []")
        if not resp or resp.status != 200:
            problems.append(f"status {resp.status if resp else 'none'}")
        if not page.title().strip():
            problems.append("empty <title>")
        if page.locator("h1").count() != 1:
            problems.append(f"{page.locator('h1').count()} h1 elements")
        if page.locator("html[lang]").count() != 1:
            problems.append("no lang on <html>")
        if (n := page.locator("img:not([alt])").count()):
            problems.append(f"{n} images without alt text")
        if problems:
            failures.append(f"{path}: " + "; ".join(problems))
    assert not failures, "\n".join(failures[:30])


@pytest.mark.live
@pytest.mark.parametrize("path", KEY_PAGES)
def test_key_pages_live_and_clean(base_url, page_with_checks, path):
    page = page_with_checks
    resp = page.goto(base_url + path, wait_until="load")
    assert resp and resp.status == 200, f"{path}: status {resp.status if resp else None}"
    problems = list(page.problems) + page.evaluate("window.__problems || []")
    assert not problems, f"{path}: {problems}"
    assert page.locator("nav a").count() >= 5


@pytest.mark.live
@pytest.mark.parametrize("path", ["/", "/watch/", "/today/", "/trends/", "/cve/"])
def test_no_sideways_scroll_on_a_phone(browser, base_url, path):
    ctx = browser.new_context(viewport={"width": 375, "height": 812}, is_mobile=True)
    page = ctx.new_page()
    page.goto(base_url + path, wait_until="load")
    # The page itself must not scroll sideways; content inside its own scroll box (nav, wide tables) may.
    over = page.evaluate("""() => {
      const de = document.documentElement;
      if (de.scrollWidth <= de.clientWidth + 1) return [];
      const boxed = el => { for (let p = el.parentElement; p; p = p.parentElement) {
        if (['auto', 'scroll', 'hidden'].includes(getComputedStyle(p).overflowX)) return true; } return false; };
      return [...document.querySelectorAll('body *')].filter(el =>
        el.getBoundingClientRect().right > de.clientWidth + 1 && !boxed(el)).slice(0, 5)
        .map(el => el.tagName.toLowerCase() + (el.className ? '.' + el.className : ''));
    }""")
    ctx.close()
    assert not over, f"{path} scrolls sideways on a 375px screen because of: {over}"


# ---------- browser: features work ----------

@pytest.mark.live
def test_watch_filters_and_live_times(base_url, page_with_checks):
    page = page_with_checks
    page.goto(base_url + "/watch/", wait_until="load")
    rows = page.locator("table.watch tbody tr")
    assert rows.count() > 0
    page.click(".filters button[data-f='KEV']")
    kinds = page.eval_on_selector_all("table.watch tbody tr:not([hidden])", "rs => rs.map(r => r.dataset.kind)")
    assert kinds and set(kinds) == {"KEV"}
    assert page.get_attribute(".filters button[data-f='KEV']", "aria-pressed") == "true"
    page.click(".filters button[data-f='all']")
    assert page.locator("table.watch tbody tr:not([hidden])").count() == rows.count()
    agos = page.eval_on_selector_all("time[data-ago]", "ts => ts.map(t => t.textContent)")
    assert agos and all(re.search(r"ago|just now", a) for a in agos), agos[:5]


@pytest.mark.live
def test_cve_anatomy_and_trends_render(base_url, page_with_checks):
    page = page_with_checks
    page.goto(base_url + "/cve/", wait_until="load")
    first = page.locator("table.watch tbody tr a.id").first
    href = first.get_attribute("href")
    page.goto(urljoin(base_url + "/cve/", href), wait_until="load")
    assert page.locator("h1").inner_text().strip()
    page.goto(base_url + "/trends/", wait_until="load")
    month = page.locator(".trend-months a").first
    page.goto(urljoin(base_url + "/trends/", month.get_attribute("href")), wait_until="load")
    assert page.locator(".bars li").count() > 0 and page.locator("table.watch tbody tr").count() > 0


@pytest.mark.live
def test_note_share_and_comments(base_url, page_with_checks):
    page = page_with_checks
    page.goto(base_url + "/notes/", wait_until="load")
    page.goto(urljoin(base_url + "/notes/", page.locator("main a[href*='notes/2']").first.get_attribute("href")),
              wait_until="load")
    assert page.locator(".share a").count() >= 2
    btn = page.locator("button[data-comments]")
    if btn.count():                                  # comments configured: nothing from giscus until clicked
        assert not [s for s in page.eval_on_selector_all("script", "ss => ss.map(s => s.src)") if "giscus" in s]
    assert not (page.problems + page.evaluate("window.__problems || []"))
