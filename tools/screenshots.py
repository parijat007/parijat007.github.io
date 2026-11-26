"""Screenshots of key pages of a built site, desktop and phone, for review in a CI artifact.

    python tools/screenshots.py _site shots
"""
import functools
import http.server
import sys
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D102
        pass

PAGES = ["/", "/today/", "/watch/", "/notes/", "/trends/", "/cve/", "/status/"]


def main(site: str, out: str) -> None:
    Path(out).mkdir(parents=True, exist_ok=True)
    handler = functools.partial(Quiet, directory=site)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        for name, vp in (("desktop", {"width": 1280, "height": 900}), ("phone", {"width": 390, "height": 844})):
            page = b.new_page(viewport=vp)
            for path in PAGES:
                page.goto(base + path, wait_until="load")
                page.screenshot(path=f"{out}/{name}-{path.strip('/').replace('/', '-') or 'home'}.png", full_page=True)
            page.close()
        b.close()
    srv.shutdown()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
