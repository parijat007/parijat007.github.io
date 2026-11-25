"""Link-preview cards (1200x630 PNG) for briefs and notes, drawn at build time.

Fonts: Archivo (SIL Open Font License, site/og/OFL-Archivo.txt), instanced from the site's own variable font.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
W, H = 1200, 630
BASE, PANEL, RULE, TEXT, MUTED, BREACH, TOOLING = "#0B0F15", "#121823", "#263042", "#E8ECF2", "#93A0B4", "#F0283C", "#2BC3B0"


def _font(kind: str, size: int):
    return ImageFont.truetype(str(HERE / f"archivo-{kind}.ttf"), size)


def _wrap(draw, text: str, font, width_px: int, max_lines: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if draw.textlength(trial, font=font) <= width_px:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        while lines[-1] and draw.textlength(lines[-1] + "…", font=font) > width_px:
            lines[-1] = lines[-1].rsplit(" ", 1)[0]
        lines[-1] += "…"
    return lines


def mark(d, x: int, y: int, size: int) -> None:
    """The Watchfloor mark (brand/watchfloor-mark.svg): 3x3 tiles, the top-right one red."""
    k = size / 64
    d.rounded_rectangle([x, y, x + size, y + size], radius=14 * k, fill=PANEL)
    for r in range(3):
        for c in range(3):
            cx, cy = x + (10 + c * 16) * k, y + (10 + r * 16) * k
            d.rounded_rectangle([cx, cy, cx + 12 * k, cy + 12 * k], radius=2.5 * k,
                                fill=BREACH if (r, c) == (0, 2) else "#364259")


def card(out: Path, kicker: str, title: str, detail: str = "", accent: str = BREACH, footer: str = "theparijat.com") -> Path:
    img = Image.new("RGB", (W, H), BASE)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 14, H], fill=accent)                         # the rail, as on the site's entries
    d.text((80, 72), kicker.upper(), font=_font("bold", 28), fill=accent)
    y = 132
    tf = _font("bold", 64)
    tlines = _wrap(d, title, tf, W - 160, 3)
    for line in tlines:
        d.text((80, y), line, font=tf, fill=TEXT)
        y += 78
    if detail:
        df = _font("regular", 32)
        for line in _wrap(d, detail, df, W - 160, 3 if len(tlines) < 3 else 2):
            d.text((80, y + 24), line, font=df, fill=MUTED)
            y += 44
    d.line([80, H - 96, W - 80, H - 96], fill=RULE, width=2)
    mark(d, 80, H - 78, 36)
    d.text((128, H - 74), "Watchfloor", font=_font("bold", 30), fill=TEXT)
    d.text((W - 80, H - 74), footer, font=_font("regular", 28), fill=MUTED, anchor="ra")
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, "PNG", optimize=True)
    return out
