#!/usr/bin/env python3
"""Render every README asset from one source, on the PipeLab design system.

The README embeds each diagram twice, through a ``<picture>`` element that
picks a variant from the reader's color scheme. Two hand-maintained copies of
one drawing drift the moment either is edited, and a drifted pair is invisible
in review because each file is individually well-formed. So geometry, copy, and
counts live here once, the palette is the only thing that varies, and
``make check-diagrams`` fails when a committed asset no longer matches what
this script produces from the live corpus.

Numbers are never painted into the hero or the logomark, which are exported by
hand and change rarely. Numbers that must track the corpus live in the stats
strip and the coverage chart, which ``make stats-update`` regenerates in the
same step as ``cases/STATS.md``.

Design tokens follow the PipeLab design system: near-black surfaces, one teal
accent, JetBrains Mono for headings and data, Inter for body, translucent
cards, purple only as a hero radial. The dark variants are transparent so they
sit flush on GitHub's canvas; the light variants darken the accent for contrast
and otherwise keep the same geometry and copy.

Run ``scripts/render_diagrams.py`` to write the files, or ``--check`` to
compare without writing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = REPO_ROOT / "assets"
STATS_FILE = REPO_ROOT / "cases" / "STATS.md"
DOCTOR_SCRIPT = REPO_ROOT / "scripts" / "run-pipelock-gauntlet.sh"

# Brand font stacks. GitHub renders README images without web fonts, so the
# fallbacks matter; the PNG exports are made on a host with the brand fonts.
MONO = "'JetBrains Mono', 'JetBrainsMono Nerd Font', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, monospace"
SANS = "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"

# Locked brand tokens (pipelab.org/.brand/colors_and_type.css).
BRAND = {
    "accent": "#00e5a0",
    "purple": "#7c3aed",
    "bg": "#09090b",
    "bg_elevated": "#0e0e11",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "dim": "#64748b",
    "warn": "#f59e0b",
    "danger": "#ef4444",
    "info": "#38bdf8",
}

# Family social-card footer. Same string, type, and position as Pipelock Rules,
# so the three cards read as one house rather than three layouts.
CARD_FOOTER = "Apache 2.0  ·  maintained by PipeLab"
CARD_FOOTER_X = 120
CARD_FOOTER_Y = 566
CARD_FOOTER_SIZE = 16

# These are contrast adaptations for text and status marks on GitHub's white
# canvas. Filled bars keep the locked accent, with dark token text on top.
LIGHT_THEME_DERIVATIVES = {"#008f66", "#dc2626", "#b45309", "#0284c7"}

# White is not a paint color here. The brand defines translucent surfaces as
# rgba(255,255,255,...) card and border tokens, and _paint splits those into a
# hex base plus an opacity attribute, so the base is what lands in the file.
# Named here so the color gate stays a real check rather than being widened.
OVERLAY_BASES = {"#ffffff"}

# README palettes. Both canvases are transparent so a diagram sits on GitHub's
# own page color instead of arriving as a pasted rectangle.
PALETTES = {
    "dark": {
        "canvas": "none",
        "card": "rgba(255,255,255,0.04)",
        "card_strong": "rgba(255,255,255,0.07)",
        "border": "rgba(255,255,255,0.10)",
        "border_strong": "rgba(255,255,255,0.18)",
        "text": BRAND["text"],
        "muted": BRAND["muted"],
        "dim": BRAND["dim"],
        "accent": BRAND["accent"],
        "accent_text": BRAND["accent"],
        "accent_soft": "rgba(0,229,160,0.12)",
        "accent_border": "rgba(0,229,160,0.35)",
        "danger": BRAND["danger"],
        "danger_soft": "rgba(239,68,68,0.14)",
        "warn": BRAND["warn"],
        "warn_soft": "rgba(245,158,11,0.14)",
        "info": BRAND["info"],
        "info_soft": "rgba(56,189,248,0.14)",
        "terminal": BRAND["bg_elevated"],
    },
    "light": {
        "canvas": "none",
        "card": "rgba(9,9,11,0.03)",
        "card_strong": "rgba(9,9,11,0.06)",
        "border": "rgba(9,9,11,0.12)",
        "border_strong": "rgba(9,9,11,0.22)",
        "text": BRAND["bg"],
        "muted": BRAND["dim"],
        "dim": "#64748b",
        "accent": BRAND["accent"],
        "accent_text": "#008f66",
        "accent_soft": "rgba(0,229,160,0.16)",
        "accent_border": "rgba(0,143,102,0.45)",
        "danger": "#dc2626",
        "danger_soft": "rgba(220,38,38,0.10)",
        "warn": "#b45309",
        "warn_soft": "rgba(180,83,9,0.12)",
        "info": "#0284c7",
        "info_soft": "rgba(2,132,199,0.12)",
        "terminal": BRAND["bg_elevated"],
    },
}


# --------------------------------------------------------------------------
# Corpus facts. Everything painted into an asset comes through here.
# --------------------------------------------------------------------------

STATS_ENTRY = re.compile(r"^\s+([a-z0-9_]+):\s*(\d+)\s*$")
STATS_TOTAL = re.compile(r"^cases_total:\s*(\d+)\s*$", re.MULTILINE)
TRANSPORT_FIELD = re.compile(
    r'["\']transport["\']\s*:\s*["\']([a-z0-9_]+)["\']'
    r"|^transport:\s*([a-z0-9_]+)\s*$",
    re.MULTILINE,
)
def live_category_counts() -> dict[str, int]:
    """Per-category case counts, straight from the generated corpus stats."""
    body = STATS_FILE.read_text(encoding="utf-8").split("by_category:", 1)
    if len(body) != 2:
        raise SystemExit(
            "render_diagrams: FAIL - cases/STATS.md has no by_category block; run 'make stats-update'"
        )
    counts = {}
    for line in body[1].splitlines():
        match = STATS_ENTRY.match(line)
        if match:
            counts[match.group(1)] = int(match.group(2))
    if not counts:
        raise SystemExit("render_diagrams: FAIL - cases/STATS.md listed no categories")
    return counts


def live_case_total() -> int:
    """The loader-backed total, which counts a drift directory as one case."""
    match = STATS_TOTAL.search(STATS_FILE.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit("render_diagrams: FAIL - cases/STATS.md has no cases_total")
    return int(match.group(1))


def runner_stats_problems() -> list[str]:
    """Confirm the snapshot that feeds drawings still matches the real loader.

    The renderer needs a compact source for individual values, but that source
    is only trustworthy when the runner that defines corpus semantics agrees.
    This deliberately runs only in ``--check`` mode: ``stats-update`` already
    obtains the same output before it rewrites the snapshot.
    """
    try:
        run = subprocess.run(
            ["go", "run", ".", "--stats", "--cases", "../cases"],
            cwd=REPO_ROOT / "runner",
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return [f"corpus stats: cannot run the runner: {exc}"]
    if run.returncode != 0:
        detail = run.stderr.strip() or "the runner exited without diagnostics"
        return [f"corpus stats: runner failed: {detail}"]
    if not run.stdout.strip():
        return ["corpus stats: runner produced no output"]
    if STATS_FILE.read_text(encoding="utf-8") != run.stdout:
        return [
            "corpus stats: cases/STATS.md does not match the runner; "
            "run 'make stats-update'"
        ]
    return []


def live_categories() -> set[str]:
    return set(live_category_counts())


def live_transports() -> set[str]:
    """Transports declared anywhere in the corpus, single-file and multi-file."""
    found = set()
    for path in sorted((REPO_ROOT / "cases").rglob("*")):
        if path.suffix not in {".json", ".yaml", ".yml"} or not path.is_file():
            continue
        for match in TRANSPORT_FIELD.finditer(path.read_text(encoding="utf-8")):
            found.add(match.group(1) or match.group(2))
    if not found:
        raise SystemExit("render_diagrams: FAIL - no transports found under cases/")
    return found


def doctor_check_names() -> list[str]:
    """Read the doctor codes from its real machine-readable output.

    A regex over shell source treated commented-out checks as live and could
    leave the terminal asset green after the doctor stopped reporting a check.
    The doctor emits its complete code list even when prerequisites are absent,
    so its JSON output is the producer this drawing needs to follow.
    """
    try:
        run = subprocess.run(
            [str(DOCTOR_SCRIPT), "--doctor-json"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise SystemExit(f"render_diagrams: FAIL - cannot run doctor: {exc}") from exc
    try:
        report = json.loads(run.stdout)
        checks = report["checks"]
        names = [check["code"] for check in checks]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SystemExit(
            "render_diagrams: FAIL - doctor did not emit its expected JSON check list"
        ) from exc
    if not names or any(not isinstance(name, str) or not name for name in names):
        raise SystemExit("render_diagrams: FAIL - doctor emitted an invalid check name")
    if len(names) != len(set(names)):
        raise SystemExit("render_diagrams: FAIL - doctor emitted duplicate check names")
    return names


# --------------------------------------------------------------------------
# SVG primitives.
# --------------------------------------------------------------------------


_RGBA = re.compile(r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([0-9.]+)\s*\)")


def _n(value) -> str:
    """Format a coordinate: integers bare, everything else to two decimals.

    Binary floating point turns a ruler position of 966.4 into the printed
    coordinate `966.4000000000001`. Sixteen digits in a row is not merely
    untidy: this repository scans its own diff with Pipelock, and that run
    matches the Credit Card Number pattern, so the generated card blocks its own
    pull request. Rounding here removes the noise at its source, and a test
    holds path data to short digit runs so it cannot come back.

    The same fix exists in pipelock-rules. Both repositories generate art that
    their own scanners read, so both need it.
    """
    if isinstance(value, str):
        return value
    rounded = round(float(value), 2)
    return str(int(rounded)) if rounded == int(rounded) else f"{rounded:g}"


def _paint(attribute: str, value: str) -> str:
    """Emit a paint as hex plus a separate opacity attribute.

    An SVG 1.1 presentation attribute takes a CSS2 `<color>`, which has no
    `rgba()`. Browsers parse it anyway, so a README image looks right on
    GitHub while every non-browser renderer paints it black: the light-theme
    cards exported as unreadable black boxes until this existed. Hex plus
    `-opacity` is the portable spelling of the same color.
    """
    match = _RGBA.fullmatch(value.strip())
    if not match:
        return f'{attribute}="{value}"'
    red, green, blue, alpha = match.groups()
    hexed = f"#{int(red):02x}{int(green):02x}{int(blue):02x}"
    return f'{attribute}="{hexed}" {attribute}-opacity="{alpha}"'


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _text(x, y, content, *, fill, size=13, family=SANS, weight=400, anchor="start",
          spacing=None, opacity=None, upper=False):
    if upper:
        content = content.upper()
    attrs = [f'x="{_n(x)}"', f'y="{_n(y)}"', f'font-family="{family}"', f'font-size="{size}"', f'fill="{fill}"']
    if weight != 400:
        attrs.append(f'font-weight="{weight}"')
    if anchor != "start":
        attrs.append(f'text-anchor="{anchor}"')
    if spacing is not None:
        attrs.append(f'letter-spacing="{spacing}"')
    if opacity is not None:
        attrs.append(f'opacity="{opacity}"')
    return f'  <text {" ".join(attrs)}>{_esc(content)}</text>'


def _eyebrow(x, y, content, *, fill, size=10, anchor="start"):
    """Uppercase mono label with wide tracking: the brand's section eyebrow."""
    return _text(x, y, content, fill=fill, size=size, family=MONO, weight=600,
                 anchor=anchor, spacing="0.15em", upper=True)


def _card(x, y, w, h, *, fill, stroke, width=1, radius=12, dash=None):
    extra = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'  <rect x="{_n(x)}" y="{_n(y)}" width="{_n(w)}" height="{_n(h)}" rx="{_n(radius)}" '
            f'{_paint("fill", fill)} {_paint("stroke", stroke)} stroke-width="{_n(width)}"{extra}/>')


def _opacity_card(x, y, w, h, *, fill, fill_opacity, stroke, width=1, radius=12, extra=""):
    """A card whose translucent fill survives SVG renderers that reject rgba()."""
    return (f'  <rect x="{_n(x)}" y="{_n(y)}" width="{_n(w)}" height="{_n(h)}" rx="{_n(radius)}" '
            f'fill="{fill}" fill-opacity="{fill_opacity}" {_paint("stroke", stroke)} '
            f'stroke-width="{_n(width)}"{extra}/>')


def _line(x1, y1, x2, y2, color, *, width=2, dash=None, cap="butt", opacity=None):
    extra = f' stroke-dasharray="{dash}"' if dash else ""
    if opacity is not None:
        extra += f' opacity="{opacity}"'
    return (f'  <path d="M {_n(x1)} {_n(y1)} L {_n(x2)} {_n(y2)}" {_paint("stroke", color)} '
            f'stroke-width="{_n(width)}" stroke-linecap="{cap}" fill="none"{extra}/>')


def _svg_open(w, h, label, p):
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{_n(w)}" height="{_n(h)}" viewBox="0 0 {w} {h}" '
           f'role="img" aria-label="{_esc(label)}">']
    if p["canvas"] != "none":
        out.append(f'  <rect width="{_n(w)}" height="{_n(h)}" fill="{p["canvas"]}"/>')
    return out



def _ruler(x1, x2, y, color, *, divisions=50, major_every=5, tick=8, big=16, width=2, cap_h=18, labels=(),
           bold=False):
    """The yardstick: baseline, end caps, evenly divided ticks.

    A label placed at fraction f sits exactly on a tick when f * divisions is
    whole, and on a major tick when it is also a multiple of major_every.
    bold adds a glow under the baseline and halos on the pins; hero use only.
    """
    pitch = (x2 - x1) / divisions
    out = []
    if bold:
        out.append(_line(x1, y, x2, y, color, width=18, cap="round", opacity=0.10))
        out.append(_line(x1, y, x2, y, color, width=8, cap="round", opacity=0.18))
    out += [_line(x1, y, x2, y, color, width=width, cap="round"),
            _line(x1, y - cap_h, x1, y, color, width=width, cap="round"),
            _line(x2, y - cap_h, x2, y, color, width=width, cap="round")]
    for i in range(1, divisions):
        tx = x1 + i * pitch
        major = i % major_every == 0
        out.append(_line(tx, y - (big if major else tick), tx, y, color,
                         width=2 if major else 1, opacity=0.95 if major else 0.45))
    for fraction, label, label_color in labels:
        lx = x1 + (x2 - x1) * fraction
        out.append(_line(lx, y - big - 10, lx, y, label_color, width=3, cap="round"))
        if bold:
            out.append(f'  <circle cx="{_n(lx)}" cy="{_n(y - big - 16)}" r="11" fill="{label_color}" opacity="0.18"/>')
        out.append(f'  <circle cx="{_n(lx)}" cy="{_n(y - big - 16)}" r="5" fill="{label_color}"/>')
        out.append(_text(lx, y + 26, label, fill=label_color, size=13, family=MONO, weight=700, anchor="middle"))
    return out


# --------------------------------------------------------------------------
# Logomark. A combination square: the yardstick, reduced to a bench tool.
# --------------------------------------------------------------------------





def _ruler_glyph(a, bg):
    """The mark: a ruler at 45 degrees and a needle reading one tick on it.

    The ruler says measure. The needle, a small solid pointer touching one tick
    from below, says a reading was taken: one case landing on one mark. No
    ring, no stem, nothing that reads as a pin. Monochrome so it holds at 16px.
    """
    out = [f'  <g transform="rotate(-45 32 32)">',
           f'    <rect x="7" y="22" width="50" height="15" rx="3" fill="{bg}" stroke="{a}" stroke-width="2.6"/>']
    for i, x in enumerate(range(13, 52, 6)):
        h = 7 if i % 2 == 0 else 4
        out.append(f'    <path d="M {x} 37 L {x} {37 - h}" stroke="{a}" stroke-width="2" stroke-linecap="round"/>')
    # The needle: a solid triangle under the fourth tick, point touching the edge.
    out.append(f'    <path d="M 31 39 L 25.5 48 L 36.5 48 Z" fill="{a}"/>')
    out.append("  </g>")
    return out

# Type metrics for the monospace wordmark. Every glyph advances the same width,
# so the wordmark's extent is exact. TRACKING is subtracted because the text is
# set with negative letter-spacing.
MONO_ADVANCE = 0.6
TRACKING = 0.02
ASCENDER = 0.75
DESCENDER = 0.21

WORDMARK_LEAD = "Agent Egress "
WORDMARK_ACCENT = "Bench"


def lockup() -> str:
    """Mark and wordmark on one line, for the README header.

    Sized from the wordmark rather than a typed canvas width. A canvas wider
    than its artwork looks off-centre the moment the image is centred on a
    page, because the empty margin is centred along with the ink.
    """
    a = BRAND["accent"]
    margin, mark_size, gap, size = 20, 96, 26, 44
    text_x = margin + mark_size + gap
    word = WORDMARK_LEAD + WORDMARK_ACCENT
    text_w = round(len(word) * size * (MONO_ADVANCE - TRACKING), 2)
    w = round(text_x + text_w + margin, 2)
    h = margin * 2 + mark_size - 24

    # Centre the wordmark's visual band on the mark's centre. Aligning the
    # baseline instead would hang the word low, because a baseline sits under
    # the letters rather than through them.
    mark_centre = 10 + mark_size / 2
    baseline = round(mark_centre - (ASCENDER + DESCENDER) * size / 2 + ASCENDER * size, 2)
    scale = round(mark_size / 64, 6)

    # No tile behind the mark. A rounded tile gives a mark a defined edge where
    # it lands on a background nobody controls, which is an avatar or a
    # favicon. On a page the tile boxes the mark in beside a bare wordmark, and
    # the sibling repository's lockup carries no tile either.
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
           f'viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Agent Egress Bench logo lockup">',
           f'  <g transform="translate({margin} 10) scale({scale})">']
    out += [f"  {line}" for line in _ruler_glyph(a, BRAND["bg_elevated"])]
    out.append("  </g>")
    # Two-tone: the accent lands on the word that distinguishes this repository
    # from its siblings, matching pipelock-rules next door.
    out.append(f'  <text x="{text_x}" y="{baseline}" font-family="{MONO}" font-size="{size}" '
               f'font-weight="700" letter-spacing="-{TRACKING}em" xml:space="preserve">'
               f'<tspan fill="{BRAND["text"]}">{WORDMARK_LEAD}</tspan>'
               f'<tspan fill="{a}">{WORDMARK_ACCENT}</tspan></text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def logo() -> str:
    a = BRAND["accent"]
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 64 64" role="img" '
           'aria-label="Agent Egress Bench logomark: a combination square set at forty-five degrees.">',
           "  <defs>",
           '    <radialGradient id="glow" cx="50%" cy="55%" r="55%">',
           f'      <stop offset="0%" stop-color="{a}" stop-opacity="0.26"/>',
           f'      <stop offset="100%" stop-color="{a}" stop-opacity="0"/>',
           "    </radialGradient>",
           "  </defs>",
           f'  <rect width="64" height="64" rx="12" fill="{BRAND["bg"]}"/>',
           '  <rect width="64" height="64" rx="12" fill="url(#glow)"/>']
    out += _ruler_glyph(a, BRAND["bg_elevated"])
    out.append("</svg>")
    return "\n".join(out) + "\n"

# --------------------------------------------------------------------------
# Hero and social preview. Brand hero treatment: radials plus particle network.
# --------------------------------------------------------------------------


def _particles(count, w, h, seed=7):
    """Deterministic particle positions. No randomness, so the file is stable."""
    state = seed
    points = []
    for _ in range(count):
        state = (state * 1103515245 + 12345) % (2 ** 31)
        x = 80 + (state % 1000) / 1000 * (w - 160)
        state = (state * 1103515245 + 12345) % (2 ** 31)
        y = 40 + (state % 1000) / 1000 * (h - 80)
        points.append((round(x, 1), round(y, 1)))
    return points


def social_preview() -> str:
    """The repository hero and GitHub social preview card.

    Dark in both themes: it is also the Open Graph card on link unfurls, where
    the reader's GitHub theme does not apply. It carries no count, because a
    number in a hand-exported raster rots silently.

    Vertical rhythm, and it is deliberate: 96 top margin, identity block to 262,
    gap, ruler at 412, verdict labels to 446, gap, footer at 566. The two gaps
    are matched on purpose. An earlier version left a single 190px void between
    the tagline and the ruler -- 30% of the canvas -- with a 126 top margin
    against a 70 bottom. Layouts that moved the ruler or the tagline were built
    and rendered, and each one simply relocated the void; growing the elements
    is what absorbs it.

    The footer is the family line, left, one place: license then maintainer.
    An earlier card split those across left, right, and a second row, so this
    card and its sibling did not read as one house.
    """
    a, w, h = BRAND["accent"], 1280, 640
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_n(w)}" height="{_n(h)}" viewBox="0 0 {w} {h}" '
        'role="img" aria-label="Agent Egress Bench, the open yardstick for agent egress control. '
        f'{CARD_FOOTER}.">',
        "  <defs>",
        '    <radialGradient id="teal" cx="30%" cy="20%" r="55%">',
        f'      <stop offset="0%" stop-color="{a}" stop-opacity="0.22"/>',
        f'      <stop offset="100%" stop-color="{a}" stop-opacity="0"/>',
        "    </radialGradient>",
        '    <radialGradient id="purple" cx="72%" cy="82%" r="55%">',
        f'      <stop offset="0%" stop-color="{BRAND["purple"]}" stop-opacity="0.30"/>',
        f'      <stop offset="100%" stop-color="{BRAND["purple"]}" stop-opacity="0"/>',
        "    </radialGradient>",
        '    <radialGradient id="mark" cx="50%" cy="62%" r="55%">',
        f'      <stop offset="0%" stop-color="{a}" stop-opacity="0.28"/>',
        f'      <stop offset="100%" stop-color="{a}" stop-opacity="0"/>',
        "    </radialGradient>",
        "  </defs>",
        f'  <rect width="{_n(w)}" height="{_n(h)}" fill="{BRAND["bg"]}"/>',
        f'  <rect width="{_n(w)}" height="{_n(h)}" fill="url(#teal)"/>',
        f'  <rect width="{_n(w)}" height="{_n(h)}" fill="url(#purple)"/>',
    ]

    points = _particles(44, w, h)
    net = [f'  <g stroke="{a}" stroke-width="1">']
    for i, (x1, y1) in enumerate(points):
        for x2, y2 in points[i + 1:]:
            d = math.hypot(x2 - x1, y2 - y1)
            if d < 150:
                net.append(f'    <line x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}" '
                           f'opacity="{round(0.16 * (1 - d / 150), 3)}"/>')
    net.append("  </g>")
    net.append(f'  <g fill="{a}" opacity="0.5">')
    net += [f'    <circle cx="{_n(x)}" cy="{_n(y)}" r="1.6"/>' for x, y in points]
    net.append("  </g>")
    out += net

    # Identity block: mark, then wordmark, centred on the card as a unit.
    #
    # Both used to start at a fixed x=96, which left the block sitting left of
    # centre while the sibling card centred its own. The wordmark is monospace,
    # so its width is arithmetic rather than an estimate, and the block can be
    # placed from the centre outward.
    #
    # No tile behind the mark. A rounded tile gives a mark an edge where it
    # lands on a background nobody controls, which is an avatar or a favicon.
    # Here the background is the card's own, so the tile only boxed the mark in.
    mark_scale = 3.2
    mark_w = 64 * mark_scale
    mark_gap = 30.4
    # 72, not 86: the sibling card's name is shorter, so the same point size
    # would make this line the loudest thing on a card whose hero is the ruler.
    # 72 is the step that matches optical weight without crowding the ticks.
    title_size = 72
    word = "Agent Egress Bench"
    title_w = len(word) * title_size * 0.58
    block_x = round((1280 - (mark_w + mark_gap + title_w)) / 2, 2)
    title_x = round(block_x + mark_w + mark_gap, 2)

    out.append(f'  <g transform="translate({_n(block_x)} 104) scale({mark_scale})">')
    out += ["  " + line for line in _ruler_glyph(a, BRAND["bg_elevated"])]
    out.append("  </g>")

    # The wordmark is ONE line, in ONE text element, coloured with tspans.
    #
    # It used to be two lines with "Bench" centred under "Agent Egress" using a
    # width computed as 12 glyphs times 0.6em. That estimate does not match the
    # font's real advance, so the second line sat visibly off-centre while the
    # arithmetic looked correct. Letting the text engine lay out one run removes
    # the estimate rather than correcting it, and there is nothing left to
    # centre by hand.
    # xml:space="preserve" is load-bearing: without it the renderer collapses the
    # trailing space inside the first tspan and the wordmark reads "EgressBench".
    out.append(f'  <text x="{_n(title_x)}" y="206" font-family="{MONO}" '
               f'font-size="{title_size}" font-weight="700" letter-spacing="-0.02em" '
               f'xml:space="preserve">'
               f'<tspan fill="{BRAND["text"]}">Agent Egress </tspan>'
               f'<tspan fill="{a}">Bench</tspan></text>')
    out.append(_text(title_x + 2, 254, "OPEN YARDSTICK FOR AGENT EGRESS CONTROL", fill=BRAND["muted"], size=18,
                     family=SANS, spacing="0.20em"))

    out += _ruler(96, 1184, 412, a, divisions=50, major_every=5, tick=10, big=22, width=4, cap_h=26, bold=True, labels=(
        (0.2, "allow", a),
        (0.4, "block", BRAND["danger"]),
        (0.6, "unreachable", BRAND["warn"]),
        (0.8, "error", BRAND["muted"]),
    ))

    out.append(_text(CARD_FOOTER_X, CARD_FOOTER_Y, CARD_FOOTER, fill=BRAND["dim"],
                     size=CARD_FOOTER_SIZE, family=MONO, spacing="0.12em"))
    out.append("</svg>")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Stats strip: the brand's stats component, with live corpus numbers.
# --------------------------------------------------------------------------

ASSURANCE_LABELS = (
    ("self-run", ("Vendor, customer, or maintainer", "ran the public method against", "their own target.")),
    ("artifact-validated", ("Rows, manifest, digests, and", "declared bindings reconcile", "under the shipped validator.")),
    ("independently-executed", ("A separate operator controlled", "the execution host and", "retained the artifacts.")),
    ("transparency-registered", ("Start commitment published before", "the run; bundle root appended to", "a log neither party operates.")),
    ("challenge-verified", ("Predeclared holdout cases outside", "the public corpus, under a", "published selection rule.")),
)


def stats_strip(p) -> str:
    items = (
        (str(live_case_total()), "cases"),
        (str(len(live_categories())), "categories"),
        (str(len(live_transports())), "transports"),
        (str(len(ASSURANCE_LABELS)), "assurance labels"),
    )
    w, h = 1200, 110
    out = _svg_open(w, h, "Corpus stats: " + ", ".join(f"{v} {k}" for v, k in items) + ".", p)
    cell = w / len(items)
    for index, (value, label) in enumerate(items):
        cx = cell * index + cell / 2
        out.append(_text(cx, 58, value, fill=p["accent_text"], size=34, family=MONO, weight=700, anchor="middle"))
        out.append(_eyebrow(cx, 86, label, fill=p["dim"], size=11, anchor="middle"))
        if index:
            out.append(_line(cell * index, 24, cell * index, 92, p["border"], width=1))
    out.append("</svg>")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Diagram: the layer under test.
# --------------------------------------------------------------------------


def _node(x, y, w, h, eyebrow, title, lines, p, *, tone=None, title_size=20, line_size=13):
    stroke = p["accent_border"] if tone == "accent" else (p[tone] if tone else p["border"])
    fill = p["accent_soft"] if tone == "accent" else (p[f"{tone}_soft"] if tone else p["card"])
    eyebrow_fill = p["accent_text"] if tone == "accent" else (p[tone] if tone else p["dim"])
    out = [_card(x, y, w, h, fill=fill, stroke=stroke, width=1.5 if tone else 1)]
    cx = x + w / 2
    out.append(_eyebrow(cx, y + 26, eyebrow, fill=eyebrow_fill, anchor="middle"))
    out.append(_text(cx, y + 56, title, fill=p["text"], size=title_size, family=MONO, weight=700, anchor="middle"))
    for i, line in enumerate(lines):
        out.append(_text(cx, y + 82 + i * 20, line, fill=p["muted"], size=line_size, anchor="middle"))
    return out


def _chevron(x, y, color, size=7):
    return f'  <path d="M {x - size} {y - size} L {x} {y} L {x - size} {y + size}" stroke="{color}" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'




def _pill(x, y, w, label, p, *, tone="accent", filled=False, role="carrier"):
    """A request in flight, drawn as a mono pill."""
    stroke = p["accent_border"] if tone == "accent" else p[tone]
    fill = p["accent_soft"] if tone == "accent" else p[f"{tone}_soft"]
    text = p["accent_text"] if tone == "accent" else p[tone]
    if filled:
        fill = p["terminal"]
    card = _card(x, y - 14, w, 28, fill=fill, stroke=stroke, width=1, radius=14)
    if role:
        card = card.replace("/>", f' data-role="{role}" data-label="{_esc(label)}"/>')
    return [card,
            _text(x + w / 2, y + 4, label, fill=text, size=11.5, family=MONO, weight=600, anchor="middle")]


def _cross(x, y, color, r=4):
    return (f'  <path d="M {x - r} {y - r} L {x + r} {y + r} M {x + r} {y - r} L {x - r} {y + r}" '
            f'stroke="{color}" stroke-width="2" stroke-linecap="round"/>')



SHOWCASE_CASE = REPO_ROOT / "cases" / "url" / "url-dlp-aws-key-001.json"


def showcase_case() -> dict:
    """The real case the first illustration walks through, read from the corpus."""
    try:
        data = json.loads(SHOWCASE_CASE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"render_diagrams: FAIL - cannot read {SHOWCASE_CASE.name}: {exc}") from exc
    for field in ("id", "transport", "expected_verdict", "payload"):
        if field not in data:
            raise SystemExit(f"render_diagrams: FAIL - {SHOWCASE_CASE.name} has no {field}")
    return data


def _elide_credential(query: str) -> str:
    """Shorten a credential-shaped query value so the asset carries no key.

    The scene draws a real case, and that case's payload is an AWS example key.
    A committed SVG holding the full token trips this repository's own secret
    scan, correctly: the fix is to stop carrying the token, not to exclude the
    directory from scanning. Enough of the value survives to read as a key.
    """
    name, sep, value = query.partition("=")
    if not sep or len(value) <= 12:
        return query
    return f"{name}={value[:4]}\u2026{value[-7:]}"


def _elide_url(url: str) -> str:
    """The full URL with any credential-shaped query value shortened."""
    head, sep, query = url.partition("?")
    return f"{head}?{_elide_credential(query)}" if sep else url


def _verdict_pill(x, y, label, p, tone, width=None):
    """A verdict tag. A fixed width makes a column of pills line up."""
    color = p["accent_text"] if tone == "accent" else p[tone]
    fill = p["accent_soft"] if tone == "accent" else p[f"{tone}_soft"]
    w = width if width is not None else len(label) * 8 + 22
    return [_card(x, y - 12, w, 24, fill=fill, stroke=color, width=1.2, radius=12),
            _text(x + w / 2, y + 4, label, fill=color, size=11.5, family=MONO, weight=700, anchor="middle")], w


def architecture(p) -> str:
    """One real case, end to end: what goes in, what sits in the middle, how it is scored."""
    case = showcase_case()
    payload = case["payload"]
    url = payload.get("url", "")
    method = payload.get("method", "GET")
    expected = case["expected_verdict"]
    exp_tone = "danger" if expected == "block" else "accent"
    other = "allow" if expected == "block" else "block"

    w, h = 1200, 412
    out = _svg_open(w, h, f"One case, end to end. Left, the case {case['id']} from the corpus: category "
                    f"{case.get('category', '')}, transport {case['transport']}, severity {case.get('severity', '')}, "
                    f"payload {method} {_elide_url(url)}, expected verdict {expected}. Middle, the egress "
                    "control under test, "
                    "sitting between the agent and the network. Right, the recorded outcome compared with the "
                    f"expected one: {expected} scores pass, {other} scores fail, and unreachable and error rows "
                    "are shown but never scored. Agent Egress Bench does this for every case.", p)

    # --- Left card: the case, as it exists in the repository.
    lx, ly, lw, lh = 40, 40, 372, 296
    out.append(_card(lx, ly, lw, lh, fill=p["card"], stroke=p["border"], width=1))
    out.append(_eyebrow(lx + 24, ly + 30, "one case from the corpus", fill=p["dim"]))
    out.append(_text(lx + 24, ly + 58, case["id"], fill=p["text"], size=16, family=MONO, weight=700))
    out.append(_line(lx + 24, ly + 74, lx + lw - 24, ly + 74, p["border"], width=1))
    y = ly + 102
    for key, value in (("category", case.get("category", "")), ("transport", case["transport"]),
                       ("severity", case.get("severity", ""))):
        out.append(_text(lx + 24, y, key, fill=p["dim"], size=12, family=MONO))
        out.append(_text(lx + lw - 24, y, value, fill=p["text"], size=13, family=MONO, anchor="end"))
        y += 26
    out.append(_text(lx + 24, y, "method", fill=p["dim"], size=12, family=MONO))
    out.append(_text(lx + lw - 24, y, method, fill=p["text"], size=13, family=MONO, anchor="end"))
    y += 26
    head, _, query = url.partition("?")
    query = _elide_credential(query)
    out.append(_text(lx + 24, y, "url", fill=p["dim"], size=12, family=MONO))
    out.append(_text(lx + lw - 24, y, head, fill=p["text"], size=13, family=MONO, anchor="end"))
    y += 22
    out.append(_text(lx + lw - 24, y, "?" + query, fill=p["danger"], size=13, family=MONO, weight=700, anchor="end"))
    y += 40
    out.append(_text(lx + 24, y + 4, "expected_verdict", fill=p["dim"], size=12, family=MONO))
    pw = len(expected) * 8 + 22
    pill, _ = _verdict_pill(lx + lw - 24 - pw, y, expected, p, exp_tone)
    out += pill

    # --- Middle: the control, with the agent and the network as faint context.
    cx, cy = 600, 178
    ax, nx = cx - 122, cx + 122   # glyph centers
    for x1, x2 in ((lx + lw, ax - 30), (ax + 30, cx - 60), (cx + 60, nx - 30), (nx + 30, 788)):
        out.append(_line(x1, cy, x2, cy, p["border_strong"], width=1.5, dash="4 5"))
    out.append(f'  <circle cx="{_n(cx)}" cy="{_n(cy)}" r="74" fill="{p["accent"]}" opacity="0.06"/>')
    out.append(f'  <circle cx="{_n(cx)}" cy="{_n(cy)}" r="58" fill="{p["terminal"]}" stroke="{p["accent"]}" stroke-width="2"/>')
    out.append(f'  <g transform="translate({cx - 29} {cy - 31}) scale(0.92)">')
    out += ["  " + line for line in _ruler_glyph(p["accent"], p["terminal"])]
    out.append("  </g>")
    out.append(_eyebrow(cx, 56, "egress control under test", fill=p["accent_text"], anchor="middle"))
    out.append(_text(cx, 78, "your proxy, egress firewall, agent gateway, or MCP wrapper",
                     fill=p["muted"], size=12, anchor="middle"))
    out.append(_text(cx, 284, "the runner sends the case in on the declared transport",
                     fill=p["muted"], size=11.5, anchor="middle"))
    out.append(_text(cx, 302, "and records whether delivery and a verdict were proved", fill=p["muted"], size=11.5,
                     anchor="middle"))
    out.append(_text(ax, cy + 6, ">_", fill=p["dim"], size=17, family=MONO, weight=700, anchor="middle"))
    out.append(_text(ax, cy + 30, "agent", fill=p["dim"], size=10, family=MONO, anchor="middle"))
    out.append(f'  <circle cx="{_n(nx)}" cy="{_n(cy)}" r="10" fill="none" stroke="{p["dim"]}" stroke-width="1.3"/>')
    out.append(f'  <ellipse cx="{_n(nx)}" cy="{_n(cy)}" rx="4.5" ry="10" fill="none" stroke="{p["dim"]}" stroke-width="1.1"/>')
    out.append(_line(nx - 10, cy, nx + 10, cy, p["dim"], width=1.1))
    out.append(_text(nx, cy + 30, "network", fill=p["dim"], size=10, family=MONO, anchor="middle"))

    # --- Right card: what came out, scored against what was expected.
    rx, ry, rw, rh = 788, 40, 372, 296
    out.append(_card(rx, ry, rw, rh, fill=p["card"], stroke=p["border"], width=1))
    out.append(_eyebrow(rx + 24, ry + 30, "scored against the expected verdict", fill=p["dim"]))
    out.append(_text(rx + 24, ry + 58, "recorded outcome", fill=p["text"], size=16, family=MONO, weight=700))
    out.append(_line(rx + 24, ry + 74, rx + rw - 24, ry + 74, p["border"], width=1))
    rows = (
        (expected, exp_tone, "pass", "accent", "the control did what the case expects"),
        (other, "accent" if other == "allow" else "danger", "fail", "danger",
         "the secret reached the network" if expected == "block" else "benign traffic was blocked"),
        ("unreachable / error", "warn", "not scored", "warn", "missing route, delivery, or verdict: never counted"),
    )
    # A table, not a list: both columns are sized to their widest label, so
    # every row has one geometry and no row trails off into blank space.
    obs_w = max(len(r[0]) for r in rows) * 8 + 22
    score_w = max(len(r[2]) for r in rows) * 8 + 22
    pad, band_x, band_w = 0, rx + 24, rw - 48
    score_x = band_x + band_w - pad - score_w
    out.append(_eyebrow(band_x + pad, ry + 96, "recorded", fill=p["dim"], size=9))
    out.append(_eyebrow(score_x + score_w, ry + 96, "score", fill=p["dim"], size=9, anchor="end"))
    for i, (observed, tone, score, stone, note) in enumerate(rows):
        band_y = ry + 110 + i * 62
        if i:
            out.append(_line(band_x, band_y - 4, band_x + band_w, band_y - 4, p["border"], width=1))
        y = band_y + 22
        out += _verdict_pill(band_x + pad, y, observed, p, tone, width=obs_w)[0]
        out += _verdict_pill(score_x, y, score, p, stone, width=score_w)[0]
        out.append(_text(band_x + pad, band_y + 46, note, fill=p["muted"], size=11.5))

    out.append(_text(600, 386, "Every case in the corpus goes through this, one at a time, on its own transport. "
                     "The benchmark scores the control, never the agent.", fill=p["muted"], size=13, anchor="middle"))
    out.append("</svg>")
    return "\n".join(out) + "\n"

# --------------------------------------------------------------------------
# Diagram: how a result is made. Stages marked along the yardstick, no boxes.
# --------------------------------------------------------------------------

SYSTEM_STAGES = (
    ("corpus", "Cases", "benchmark", ("wire input, expected verdict", "immutable IDs, frozen semantics")),
    ("runner", "Fixtures + adapter", "benchmark", ("runner-owned fixtures", "delivery evidence is recorded")),
    ("target", "Product under test", "vendor", ("pinned version, config digest", "verdict observed on the wire")),
    ("evidence", "Rows + bundle", "run", ("result_state on every row", "two metrics, kept apart")),
    ("verify", "Offline validation", "anyone", ("rows, manifest, digests", "no network, no call home")),
    ("publish", "Result + label", "publisher", ("hosted by whoever ran it", "a label, never a mark")),
)
OWNER_TONES = {"benchmark": "accent", "vendor": "warn", "run": "info", "anyone": "text", "publisher": "info"}


def system(p) -> str:
    w, h = 1200, 424
    out = _svg_open(w, h, "How a result is produced, as marks along a ruler: cases, the runner with its own "
                    "fixtures and adapter, the product under test, the evidence rows and bundle, offline "
                    "validation, and publication. Each mark names who owns it.", p)
    y = 196
    x1, x2 = 60, 1140
    out += _ruler(x1, x2, y, p["accent"], divisions=40, major_every=4, tick=6, big=12, width=2, cap_h=16)
    step = (x2 - x1) / (len(SYSTEM_STAGES) - 1)
    for i, (eyebrow, title, owner, lines) in enumerate(SYSTEM_STAGES):
        cx = x1 + i * step
        tone = OWNER_TONES[owner]
        color = p["accent_text"] if tone == "accent" else (p["text"] if tone == "text" else p[tone])
        out.append(f'  <circle cx="{_n(cx)}" cy="{_n(y)}" r="9" fill="{p["terminal"]}" stroke="{color}" stroke-width="2.5"/>')
        out.append(f'  <circle cx="{_n(cx)}" cy="{_n(y)}" r="3" fill="{color}"/>')
        anchor = "start" if i == 0 else ("end" if i == len(SYSTEM_STAGES) - 1 else "middle")
        tx = cx if anchor == "middle" else (cx - 9 if anchor == "start" else cx + 9)
        out.append(_eyebrow(tx, y - 70, eyebrow, fill=color, anchor=anchor))
        out.append(_text(tx, y - 44, title, fill=p["text"], size=15, family=MONO, weight=700, anchor=anchor))
        # Alternate stages drop their detail lines a row lower, so neighbours
        # never collide however many marks the ruler carries.
        drop = 0 if i % 2 == 0 else 44
        if drop:
            out.append(_line(cx, y + 14, cx, y + 36 + drop, p["border_strong"], width=1, dash="2 3"))
        for j, line in enumerate(lines):
            out.append(_text(tx, y + 48 + drop + j * 18, line, fill=p["muted"], size=12, anchor=anchor))

    ly = 340
    out.append(_eyebrow(60, ly, "who owns each mark", fill=p["dim"]))
    lx = 60
    for owner, note in (("benchmark", "this repository"), ("vendor", "product under test"),
                        ("run", "produced by the run"), ("anyone", "offline, any reader"),
                        ("publisher", "whoever ran it")):
        tone = OWNER_TONES[owner]
        color = p["accent_text"] if tone == "accent" else (p["text"] if tone == "text" else p[tone])
        out.append(f'  <circle cx="{_n(lx + 6)}" cy="{_n(ly + 24)}" r="5" fill="{color}"/>')
        out.append(_text(lx + 18, ly + 28, f"{owner}: {note}", fill=p["muted"], size=12, family=MONO))
        lx += 228
    out.append(_text(60, 404, "The benchmark supplies the ruler and the validator. It never touches the target, "
                     "never hosts a result, and never awards a mark.", fill=p["dim"], size=12.5))
    out.append("</svg>")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Diagram: result states as a flow. Cases enter wide; every gate peels off a
# slice that is never scored; the survivors split into pass and fail.
# --------------------------------------------------------------------------



def _band(x1, top1, bot1, x2, top2, bot2, fill, opacity=1.0, extra=""):
    """A horizontal band whose edges ease from one thickness to another."""
    m = (x1 + x2) / 2
    return (f'  <path d="M {x1} {top1} C {m} {top1}, {m} {top2}, {x2} {top2} L {x2} {bot2} '
            f'C {m} {bot2}, {m} {bot1}, {x1} {bot1} Z" fill="{fill}" opacity="{opacity}"{extra}/>')


def _ribbon(x, top, bot, bx, by, bw, fill, opacity=0.85):
    """A slice that leaves the band's underside and lands flat in a bucket of width bw.

    Vertical thickness at the band becomes horizontal width at the bucket, so the
    ribbon reads as the same cases turning downward rather than a drip.
    """
    return (f'  <path d="M {x} {top} '
            f'C {x + 70} {top}, {bx - bw / 2} {by - 110}, {bx - bw / 2} {by} '
            f'L {bx + bw / 2} {by} '
            f'C {bx + bw / 2} {by - 110}, {x + 70 + (bot - top)} {bot}, {x} {bot} Z" '
            f'fill="{fill}" opacity="{opacity}"/>')



def result_states(p) -> str:
    w, h = 1200, 430
    out = _svg_open(w, h, "Result states as a flow. Cases enter as one wide band. At the first gate, cases with "
                    "no exact adapter route leave as unreachable, outside the denominator. At the second, cases "
                    "without delivery proof leave as delivery_unavailable, an error. At the third, cases whose "
                    "verdict was not observed leave as verdict_unobservable, an error. The band that reaches the "
                    "end is scored: pass when the observed verdict matches the expected one, fail when it does "
                    "not.", p)
    out.append("  <defs>")
    for name, tone in (("rib-warn", "warn"), ("rib-danger", "danger")):
        out.append(f'    <linearGradient id="{name}" gradientUnits="userSpaceOnUse" x1="0" y1="130" x2="0" y2="330">')
        out.append(f'      <stop offset="0" stop-color="{p["accent"]}" stop-opacity="0"/>')
        out.append(f'      <stop offset="0.62" stop-color="{p["accent"]}" stop-opacity="0.35"/>')
        out.append(f'      <stop offset="1" stop-color="{p[tone]}" stop-opacity="0.85"/>')
        out.append("    </linearGradient>")
    out.append("  </defs>")

    left, right = 60, 1140
    top, thick, ease = 128, (118, 90, 62, 38), 40
    gates = ((320, "Exact adapter route?", "unreachable", "warn", "visible, outside the denominator"),
             (570, "Delivery proven?", "delivery_unavailable", "danger", "error, never a block"),
             (820, "Verdict observed?", "verdict_unobservable", "danger", "error, never a block"))
    fork_x, card_x, card_w, card_h = 1000, 1040, 100, 44
    bucket_y, bucket_h = 318, 46

    # Header strip: one edge with the band.
    out.append(_card(left, 24, right - left, 52, fill=p["card"], stroke=p["border"], width=1, radius=10))
    for i, (gx, question, _, tone, _) in enumerate(gates):
        out.append(f'  <circle cx="{_n(gx)}" cy="42" r="10" fill="{p["terminal"]}" stroke="{p["accent"]}" stroke-width="1.5"/>')
        out.append(_text(gx, 46, str(i + 1), fill=p["accent_text"], size=11, family=MONO, weight=700, anchor="middle"))
        out.append(_text(gx + 18, 46, question, fill=p["text"], size=13, weight=600))
        out.append(_text(gx + 18, 64, "no", fill=p[tone], size=11, family=MONO, weight=700))
        # A gate line from the strip down to the band's top edge, and no further.
        out.append(_line(gx, 76, gx, top - 6, p["border_strong"], width=1, dash="3 4"))
    out.append(f'  <circle cx="{_n(fork_x)}" cy="42" r="10" fill="{p["terminal"]}" stroke="{p["accent"]}" stroke-width="1.5"/>')
    out.append(_text(fork_x, 46, "4", fill=p["accent_text"], size=11, family=MONO, weight=700, anchor="middle"))
    out.append(_text(fork_x + 18, 46, "Scored", fill=p["text"], size=13, weight=600))
    out.append(_text(fork_x + 18, 64, "vs expected", fill=p["accent_text"], size=11, family=MONO, weight=700))
    out.append(_line(fork_x, 76, fork_x, top - 6, p["border_strong"], width=1, dash="3 4"))
    out.append(_eyebrow(left, top - 16, "every case in the corpus", fill=p["dim"]))

    # Ribbons first, so the band lies over their roots.
    for i, (gx, _, bucket, tone, note) in enumerate(gates):
        bw = thick[i] - thick[i + 1]
        bx = gx + 90
        out.append(_ribbon(gx - ease, top + thick[i + 1], top + thick[i], bx, bucket_y, bw, f"url(#rib-{tone})"))
        out.append(_card(bx - 96, bucket_y, 192, bucket_h, fill=p[f"{tone}_soft"], stroke=p[tone], width=1.2, radius=10))
        out.append(_text(bx, bucket_y + 19, bucket, fill=p[tone], size=12, family=MONO, weight=700, anchor="middle"))
        out.append(_text(bx, bucket_y + 36, note, fill=p["muted"], size=10.5, anchor="middle"))

    # The band: one path, so there are no seams. Flat top, eased steps on the bottom.
    d = [f"M {left} {top} L {fork_x} {top}"]
    d.append(f"L {fork_x} {top + thick[3]}")
    x_after = fork_x
    for i in reversed(range(len(gates))):
        gx = gates[i][0]
        # walk back along the bottom edge: flat at thick[i+1], then ease up to thick[i]
        d.append(f"L {gx + ease} {top + thick[i + 1]}")
        d.append(f"C {gx} {top + thick[i + 1]}, {gx} {top + thick[i]}, {gx - ease} {top + thick[i]}")
    d.append(f"L {left} {top + thick[0]} Z")
    out.append(f'  <path d="{" ".join(d)}" fill="{p["accent"]}" opacity="0.30"/>')
    out.append(_line(left, top, fork_x, top, p["accent"], width=1.5, opacity=0.8))

    # The fork: two full-thickness ribbons that end exactly at the card edge.
    half = thick[3] / 2
    pass_y, fail_y = top - 20, top + thick[3] + 36
    out.append(_band(fork_x, top, top + half, card_x, pass_y, pass_y + half, p["accent"], 0.65))
    out.append(_band(fork_x, top + half, top + thick[3], card_x, fail_y - half, fail_y, p["danger"], 0.65))
    for y0, label, tone in ((pass_y + half / 2, "pass", "accent"), (fail_y - half / 2, "fail", "danger")):
        color = p["accent_text"] if tone == "accent" else p[tone]
        out.append(_card(card_x, y0 - card_h / 2, card_w, card_h, fill=p[f"{tone}_soft"], stroke=color, width=1.2, radius=10))
        out.append(_text(card_x + card_w / 2, y0 + 5, label, fill=color, size=13, family=MONO, weight=700, anchor="middle"))

    out.append(_text(left, 404, "Containment and false-positive rate count only the band that reaches gate 4. "
                     "A tool cannot shrink the denominator by declaring a capability away, and an error is never a pass.",
                     fill=p["dim"], size=12))
    out.append("</svg>")
    return "\n".join(out) + "\n"

# --------------------------------------------------------------------------
# Diagram: the assurance ladder.
# --------------------------------------------------------------------------


def assurance(p) -> str:
    out = _svg_open(1200, 330, "The five assurance labels a result may carry, from self-run through "
                    "artifact-validated, independently-executed, and transparency-registered to "
                    "challenge-verified. Labels stack. A run carries none by default, and none of them is a "
                    "mark of approval.", p)
    step_w, rise, base_y, floor, x = 220, 30, 186, 270, 40
    for index, (label, lines) in enumerate(ASSURANCE_LABELS):
        y = base_y - index * rise
        strong = index >= 2
        out.append(_card(x, y, step_w, floor - y, fill=p["accent_soft"] if strong else p["card"],
                         stroke=p["accent_border"] if strong else p["border"], width=1))
        out.append(_text(x + 14, y + 22, f"{index + 1}", fill=p["accent_text"], size=11, family=MONO, weight=700))
        out.append(_text(x + 32, y + 22, label, fill=p["text"], size=12.5, family=MONO, weight=700))
        for j, line in enumerate(lines):
            out.append(_text(x + 14, y + 44 + j * 16, line, fill=p["muted"], size=11))
        x += step_w + 10
    out.append(_text(40, 300, "A run carries no label by default and may carry several. Each answers one "
                     "question and leaves the others open.", fill=p["text"], size=13, weight=600))
    out.append(_text(40, 320, "None of them means approved, audited, or safe. The maintainer awards no mark to "
                     "anyone's result, including its own.", fill=p["dim"], size=12.5))
    out.append("</svg>")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Diagram: corpus composition. One row per surface, bars segmented by category.
# Rows and segments are data, so the drawing lays out the same at 18 or 40.
# --------------------------------------------------------------------------

# Every live case category is placed in exactly one group. `--check` fails when
# the corpus grows a category this map does not mention.
COVERAGE_GROUPS = (
    ("outbound http", "What the agent sends", (
        ("url", "URL"), ("request_body", "body"), ("headers", "headers"), ("hostname_exfiltration", "DNS labels"))),
    ("inbound content", "What comes back", (
        ("response_fetch", "fetched pages"), ("response_mitm", "intercepted TLS"))),
    ("mcp", "Tools and their supply chain", (
        ("mcp_input", "arguments"), ("mcp_tool", "definitions"), ("mcp_chain", "chains"), ("mcp_drift", "drift"))),
    ("agent to agent", "Peer agent traffic", (
        ("a2a_message", "messages"), ("a2a_agent_card", "agent cards"))),
    ("streaming", "Long-lived connections", (("websocket_dlp", "WebSocket frames"),)),
    ("evasion", "Getting past the scanner", (
        ("ssrf_bypass", "SSRF"), ("encoding_evasion", "encoding"), ("shell_obfuscation", "shell"))),
    ("sensitive data", "High-value payloads", (("crypto_financial", "wallets, cards, IBANs"),)),
    ("control", "Must not be blocked", (("false_positive", "benign traffic"),)),
)
CONTROL_GROUP = "control"




def _squarify(items, x, y, w, h):
    """Squarified treemap layout. items: [(key, value)] sorted descending.

    Returns [(key, value, x, y, w, h)]. Pure function so the test can assert
    that every rect stays inside the region and areas sum to the region.
    """
    items = list(items)
    if any(value < 0 for _, value in items):
        raise ValueError("treemap counts cannot be negative")
    total = sum(v for _, v in items)
    if total == 0:
        # A zero-count category has no drawable area. Returning explicit
        # zero-area tiles keeps the layout total, finite, and honest instead
        # of inventing a visual proportion or dividing by zero.
        return [(key, value, x, y, 0, 0) for key, value in items]
    scale = (w * h) / total
    out = []
    while items:
        vertical = w >= h  # lay a column when wide, a row when tall
        side = h if vertical else w
        row, best = [], None
        for key, value in items:
            trial = row + [(key, value)]
            area = sum(v for _, v in trial) * scale
            thick = area / side
            worst = max(max(v * scale / thick / thick if thick else 1, thick * thick / (v * scale)) for _, v in trial) \
                if all(v > 0 for _, v in trial) else float("inf")
            if best is None or worst <= best:
                row, best = trial, worst
            else:
                break
        area = sum(v for _, v in row) * scale
        thick = area / side
        offset = 0
        for key, value in row:
            length = value * scale / thick if thick else 0
            if vertical:
                out.append((key, value, x, y + offset, thick, length))
            else:
                out.append((key, value, x + offset, y, length, thick))
            offset += length
        if vertical:
            x, w = x + thick, w - thick
        else:
            y, h = y + thick, h - thick
        items = items[len(row):]
    return out


def _treemap_rows(items, x, y, w, h, row_count=2):
    """Lay proportional group tiles in broad rows so narrow groups keep labels.

    Each row gets height in proportion to its sum, then each item gets width in
    proportion to its value. The visible area of every returned tile therefore
    remains proportional to its count.
    """
    items = list(items)
    if not items:
        return []
    if any(value < 0 for _, value in items):
        raise ValueError("treemap counts cannot be negative")
    total = sum(value for _, value in items)
    if total == 0:
        return [(key, value, x, y, 0, 0) for key, value in items]
    row_count = max(1, min(row_count, len(items)))
    rows, cursor = [], 0
    remaining_total = total
    for row_index in range(row_count):
        remaining_rows = row_count - row_index
        if remaining_rows == 1:
            rows.append(items[cursor:])
            break
        target = remaining_total / remaining_rows
        row, row_total = [], 0
        while cursor < len(items) - (remaining_rows - 1):
            candidate = items[cursor]
            if row and abs(row_total - target) <= abs(row_total + candidate[1] - target):
                break
            row.append(candidate)
            row_total += candidate[1]
            cursor += 1
        rows.append(row)
        remaining_total -= row_total

    out, cy = [], y
    for row_index, row in enumerate(rows):
        row_total = sum(value for _, value in row)
        rh = h - (cy - y) if row_index == len(rows) - 1 else h * row_total / total
        cx = x
        for item_index, (key, value) in enumerate(row):
            cw = w - (cx - x) if item_index == len(row) - 1 else w * value / row_total
            out.append((key, value, cx, cy, cw, rh))
            cx += cw
        cy += rh
    return out


def _wrap_label(label, max_chars):
    """Wrap a short tile label without splitting identifiers or words."""
    words, lines, current = label.split(), [], ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if current and len(candidate) > max_chars:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [label]


def coverage(p) -> str:
    """The corpus as a treemap: area is case count, tiles are grouped by surface."""
    counts = live_category_counts()
    w, h, gap = 1200, 620, 6
    out = _svg_open(w, h, "The corpus as a treemap where area is case count. Groups by attacked surface: " +
                    ", ".join(f"{title} {sum(counts.get(k, 0) for k, _ in e)} cases" for _, title, e in COVERAGE_GROUPS)
                    + ". The benign control group is outlined because it is scored on the false-positive axis.", p)
    groups = sorted(((kicker, sum(counts.get(k, 0) for k, _ in entries)) for kicker, _, entries in COVERAGE_GROUPS),
                    key=lambda kv: -kv[1])
    meta = {kicker: (title, entries) for kicker, title, entries in COVERAGE_GROUPS}
    for kicker, total, gx, gy, gw, gh in _treemap_rows(groups, 20, 20, w - 40, h - 88, row_count=2):
        control = kicker == CONTROL_GROUP
        title, entries = meta[kicker]
        ix, iy, iw, ih = gx + gap / 2, gy + gap / 2, gw - gap, gh - gap
        group_fill, group_opacity = (p["text"], 0.02) if control else (p["accent"], 0.045)
        group_stroke = p["border_strong"] if control else p["accent_border"]
        out.append(_opacity_card(ix, iy, iw, ih, fill=group_fill, fill_opacity=group_opacity,
                                 stroke=group_stroke, width=1.3, radius=12,
                                 extra=f' data-role="coverage-group" data-group="{_esc(kicker)}" data-count="{total}"'))
        # Category tiles inside the group, leaving a header band for the label.
        header = 58
        cats = sorted(((k, counts.get(k, 0)) for k, _ in entries), key=lambda kv: -kv[1])
        labels = {k: label for k, label in entries}
        for key, n, cx, cy, cw, ch in _squarify(cats, ix + 7, iy + header, iw - 14, ih - header - 7):
            tx, ty, tw, th = cx + 3, cy + 3, max(cw - 6, 0), max(ch - 6, 0)
            if control:
                fill, fill_opacity, stroke = p["text"], 0.025, p["border_strong"]
            else:
                fill, fill_opacity, stroke = p["accent"], 0.16, p["accent_border"]
            out.append(_opacity_card(tx, ty, tw, th, fill=fill, fill_opacity=fill_opacity,
                                     stroke=stroke, width=1, radius=8,
                                     extra=f' data-role="coverage-category" data-category="{key}" data-count="{n}"'))
            max_chars = max(7, int((tw - 20) / 7.2))
            lines = _wrap_label(labels[key], max_chars)
            line_h = 15
            block_h = len(lines) * line_h + 18
            label_y = ty + max(18, (th - block_h) / 2 + 13)
            for line_index, line in enumerate(lines):
                out.append(_text(tx + 10, label_y + line_index * line_h, line, fill=p["text"], size=11.5,
                                 family=MONO, weight=650))
            out.append(_text(tx + 10, min(ty + th - 10, label_y + len(lines) * line_h + 4), f"{n} cases",
                             fill=p["muted"], size=10.5, family=MONO, weight=600))
        header_color = p["muted"] if control else p["accent_text"]
        out.append(_eyebrow(ix + 12, iy + 20, kicker, fill=header_color, size=9))
        if iw >= 178:
            out.append(_text(ix + 12, iy + 42, title, fill=p["text"], size=12, family=MONO, weight=700))
            out.append(_text(ix + iw - 12, iy + 42, str(total), fill=header_color, size=12, family=MONO,
                             weight=700, anchor="end"))
        else:
            out.append(_text(ix + 12, iy + 42, f"{total} cases", fill=p["text"], size=11.5, family=MONO, weight=700))
    fy = h - 24
    out.append(_text(20, fy, "Area tracks case count. Teal tiles are attack cases. The outlined control is benign traffic.",
                     fill=p["dim"], size=12))
    out.append(_text(w - 20, fy, f"{sum(counts.values())} cases · {len(counts)} categories",
                     fill=p["dim"], size=12, family=MONO, anchor="end"))
    out.append("</svg>")
    return "\n".join(out) + "\n"

# --------------------------------------------------------------------------
# Terminal: the doctor. Brand terminal block; one variant for both themes.
# --------------------------------------------------------------------------

DOCTOR_LINES = tuple((name, "ok") for name in (
    "platform_linux", "command_git", "command_python3", "command_go", "command_curl", "command_jq",
    "command_sha256sum", "command_tar", "command_timeout", "command_realpath", "command_make",
    "go_version", "mcp_stdio_bridge", "kernel_sandbox", "repository_root", "release_pin",
))
DOCTOR_READY = "ready: local prerequisites are satisfied"



EVIDENCE_README = REPO_ROOT / "examples" / "pipelock" / "README.md"
EVIDENCE_FILES = (
    "execution-decision.json", "run-bundle.json", "raw-summary.json", "results.jsonl",
    "tool-profile.json", "capability-registry.json", "runner.stderr", "command.txt",
    "case-index.json", "corpus-manifest.txt", "make-stats.txt", "pipelock-release.json",
    "checksums.txt", "pipelock-version.txt", "run-metadata.json", "entrypoint-command.txt",
)


def documented_evidence_files() -> set[str]:
    """File names the reference-runner guide documents for one run directory."""
    text = EVIDENCE_README.read_text(encoding="utf-8")
    start = text.find("`execution-decision.json`")
    if start < 0:
        raise SystemExit("render_diagrams: FAIL - examples/pipelock/README.md no longer documents the run directory")
    block = text[start:text.find("\n\n", start)]
    return set(re.findall(r"`([a-z0-9._-]+\.(?:json|jsonl|txt|stderr))`", block))


def _terminal_frame(x, w, h, title):
    out = [_card(x + 0.5, 0.5, w - 1, h - 1, fill=BRAND["bg_elevated"], stroke="rgba(255,255,255,0.10)", radius=12),
           f'  <path d="M {x + 12} 0.5 H {x + w - 12} A 12 12 0 0 1 {x + w - 0.5} 12 V 40 H {x + 0.5} V 12 '
           f'A 12 12 0 0 1 {x + 12} 0.5 Z" fill="#ffffff" fill-opacity="0.03"/>',
           _line(x + 0.5, 40, x + w - 0.5, 40, "rgba(255,255,255,0.06)", width=1)]
    for i, c in enumerate((BRAND["danger"], BRAND["warn"], BRAND["accent"])):
        out.append(f'  <circle cx="{_n(x + 22 + i * 20)}" cy="20" r="6" fill="{c}" opacity="0.85"/>')
    out.append(_text(x + w / 2, 25, title, fill=BRAND["dim"], size=12, family=MONO, anchor="middle"))
    return out


def terminal_doctor() -> str:
    """Two panels: the preflight on the left, what a run leaves behind on the right."""
    a, line_h = BRAND["accent"], 21
    rows = max(len(DOCTOR_LINES) + 3, len(EVIDENCE_FILES) + 2)
    w, h = 1200, 96 + rows * line_h + 30
    lw, rw, gap = 590, 590, 20
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{_n(w)}" height="{_n(h)}" viewBox="0 0 {w} {h}" role="img" '
           'aria-label="Two terminals. Left: ./scripts/run-pipelock-gauntlet.sh --doctor reports every prerequisite '
           'check as ok and ends with ready: local prerequisites are satisfied. Right: the evidence directory one '
           'run leaves behind, listing every retained file.">']
    out += _terminal_frame(0, lw, h, "preflight")
    out += _terminal_frame(lw + gap, rw, h, "one run, one evidence directory")
    y = 70
    out.append(_text(24, y, "$", fill=BRAND["dim"], size=13.5, family=MONO))
    out.append(_text(40, y, "./scripts/run-pipelock-gauntlet.sh --doctor", fill=BRAND["text"], size=13.5, family=MONO))
    y += 30
    for name, value in DOCTOR_LINES:
        out.append(_text(24, y, name, fill=BRAND["muted"], size=13.5, family=MONO))
        out.append(_text(240, y, value, fill=a, size=13.5, family=MONO, weight=700))
        y += line_h
    y += 8
    out.append(_text(24, y, DOCTOR_READY, fill=a, size=13.5, family=MONO, weight=700))

    rx, y = lw + gap + 24, 70
    out.append(_text(rx, y, "$", fill=BRAND["dim"], size=13.5, family=MONO))
    out.append(_text(rx + 16, y, "./scripts/run-pipelock-gauntlet.sh", fill=BRAND["text"], size=13.5, family=MONO))
    y += line_h
    out.append(_text(rx, y, "$", fill=BRAND["dim"], size=13.5, family=MONO))
    out.append(_text(rx + 16, y, "ls continuous-gauntlet-runs/<timestamp>/", fill=BRAND["text"], size=13.5, family=MONO))
    y += 30
    for name in EVIDENCE_FILES:
        out.append(_text(rx, y, name, fill=BRAND["muted"], size=13.5, family=MONO))
        y += line_h
    y += 8
    out.append(_text(rx, y, f"{len(EVIDENCE_FILES)} files. Exact command, raw rows, digests, release identity.",
                     fill=a, size=12.5, family=MONO, weight=700))
    out.append("</svg>")
    return "\n".join(out) + "\n"

# --------------------------------------------------------------------------
# Build, verify, write.
# --------------------------------------------------------------------------

# Rendered once per theme, embedded behind <picture>.
DIAGRAMS = {
    "architecture": architecture,
    "system": system,
    "result-states": result_states,
    "assurance": assurance,
    "coverage": coverage,
    "stats-strip": stats_strip,
}
# Rendered once, theme-independent.
SINGLES = {
    "social-preview.svg": social_preview,
    "logo.svg": logo,
    "lockup.svg": lockup,
    "terminal-doctor.svg": terminal_doctor,
}
# Hand-exported rasters, each pinned to the SVG it came from.
PNG_EXPORTS = {
    "social-preview.png": "social-preview.svg",
    "logo-256.png": "logo.svg",
}


def _strings_of(svg: str) -> list[str]:
    """Text runs of a generated SVG, for gates that check what a drawing says."""
    return [re.sub(r"&[a-z]+;", " ", m) for m in re.findall(r"<text[^>]*>([^<]*)</text>", svg)]


def verify_against_corpus() -> list[str]:
    """Report drawings that no longer describe the corpus they illustrate."""
    problems = []
    placed = {key for _, _, entries in COVERAGE_GROUPS for key, _ in entries}
    live = live_categories()
    for missing in sorted(live - placed):
        problems.append(f"coverage diagram: category {missing!r} has cases but no group; add it to COVERAGE_GROUPS")
    for extra in sorted(placed - live):
        problems.append(f"coverage diagram: group entry {extra!r} matches no live category")
    if len(placed) != sum(len(e) for _, _, e in COVERAGE_GROUPS):
        problems.append("coverage diagram: a category is placed in more than one group")

    # The one-case scene reads its case at render time, so the byte comparison in
    # --check is what catches a drawing that fell behind the corpus.

    documented = documented_evidence_files()
    for name in EVIDENCE_FILES:
        if name not in documented:
            problems.append(f"terminal: lists {name!r}, which examples/pipelock/README.md no longer documents")
    for name in sorted(documented - set(EVIDENCE_FILES)):
        problems.append(f"terminal: examples/pipelock/README.md documents {name!r}, which the drawing omits")

    script_checks = doctor_check_names()
    drawn = [name for name, _ in DOCTOR_LINES]
    for name in drawn:
        if name not in script_checks:
            problems.append(f"terminal-doctor: shows check {name!r}, which the portable entrypoint no longer reports")
    for name in script_checks:
        if name not in drawn:
            problems.append(f"terminal-doctor: the portable entrypoint reports {name!r}, which the drawing omits")
    return problems


def build() -> dict[Path, str]:
    files = {}
    for name, render in SINGLES.items():
        files[ASSET_DIR / name] = render()
    for name, render in DIAGRAMS.items():
        for theme, palette in PALETTES.items():
            files[ASSET_DIR / f"diagram-{name}-{theme}.svg"] = render(palette)
    return files


def sidecar(png: str) -> Path:
    return ASSET_DIR / f"{png}.source"


def png_problems() -> list[str]:
    """Rasters are exported by hand; each sidecar pins one to its SVG."""
    problems = []
    for png, svg in PNG_EXPORTS.items():
        if not (ASSET_DIR / png).exists():
            problems.append(f"assets/{png}: missing; export it from assets/{svg}")
            continue
        if not sidecar(png).exists():
            problems.append(f"assets/{png}.source: missing; run scripts/render_diagrams.py --stamp-png")
            continue
        if not (ASSET_DIR / svg).exists():
            problems.append(f"assets/{svg}: missing; run scripts/render_diagrams.py")
            continue
        want = hashlib.sha256((ASSET_DIR / svg).read_bytes()).hexdigest()
        if sidecar(png).read_text(encoding="utf-8").strip() != want:
            problems.append(f"assets/{png}: exported from an older assets/{svg}; re-export it and run "
                            "scripts/render_diagrams.py --stamp-png")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare committed assets without writing")
    parser.add_argument("--stamp-png", action="store_true",
                        help="record the SVG digest each hand-exported PNG was made from")
    args = parser.parse_args()

    if args.stamp_png:
        for png, svg in PNG_EXPORTS.items():
            digest = hashlib.sha256((ASSET_DIR / svg).read_bytes()).hexdigest()
            sidecar(png).write_text(digest + "\n", encoding="utf-8")
            print(f"stamped assets/{png}.source")
        return 0

    problems = verify_against_corpus()
    files = build()

    if args.check:
        problems += runner_stats_problems()
        for path, content in sorted(files.items()):
            relative = path.relative_to(REPO_ROOT)
            if not path.exists():
                problems.append(f"{relative}: missing; run scripts/render_diagrams.py")
            elif path.read_text(encoding="utf-8") != content:
                problems.append(f"{relative}: stale; run scripts/render_diagrams.py")
        problems += png_problems()
        if problems:
            print("check-diagrams: FAIL", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 1
        print(f"check-diagrams: OK ({len(files)} assets match the corpus)")
        return 0

    if problems:
        print("render_diagrams: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in sorted(files.items()):
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
