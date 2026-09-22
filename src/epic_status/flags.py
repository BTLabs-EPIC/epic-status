"""Country flags as hand-written inline SVG.

Regional-indicator flag emoji are not an option: Chrome on Windows renders them as
the two bare letters, and on a minimal Linux font set they come out as fallback
boxes. A status page cannot ship an icon that is invisible to a large share of its
readers, so these are self-hosted flat-colour SVG with no font dependency and
identical output everywhere.

Simplification is deliberate. These are drawn for a 20x14 slot, where a
recognisable simplification beats an accurate mess: coats of arms and other central
emblems are omitted, and a country whose flag is only distinguishable *by* its
emblem falls through to the two-letter chip rather than being drawn as a near-
duplicate of its neighbour's.
"""

from __future__ import annotations

import html
import re
from math import cos, hypot, pi, sin

W = 20.0
H = 14.0

_CODE_RE = re.compile(r"^[A-Z]{2}$")

# Diagonals and curves have to opt out of the root's crispEdges, which exists so
# 1px horizontal bands stay sharp but leaves anything off-axis visibly stepped.
_AA = ' shape-rendering="geometricPrecision"'

_WHITE = "#FFFFFF"
_BLACK = "#000000"


def _n(value: float) -> str:
    """Trim trailing zeros. Purely to keep the markup readable in page source."""
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return text or "0"


def _rect(x: float, y: float, w: float, h: float, fill: str) -> str:
    return (
        f'<rect x="{_n(x)}" y="{_n(y)}" width="{_n(w)}" height="{_n(h)}"'
        f' fill="{fill}"/>'
    )


def _bg(fill: str) -> str:
    return _rect(0, 0, W, H, fill)


def _poly(points: list[tuple[float, float]], fill: str, *, aa: bool = True) -> str:
    body = " ".join(f"{_n(x)},{_n(y)}" for x, y in points)
    return f'<polygon points="{body}" fill="{fill}"{_AA if aa else ""}/>'


def _circle(cx: float, cy: float, r: float, fill: str) -> str:
    return (
        f'<circle cx="{_n(cx)}" cy="{_n(cy)}" r="{_n(r)}" fill="{fill}"{_AA}/>'
    )


# Bands are stacked rather than tiled: each one is drawn full-bleed to the far
# edge, so no rounding error can leave a hairline gap between two of them.


def _horizontal(*fills: str) -> str:
    step = H / len(fills)
    return "".join(
        _rect(0, i * step, W, H - i * step, fill) for i, fill in enumerate(fills)
    )


def _vertical(*fills: str) -> str:
    step = W / len(fills)
    return "".join(
        _rect(i * step, 0, W - i * step, H, fill) for i, fill in enumerate(fills)
    )


def _bands_h(fills: list[tuple[str, float]]) -> str:
    """Horizontal bands with explicit weights, e.g. Spain's 1:2:1."""
    total = sum(weight for _, weight in fills)
    out: list[str] = []
    y = 0.0
    for fill, weight in fills:
        out.append(_rect(0, y, W, H - y, fill))
        y += H * weight / total
    return "".join(out)


def _nordic(bg: str, cross: str, inner: str | None = None) -> str:
    """Off-centre cross, as every Nordic flag has it."""
    out = [_bg(bg)]
    out.append(_rect(0, 5.5, W, 3.0, cross))
    out.append(_rect(6.2, 0, 3.0, H, cross))
    if inner is not None:
        out.append(_rect(0, 6.4, W, 1.2, inner))
        out.append(_rect(6.9, 0, 1.6, H, inner))
    return "".join(out)


def _saltire(
    x0: float, y0: float, w: float, h: float, width: float, fill: str
) -> str:
    """A diagonal cross drawn as two hexagons clipped to the box.

    A thick stroke on a corner-to-corner line is shorter to write but its butt caps
    poke outside the box, which is invisible on a full-bleed flag and an obvious
    smear when the same drawing is reused as Australia's canton.
    """
    x1, y1 = x0 + w, y0 + h
    t = width * hypot(w, h) / h  # horizontal thickness for the wanted perpendicular
    k = (h / w) * (t / 2)
    down = [
        (x0, y0 + k),
        (x0, y0),
        (x0 + t / 2, y0),
        (x1, y1 - k),
        (x1, y1),
        (x1 - t / 2, y1),
    ]
    up = [
        (x1, y0 + k),
        (x1, y0),
        (x1 - t / 2, y0),
        (x0, y1 - k),
        (x0, y1),
        (x0 + t / 2, y1),
    ]
    return _poly(down, fill) + _poly(up, fill)


_GB_BLUE = "#012169"
_GB_RED = "#C8102E"


def _union(x0: float, y0: float, w: float, h: float) -> str:
    """The Union Flag, reused at full bleed for GB and as the canton for AU.

    Not counterchanged: the saltire's half-width offset is the one detail that is
    pure cost at this size, so the white and red diagonals are concentric.
    """
    return "".join(
        [
            _rect(x0, y0, w, h, _GB_BLUE),
            _saltire(x0, y0, w, h, h / 5, _WHITE),
            _saltire(x0, y0, w, h, h / 15, _GB_RED),
            _rect(x0, y0 + h / 2 - h / 6, w, h / 3, _WHITE),
            _rect(x0 + w / 2 - h / 6, y0, h / 3, h, _WHITE),
            _rect(x0, y0 + h / 2 - h / 10, w, h / 5, _GB_RED),
            _rect(x0 + w / 2 - h / 10, y0, h / 5, h, _GB_RED),
        ]
    )


def _star(cx: float, cy: float, r: float, fill: str, rotation: float = -pi / 2) -> str:
    """Five-pointed star. Generated rather than typed so the points stay even."""
    points: list[tuple[float, float]] = []
    for i in range(10):
        radius = r if i % 2 == 0 else r * 0.382
        angle = rotation + i * pi / 5
        points.append((cx + radius * cos(angle), cy + radius * sin(angle)))
    return _poly(points, fill)


def _maple_leaf(fill: str) -> str:
    """Canada. Mirrored from a half outline so it cannot come out lopsided.

    Without it the flag is a red-white-red vertical bicolour, indistinguishable
    from Peru's at this size. Two details do the work of making it read as a leaf
    rather than a star: the notches cut back close to the centre line, and the stem
    is a separate narrow bar. Kept inside x 6..14 so it never touches the red bands.
    """
    half = [
        (10.00, 1.55),  # apex
        (10.50, 3.45),  # notch
        (11.80, 3.00),  # upper lobe
        (11.50, 4.70),
        (13.35, 4.20),  # mid lobe
        (12.80, 5.55),
        (13.95, 6.05),  # widest lobe
        (13.05, 6.95),
        (11.45, 7.05),  # deep cut back toward the centre line
        (12.05, 9.20),  # lower spur
        (10.75, 8.90),
        (10.58, 12.45),  # stem
    ]
    points = half + [(W - x, y) for x, y in reversed(half)]
    return _poly(points, fill)


def _us() -> str:
    """Thirteen stripes reduced to seven, and no stars: five-pointed stars at this
    size are mud. The canton carries a sparse dot grid instead, which reads as
    texture rather than as a wrong star count."""
    stripe = H / 7
    out = [_bg(_WHITE)]
    for i in range(0, 7, 2):
        out.append(_rect(0, i * stripe, W, stripe, "#B31942"))
    canton_w, canton_h = 8.8, stripe * 3
    out.append(_rect(0, 0, canton_w, canton_h, "#0A3161"))
    for row in range(4):
        y = 0.85 + row * 1.25
        offset = 0.0 if row % 2 == 0 else 0.8
        for col in range(5 if row % 2 == 0 else 4):
            x = 0.9 + offset + col * 1.6
            out.append(_rect(x, y, 0.55, 0.55, _WHITE))
    return "".join(out)


def _sg() -> str:
    """Crescent plus a ring of five stars, both reduced to circles. The crescent is
    a white disc with a red disc laid over it — no mask, no clip path, no id."""
    out = [_rect(0, 0, W, H, _WHITE), _rect(0, 0, W, H / 2, "#EF3340")]
    out.append(_circle(4.7, 3.5, 2.5, _WHITE))
    out.append(_circle(5.9, 3.5, 2.25, "#EF3340"))
    for i in range(5):
        angle = -pi / 2 + i * 2 * pi / 5
        out.append(_circle(9.4 + 1.9 * cos(angle), 3.5 + 1.9 * sin(angle), 0.4, _WHITE))
    return "".join(out)


def _tr() -> str:
    out = [_bg("#E30A17")]
    out.append(_circle(8.0, 7.0, 3.1, _WHITE))
    out.append(_circle(9.1, 7.0, 2.5, "#E30A17"))
    out.append(_star(13.0, 7.0, 2.0, _WHITE))
    return "".join(out)


def _il() -> str:
    """Star of David as two overlapping triangles. Outlining it would need a stroke
    that vanishes below about 16px, so it is drawn solid."""
    blue = "#0038B8"
    cx, cy, r = 10.0, 7.0, 2.9
    up = [
        (cx + r * cos(-pi / 2 + i * 2 * pi / 3), cy + r * sin(-pi / 2 + i * 2 * pi / 3))
        for i in range(3)
    ]
    down = [
        (cx + r * cos(pi / 2 + i * 2 * pi / 3), cy + r * sin(pi / 2 + i * 2 * pi / 3))
        for i in range(3)
    ]
    return "".join(
        [
            _bg(_WHITE),
            _rect(0, 1.3, W, 1.7, blue),
            _rect(0, H - 3.0, W, 1.7, blue),
            _poly(up, blue),
            _poly(down, blue),
        ]
    )


def _br() -> str:
    """Rhombus and disc kept; the constellation and the banner motto are dropped —
    at 20px they are noise, and the three shapes alone are unambiguous."""
    return "".join(
        [
            _bg("#009739"),
            _poly([(10, 1.4), (18.6, 7), (10, 12.6), (1.4, 7)], "#FEDD00"),
            _circle(10, 7, 3.0, "#012169"),
        ]
    )


def _in() -> str:
    """The chakra's 24 spokes are below the resolution of this slot, so it is a navy
    ring: two discs, outer navy and inner white."""
    return "".join(
        [
            _horizontal("#FF9933", _WHITE, "#138808"),
            _circle(10, 7, 2.0, "#000080"),
            _circle(10, 7, 1.35, _WHITE),
        ]
    )


def _au() -> str:
    """Canton plus stars as discs. Five-pointed stars this small are indistinct, and
    the Commonwealth star's seven points doubly so."""
    out = [_bg(_GB_BLUE), _union(0, 0, 10.0, 7.0)]
    out.append(_circle(5.0, 10.6, 1.05, _WHITE))
    for cx, cy, r in (
        (15.4, 3.0, 0.62),
        (17.7, 6.6, 0.7),
        (15.1, 9.6, 0.62),
        (12.9, 6.2, 0.55),
        (16.4, 5.2, 0.34),
    ):
        out.append(_circle(cx, cy, r, _WHITE))
    return "".join(out)


def _ch() -> str:
    return "".join(
        [
            _bg("#DA291C"),
            _rect(6.2, 5.6, 7.6, 2.8, _WHITE),
            _rect(8.6, 3.2, 2.8, 7.6, _WHITE),
        ]
    )


def _cz() -> str:
    return "".join(
        [
            _rect(0, 0, W, H, _WHITE),
            _rect(0, H / 2, W, H / 2, "#D7141A"),
            _poly([(0, 0), (10.0, 7.0), (0, H)], "#11457E"),
        ]
    )


def _svg(body: str) -> str:
    """No width or height: CSS sizes the slot. No <title> either — the wrapper span
    carries the accessible name, so a duplicate here would be read twice."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 14" role="img"'
        f' shape-rendering="crispEdges">{body}</svg>'
    )


FLAG_SVG: dict[str, str] = {
    "AE": _svg(
        _horizontal("#00732F", _WHITE, _BLACK) + _rect(0, 0, 5.0, H, "#EF3340")
    ),
    "AT": _svg(_horizontal("#ED2939", _WHITE, "#ED2939")),
    "AU": _svg(_au()),
    "BE": _svg(_vertical(_BLACK, "#FAE042", "#ED2939")),
    "BG": _svg(_horizontal(_WHITE, "#00966E", "#D62612")),
    "BR": _svg(_br()),
    "CA": _svg(
        _bg(_WHITE)
        + _rect(0, 0, 5.0, H, "#D80621")
        + _rect(15.0, 0, 5.0, H, "#D80621")
        + _maple_leaf("#D80621")
    ),
    "CH": _svg(_ch()),
    "CZ": _svg(_cz()),
    "DE": _svg(_horizontal(_BLACK, "#DD0000", "#FFCE00")),
    "DK": _svg(_nordic("#C8102E", _WHITE)),
    "EE": _svg(_horizontal("#0072CE", _BLACK, _WHITE)),
    "ES": _svg(_bands_h([("#AA151B", 1), ("#F1BF00", 2), ("#AA151B", 1)])),
    "FI": _svg(_nordic(_WHITE, "#003580")),
    "FR": _svg(_vertical("#002395", _WHITE, "#ED2939")),
    "GB": _svg(_union(0, 0, W, H)),
    "HU": _svg(_horizontal("#CD2A3E", _WHITE, "#436F4D")),
    "IE": _svg(_vertical("#169B62", _WHITE, "#FF883E")),
    "IL": _svg(_il()),
    "IN": _svg(_in()),
    "IT": _svg(_vertical("#008C45", "#F4F5F0", "#CD212A")),
    "JP": _svg(_bg(_WHITE) + _circle(10, 7, 4.1, "#BC002D")),
    "LT": _svg(_horizontal("#FDB913", "#006A44", "#C1272D")),
    "LU": _svg(_horizontal("#ED2939", _WHITE, "#00A1DE")),
    "LV": _svg(_bands_h([("#9E3039", 2), (_WHITE, 1), ("#9E3039", 2)])),
    "NL": _svg(_horizontal("#AE1C28", _WHITE, "#21468B")),
    "NO": _svg(_nordic("#BA0C2F", _WHITE, "#00205B")),
    "PL": _svg(_bg(_WHITE) + _rect(0, H / 2, W, H / 2, "#DC143C")),
    "PT": _svg(
        _bg("#DA291C") + _rect(0, 0, W * 0.4, H, "#046A38")
    ),
    "RO": _svg(_vertical("#002B7F", "#FCD116", "#CE1126")),
    "RU": _svg(_horizontal(_WHITE, "#0039A6", "#D52B1E")),
    "SE": _svg(_nordic("#006AA7", "#FECC00")),
    "SG": _svg(_sg()),
    "TR": _svg(_tr()),
    "UA": _svg(_bg("#005BBB") + _rect(0, H / 2, W, H / 2, "#FFD500")),
    "US": _svg(_us()),
}


# Every code the registry or an RDAP lookup can produce for this fleet needs a
# name, whether or not it has a drawing: the chip still has to have a title.
COUNTRY_NAMES: dict[str, str] = {
    "AE": "United Arab Emirates",
    "AT": "Austria",
    "AU": "Australia",
    "BE": "Belgium",
    "BG": "Bulgaria",
    "BR": "Brazil",
    "CA": "Canada",
    "CH": "Switzerland",
    "CZ": "Czechia",
    "DE": "Germany",
    "DK": "Denmark",
    "EE": "Estonia",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "HK": "Hong Kong",
    "HR": "Croatia",
    "HU": "Hungary",
    "IE": "Ireland",
    "IL": "Israel",
    "IN": "India",
    "IT": "Italy",
    "JP": "Japan",
    "KR": "South Korea",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "LV": "Latvia",
    "MD": "Moldova",
    "NL": "Netherlands",
    "NO": "Norway",
    "NZ": "New Zealand",
    "PL": "Poland",
    "PT": "Portugal",
    "RO": "Romania",
    "RS": "Serbia",
    "RU": "Russia",
    "SE": "Sweden",
    "SG": "Singapore",
    "SK": "Slovakia",
    "TR": "Turkey",
    "UA": "Ukraine",
    "US": "United States",
    "ZA": "South Africa",
}

UNKNOWN_TITLE = "Location unknown"

# The project owner's call: where the country cannot be determined, print the word
# rather than leaving the cell empty, so the column never reads as broken markup.
UNKNOWN_MARKUP = (
    f'<span class="flag flag-none" title="{UNKNOWN_TITLE}">unknown</span>'
)


def _normalise(country: str | None) -> str | None:
    """Uppercase, then validate. The value can come from RDAP, which is
    third-party data interpolated straight into markup, so anything that is not
    two ASCII letters is discarded rather than escaped and rendered."""
    if not isinstance(country, str):
        return None
    code = country.strip().upper()
    if not _CODE_RE.match(code):
        return None
    return code if code in COUNTRY_NAMES else None


def flag_title(country: str | None) -> str:
    code = _normalise(country)
    return COUNTRY_NAMES[code] if code else UNKNOWN_TITLE


def flag(country: str | None) -> str:
    """Markup for one flag slot. Never raises; unknown input degrades in place."""
    code = _normalise(country)
    if code is None:
        return UNKNOWN_MARKUP

    name = html.escape(COUNTRY_NAMES[code], quote=True)
    svg = FLAG_SVG.get(code)
    if svg is None:
        # Graceful degradation, and the reason coverage does not have to be
        # complete: a wrong flag is worse than an honest two-letter chip.
        return (
            f'<span class="flag flag-code" title="{name}">'
            f'<span class="sr-only">{name}</span>{code}</span>'
        )

    # aria-hidden on the drawing, with the name in a visually-hidden sibling, so a
    # screen reader says "Germany" once and a copy-paste of the row carries it too.
    return (
        f'<span class="flag" title="{name}" aria-hidden="true">{svg}</span>'
        f'<span class="sr-only">{name}</span>'
    )
