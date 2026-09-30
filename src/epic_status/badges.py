"""Embeddable SVG status badges: `/badge/<slug>.svg`.

For an operator's README or a pool's front page. Shields-style — a dark label and a
coloured value — because that is the shape readers already recognise, and because a
badge is read at a glance in someone else's layout rather than in ours.

Three decisions worth stating:

**Drawn here, not fetched from shields.io.** A badge that loads from a third party
discloses every reader of the embedding page to that third party, which is the
opposite of what this project does with its own fonts.

**Monospace, so the width is arithmetic.** A proportional face needs a per-glyph width
table to size the box; a monospace one needs a multiplication. The badge renders in
whatever monospace font the viewer has, and each advance is close enough to 0.6em in
all of the common ones that the box fits.

**The value is words, not only colour.** `healthy · 99.97%` reads correctly in a
monochrome screenshot and to a colour-blind reader, which the state colour alone would
not.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from .models import State, TargetStatus

_FONT_PX = 11
_CHAR_W = 6.6
"""0.6em at 11px: the advance of the common monospace faces."""
_PAD = 6
_HEIGHT = 20

_TONE = {
    State.HEALTHY: "#2f7d46",
    State.DEGRADED: "#a86a12",
    State.DOWN: "#c0392b",
    State.UNKNOWN: "#6b6b6b",
}
_LABEL_BG = "#2b2b31"

_WORD = {
    State.HEALTHY: "healthy",
    State.DEGRADED: "degraded",
    State.DOWN: "down",
    State.UNKNOWN: "unknown",
}

MAX_LABEL = 40


def badge_for(status: TargetStatus | None, *, label: str) -> str:
    """The badge for one target, or a grey "not monitored" badge for none."""
    if status is None:
        return render(label, "not monitored", _TONE[State.UNKNOWN])
    value = _WORD[status.state]
    if status.uptime_30d is not None:
        value += f" · {_pct(status.uptime_30d)}"
    return render(label, value, _TONE[status.state])


def render(label: str, value: str, colour: str) -> str:
    """A two-part badge. Both strings are escaped: `label` can come from a query
    parameter, and a badge is served as an image that some viewers render inline."""
    label = label[:MAX_LABEL]
    left = round(len(label) * _CHAR_W) + 2 * _PAD
    right = round(len(value) * _CHAR_W) + 2 * _PAD
    width = left + right
    text_y = 14
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{_HEIGHT}"'
        f' role="img" aria-label="{escape(label, _ATTR)}: {escape(value, _ATTR)}">'
        f"<title>{escape(label)}: {escape(value)}</title>"
        f'<clipPath id="r"><rect width="{width}" height="{_HEIGHT}" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{left}" height="{_HEIGHT}" fill="{_LABEL_BG}"/>'
        f'<rect x="{left}" width="{right}" height="{_HEIGHT}" fill="{colour}"/>'
        f"</g>"
        f'<g fill="#fff" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,'
        f"'DejaVu Sans Mono',monospace\" font-size=\"{_FONT_PX}\">"
        f'<text x="{_PAD}" y="{text_y}">{escape(label)}</text>'
        f'<text x="{left + _PAD}" y="{text_y}">{escape(value)}</text>'
        f"</g></svg>"
    )


_ATTR = {'"': "&quot;"}


def _pct(value: float) -> str:
    """Same rule as the board: 100% only when it rounds there honestly."""
    if value >= 0.9995:
        return "100%"
    return f"{value * 100:.2f}%"
