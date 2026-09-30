"""Icons, from Lucide, vendored.

Every mark on this site was drawn by hand until now, and the hand showed: a chain of three
blocks at 12px read as "ooo", and a globe built from a circle and two arcs read as a boxed
squiggle. Drawing an icon set is a craft discipline that a status page has no business
reinventing badly.

Lucide (ISC, `src/epic_status/static/icons/LICENSE`) is the source. The paths below are copied
from its 24×24 grid unchanged, including the stroke width and the round joins — the whole point
of taking a set is that its internal consistency comes with it. Only `viewBox` and the stroke
colour are ours, and the colour is `currentColor` so a mark inherits the text it sits beside.

Inlined rather than loaded from `/static/icons/*.svg`, for one reason: a mark that has to change
colour with its context cannot be an `<img>`. `currentColor` does not cross that boundary, and
these are all small enough that the bytes are cheaper than the extra requests. The flags are the
opposite case — 44 full-colour drawings that never recolour — so those are files.
"""

from __future__ import annotations

from typing import Final

from markupsafe import Markup

#: Shared attributes, so every icon is the same weight and the same joins. Lucide's own defaults;
#: changing them here would break the consistency that is the reason for using a set.
_ATTRS: Final = (
    'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"'
)


def _icon(name: str, paths: str, size: int) -> Markup:
    return Markup(
        f'<svg class="icon icon-{name}" width="{size}" height="{size}" {_ATTRS}>{paths}</svg>'
    )


#: Lucide `boxes`. Three cubes in isometric projection — the chain-of-blocks idea drawn by
#: people who draw icons. Replaces a hand-made row of rounded rectangles that, at label size,
#: was indistinguishable from three small circles.
_BOXES: Final = (
    '<path d="M2.97 12.92A2 2 0 0 0 2 14.63v3.24a2 2 0 0 0 .97 1.71l3 1.8a2 2 0 0 0 2.06 0L12 19v-5.5l-5-3-4.03 2.42Z"/>'
    '<path d="m7 16.5-4.74-2.85"/><path d="m7 16.5 5-3"/><path d="M7 16.5v5.17"/>'
    '<path d="M12 13.5V19l3.97 2.38a2 2 0 0 0 2.06 0l3-1.8a2 2 0 0 0 .97-1.71v-3.24a2 2 0 0 0-.97-1.71L17 10.5l-5 3Z"/>'
    '<path d="m17 16.5-5-3"/><path d="m17 16.5 4.74-2.85"/><path d="M17 16.5v5.17"/>'
    '<path d="M7.97 4.42A2 2 0 0 0 7 6.13v4.37l5 3 5-3V6.13a2 2 0 0 0-.97-1.71l-3-1.8a2 2 0 0 0-2.06 0l-3 1.8Z"/>'
    '<path d="M12 8 7.26 5.15"/><path d="m12 8 4.74-2.85"/><path d="M12 13.5V8"/>'
)

#: Lucide `globe`. Stands in for a location the registry could not give us.
_GLOBE: Final = (
    '<circle cx="12" cy="12" r="10"/>'
    '<path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>'
    '<path d="M2 12h20"/>'
)

#: Lucide `check-check`. The verified mark.
_CHECK_CHECK: Final = '<path d="M18 6 7 17l-5-5"/><path d="m22 10-7.5 7.5L13 16"/>'

#: Lucide `triangle-alert`. The marker on a relay whose TLS certificate is inside the
#: renewal window. Three strokes, which is why it survives being drawn at 12px where a
#: clock face or a shield turns to mush.
_TRIANGLE_ALERT: Final = (
    '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/>'
    '<path d="M12 9v4"/><path d="M12 17h.01"/>'
)


def boxes(size: int = 15) -> Markup:
    return _icon("boxes", _BOXES, size)


def globe(size: int = 14) -> Markup:
    return _icon("globe", _GLOBE, size)


def check_check(size: int = 15) -> Markup:
    return _icon("check", _CHECK_CHECK, size)


def triangle_alert(size: int = 12) -> Markup:
    return _icon("warn", _TRIANGLE_ALERT, size)
