"""Country flags, from flag-icons, vendored.

These were hand-drawn: 36 flags built from rectangles and approximated crosses. They were
honest about their own limits — a country without a drawing degraded to a two-letter chip — but
they looked hand-drawn, because they were. Nobody should be redrawing the Union Jack.

flag-icons (MIT, `static/flags/LICENSE`) is the source, at its 4×3 aspect. The files are served
from `/static/flags/` rather than inlined: a flag is full-colour artwork that never needs to
inherit anything from the page, so an `<img>` is the right element, the browser caches each one
once for the whole session, and the markup stays small. Icons that *do* recolour with their
context are inlined instead — see `icons.py`.

Served locally, never from a CDN. Same rule as the typeface: no reader's address is disclosed to
a third party for the sake of a picture.
"""

from __future__ import annotations

import html
import re

from .icons import globe

_CODE_RE = re.compile(r"^[A-Z]{2}$")

#: Codes with a file in `static/flags/`. Declared rather than read from the directory at import,
#: so a missing file is a test failure with a name in it instead of a flag that quietly stops
#: rendering in production. `test_flags` asserts the set and the directory agree.
FLAG_CODES: frozenset[str] = frozenset(
    {
        "AE", "AT", "AU", "BE", "BG", "BR", "CA", "CH", "CZ", "DE", "DK", "EE",
        "ES", "FI", "FR", "GB", "HK", "HR", "HU", "IE", "IL", "IN", "IT", "JP",
        "KR", "LT", "LU", "LV", "MD", "NL", "NO", "NZ", "PL", "PT", "RO", "RS",
        "RU", "SE", "SG", "SK", "TR", "UA", "US", "ZA",
    }
)

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

#: A globe, where the registry could not tell us where a host is.
#:
#: This was the word "unknown" in a bordered chip — the widest thing the Location column ever
#: held, wider than any flag, so the column had to be sized for it and at four-digit latencies it
#: still collided with the number beside it. An icon occupies the same slot as the flags it
#: stands in for, and the label carries the meaning for anyone who cannot see it.
UNKNOWN_MARKUP = (
    f'<span class="flag flag-none" title="{UNKNOWN_TITLE}" role="img"'
    f' aria-label="{UNKNOWN_TITLE}">{globe()}</span>'
)


def _normalise(country: str | None) -> str | None:
    """Uppercase, then validate.

    The value can come from RDAP, which is third-party data interpolated straight into markup, so
    anything that is not two ASCII letters is discarded rather than escaped and rendered.
    """
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
    if code not in FLAG_CODES:
        # Graceful degradation, and the reason coverage does not have to be complete: a wrong
        # flag is worse than an honest two-letter chip.
        return (
            f'<span class="flag flag-code" title="{name}">'
            f'<span class="sr-only">{name}</span>{code}</span>'
        )

    # `alt=""` with the name in a visually-hidden sibling, so a screen reader says "Germany"
    # once rather than twice and a copy-paste of the row still carries it. Dimensions are on the
    # element so the row does not reflow while the file loads.
    return (
        f'<img class="flag flag-img" src="/static/flags/{code.lower()}.svg"'
        f' width="20" height="15" alt="" title="{name}" loading="lazy" decoding="async" />'
        f'<span class="sr-only">{name}</span>'
    )
