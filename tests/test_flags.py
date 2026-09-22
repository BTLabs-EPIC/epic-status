"""Flag markup.

Two things are under test that are easy to get wrong and invisible when they break:
the SVG must be inert and self-contained (it is emitted inline into every board
page, several times over), and unrecognised input must degrade in place rather than
reach the page. The country code arrives from RDAP, so it is third-party data going
straight into markup.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from epic_status.flags import (
    COUNTRY_NAMES,
    FLAG_SVG,
    flag,
    flag_title,
)

# The list this module was commissioned for: where crypto nodes actually run.
REQUESTED = """GB DE FI US NL FR CA SG PL SE CH RO CZ JP AU IE ES IT AT NO DK BE
LT LV EE UA IN BR ZA KR HK NZ PT LU MD BG HU SK HR RS TR IL AE RU""".split()

CODES = sorted(FLAG_SVG)
CHIPS = sorted(set(COUNTRY_NAMES) - set(FLAG_SVG))

NONE_MARKUP = '<span class="flag flag-none" title="Location unknown">unknown</span>'

FORBIDDEN = [
    # Every one of these is a way for an inline SVG to reach outside itself, to
    # collide with another copy of a flag on the same page, or to duplicate the
    # accessible name the wrapper already carries.
    "<script",
    "url(",
    " id=",
    "<use",
    "xlink",
    "class=",
    "<style",
    "linearGradient",
    "<title",
]


# ------------------------------------------------------------------------ coverage


@pytest.mark.parametrize("code", CODES)
def test_svg_keys_are_alpha2_uppercase(code: str) -> None:
    assert re.fullmatch(r"[A-Z]{2}", code)


@pytest.mark.parametrize("code", CODES)
def test_every_svg_has_a_name(code: str) -> None:
    """The wrapper's title comes from COUNTRY_NAMES, so a drawing without a name
    would render a flag with an empty tooltip."""
    assert code in COUNTRY_NAMES
    assert COUNTRY_NAMES[code].strip()


@pytest.mark.parametrize("code", REQUESTED)
def test_every_requested_code_has_a_name(code: str) -> None:
    """Names are required for all of them, drawing or not: the chip still needs a
    title."""
    assert code in COUNTRY_NAMES


def test_names_do_not_exceed_the_requested_set() -> None:
    """A name with no code path to reach it is dead weight, and a code outside the
    requested set is a sign this drifted from the geo module."""
    assert set(COUNTRY_NAMES) == set(REQUESTED)


# -------------------------------------------------------------------- svg hygiene


@pytest.mark.parametrize("code", CODES)
def test_svg_is_sized_by_css(code: str) -> None:
    svg = FLAG_SVG[code]
    assert 'viewBox="0 0 20 14"' in svg
    assert " width=" not in svg.split(">", 1)[0]
    assert " height=" not in svg.split(">", 1)[0]


@pytest.mark.parametrize("code", CODES)
def test_svg_contains_nothing_that_reaches_outside_itself(code: str) -> None:
    svg = FLAG_SVG[code]
    for token in FORBIDDEN:
        assert token not in svg, f"{code} contains {token!r}"


@pytest.mark.parametrize("code", CODES)
def test_svg_is_well_formed_xml(code: str) -> None:
    """Inline SVG in an HTML page is parsed leniently, so a stray unclosed tag would
    silently swallow the rest of a table row rather than fail visibly."""
    root = ET.fromstring(FLAG_SVG[code])
    assert root.tag.endswith("svg")
    assert root.get("role") == "img"
    assert root.get("shape-rendering") == "crispEdges"
    assert len(list(root)) > 0


@pytest.mark.parametrize("code", CODES)
def test_svg_fills_the_whole_viewbox(code: str) -> None:
    """The first shape is always a full-bleed background, so no flag can render with
    a transparent corner showing the page behind it."""
    first = list(ET.fromstring(FLAG_SVG[code]))[0]
    assert first.tag.endswith(("rect", "polygon"))
    if first.tag.endswith("rect"):
        assert first.get("width") == "20"
        assert first.get("height") == "14"


# -------------------------------------------------------------------- flag(), known


def test_known_flag_markup() -> None:
    markup = flag("DE")
    assert markup.startswith('<span class="flag" title="Germany" aria-hidden="true">')
    assert FLAG_SVG["DE"] in markup
    assert markup.endswith('</span><span class="sr-only">Germany</span>')


def test_flag_is_case_insensitive() -> None:
    assert flag("de") == flag("DE")
    assert flag(" de ") == flag("DE")


@pytest.mark.parametrize("code", CODES)
def test_every_known_flag_carries_its_name_twice(code: str) -> None:
    """Once as a title for a pointer, once visually hidden for a screen reader and
    for anyone copying the row out of the page."""
    name = COUNTRY_NAMES[code]
    markup = flag(code)
    assert f'title="{name}"' in markup
    assert f'<span class="sr-only">{name}</span>' in markup
    assert 'aria-hidden="true"' in markup


# --------------------------------------------------------------------- flag(), chip


def test_chip_fallback_exists() -> None:
    """If every name gained a drawing this test would be vacuous, and the fallback
    path would stop being exercised."""
    assert CHIPS, "no chip codes left to test the degradation path with"


@pytest.mark.parametrize("code", CHIPS)
def test_chip_markup(code: str) -> None:
    """A two-letter chip is the graceful degradation. A wrong flag would be worse."""
    name = COUNTRY_NAMES[code]
    assert flag(code) == (
        f'<span class="flag flag-code" title="{name}">'
        f'<span class="sr-only">{name}</span>{code}</span>'
    )


@pytest.mark.parametrize("code", CHIPS)
def test_chip_shows_the_uppercase_code(code: str) -> None:
    markup = flag(code.lower())
    assert "flag-code" in markup
    assert f">{code}</span>" in markup


# --------------------------------------------------------------------- flag(), none

UNKNOWN_INPUTS = [
    pytest.param(None, id="none"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace"),
    pytest.param("xx", id="lowercase-unassigned"),
    pytest.param("ZZ", id="unassigned"),
    pytest.param("<script>", id="markup"),
    pytest.param('" onmouseover="x', id="attribute-break-out"),
    pytest.param("D", id="one-letter"),
    pytest.param("DEU", id="alpha3"),
    pytest.param("D3", id="digit"),
    pytest.param("D-", id="punctuation"),
    pytest.param("ÖÖ", id="non-ascii"),
    pytest.param(42, id="not-a-string"),
    pytest.param(["DE"], id="list"),
]


@pytest.mark.parametrize("value", UNKNOWN_INPUTS)
def test_unknown_input_returns_the_placeholder(value: object) -> None:
    """The literal lowercase word, occupying the same slot: where the country cannot
    be determined the column must still read as a column, not as an empty cell.
    Also the escaping boundary — nothing that fails the alpha-2 check is ever
    interpolated, so there is no escaping to get wrong.
    """
    assert flag(value) == NONE_MARKUP  # type: ignore[arg-type]


@pytest.mark.parametrize("value", UNKNOWN_INPUTS)
def test_unknown_input_never_leaks_into_the_markup(value: object) -> None:
    markup = flag(value)  # type: ignore[arg-type]
    assert "<script" not in markup
    assert "onmouseover" not in markup
    if isinstance(value, str) and value.strip():
        assert value.strip() not in markup or value.strip().upper() in {"XX", "ZZ"}


def test_placeholder_is_the_lowercase_word() -> None:
    assert ">unknown<" in flag(None)
    assert "flag-none" in flag(None)


# ------------------------------------------------------------------- flag_title()


@pytest.mark.parametrize("code", sorted(COUNTRY_NAMES))
def test_flag_title_known(code: str) -> None:
    assert flag_title(code) == COUNTRY_NAMES[code]
    assert flag_title(code.lower()) == COUNTRY_NAMES[code]


@pytest.mark.parametrize("value", UNKNOWN_INPUTS)
def test_flag_title_unknown(value: object) -> None:
    assert flag_title(value) == "Location unknown"  # type: ignore[arg-type]


def test_flag_title_matches_the_title_attribute_in_flag() -> None:
    for code in sorted(COUNTRY_NAMES):
        assert f'title="{flag_title(code)}"' in flag(code)
