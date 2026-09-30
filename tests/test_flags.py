"""Flags and icons.

These were 36 hand-drawn SVGs, and the tests here were mostly about the drawings: that each one
was well-formed XML, that its first shape filled the viewBox, that it carried no external
reference. Those assertions were load-bearing while we were the ones drawing — a flag built from
rectangles can be malformed in ways a vendored one cannot.

The drawings are now flag-icons (MIT) served as files, so the tests are about the wiring instead:
that every country we name has a file, that the markup points at it, that a country we cannot draw
still degrades to a chip, and that third-party input from RDAP cannot reach the page as markup.
That last one is the only test here that was ever about security, and it is unchanged.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from epic_status.flags import (
    COUNTRY_NAMES,
    FLAG_CODES,
    UNKNOWN_MARKUP,
    UNKNOWN_TITLE,
    flag,
    flag_title,
)

FLAG_DIR = Path(__file__).resolve().parents[1] / "src" / "epic_status" / "static" / "flags"

CODES = sorted(FLAG_CODES)
CHIPS = sorted(set(COUNTRY_NAMES) - FLAG_CODES)


# ------------------------------------------------------------------ the vendored set


def test_the_flag_directory_exists() -> None:
    assert FLAG_DIR.is_dir()


@pytest.mark.parametrize("code", CODES)
def test_every_declared_code_has_a_file(code: str) -> None:
    """`FLAG_CODES` is declared in the module rather than read from the directory, so that a
    missing file fails here with a name in it instead of quietly rendering nothing in
    production."""
    assert (FLAG_DIR / f"{code.lower()}.svg").is_file()


@pytest.mark.parametrize("code", CODES)
def test_every_file_is_well_formed_svg(code: str) -> None:
    root = ET.fromstring((FLAG_DIR / f"{code.lower()}.svg").read_text())
    assert root.tag.endswith("svg")
    assert root.get("viewBox")


@pytest.mark.parametrize("code", CODES)
def test_no_flag_reaches_outside_itself(code: str) -> None:
    """A flag is markup served from our own origin: it must not fetch anything, script anything,
    or embed a raster.

    The first version of this forbade `xlink:href` outright and failed on seven flags. That was
    the test being wrong, not the artwork: flag-icons uses `<use xlink:href="#id">` to repeat a
    star or a stripe within the same file, which is reuse rather than a reference outward. What
    matters is where a reference points, so that is what this checks.
    """
    svg = (FLAG_DIR / f"{code.lower()}.svg").read_text()
    lowered = svg.lower()
    for forbidden in ("<script", "<image", "<foreignobject", "javascript:", "data:"):
        assert forbidden not in lowered, forbidden

    # Every href, with or without the xlink prefix, must be a same-document fragment.
    for match in re.finditer(r'(?:xlink:)?href\s*=\s*"([^"]*)"', svg):
        assert match.group(1).startswith("#"), match.group(1)

    # The only absolute URLs allowed are the namespace declarations, which fetch nothing.
    for match in re.finditer(r'https?://[^"\s]+', svg):
        assert match.group(0).startswith("http://www.w3.org/"), match.group(0)


@pytest.mark.parametrize("code", CODES)
def test_every_declared_code_has_a_name(code: str) -> None:
    assert COUNTRY_NAMES.get(code)


def test_no_orphan_files() -> None:
    """A file with no declared code would never be served, and a code with no name would render a
    flag with no label."""
    on_disk = {p.stem.upper() for p in FLAG_DIR.glob("*.svg")}
    assert on_disk == FLAG_CODES


def test_the_licence_travels_with_the_artwork() -> None:
    assert (FLAG_DIR / "LICENSE").is_file()
    assert "MIT" in (FLAG_DIR / "LICENSE").read_text()


# ------------------------------------------------------------------------- markup


@pytest.mark.parametrize("code", CODES)
def test_known_flag_points_at_its_file(code: str) -> None:
    markup = flag(code)
    assert f'src="/static/flags/{code.lower()}.svg"' in markup
    # Dimensions on the element, so a row does not reflow while the file loads.
    assert 'width="20"' in markup and 'height="15"' in markup


@pytest.mark.parametrize("code", CODES)
def test_every_known_flag_carries_its_name_twice(code: str) -> None:
    """Once as a tooltip for a mouse, once visually hidden for a screen reader and for a
    copy-paste of the row."""
    name = COUNTRY_NAMES[code]
    markup = flag(code)
    assert f'title="{name}"' in markup
    assert f">{name}</span>" in markup
    # `alt=""` with the name in a sibling, rather than in `alt`, so it is announced once.
    assert 'alt=""' in markup


def test_flag_is_case_insensitive() -> None:
    assert flag("de") == flag("DE") == flag(" de ")


@pytest.mark.skipif(not CHIPS, reason="every named country currently has a file")
@pytest.mark.parametrize("code", CHIPS)
def test_chip_fallback_for_a_country_without_artwork(code: str) -> None:
    markup = flag(code)
    assert "flag-code" in markup
    assert code in markup


def test_chip_path_exists_even_with_full_coverage() -> None:
    """Coverage is complete today. The branch still has to work, because the next country RDAP
    returns will not have been downloaded — a wrong flag is worse than an honest chip."""
    from epic_status import flags

    original = flags.FLAG_CODES
    try:
        flags.FLAG_CODES = frozenset()
        markup = flags.flag("DE")
    finally:
        flags.FLAG_CODES = original
    assert "flag-code" in markup
    assert ">DE</span>" in markup
    assert "<img" not in markup


# -------------------------------------------------------------------- unknown input


@pytest.mark.parametrize(
    "value",
    [None, "", " ", "X", "XYZ", "12", "D3", "ZZ", "<svg>", "de'", 7, 7.0, True, b"DE", ["DE"]],
    ids=[
        "none", "empty", "space", "one-letter", "three-letters", "digits", "mixed",
        "unassigned", "markup", "quote", "int", "float", "bool", "bytes", "list",
    ],
)
def test_unknown_input_returns_the_placeholder(value: object) -> None:
    assert flag(value) == UNKNOWN_MARKUP  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["<script>x</script>", '" onload="x', "../../etc/passwd", "DE<"])
def test_unknown_input_never_leaks_into_the_markup(value: str) -> None:
    """The security assertion. `country` reaches this function from an RDAP response, so a value
    that is not two ASCII letters is discarded rather than escaped and rendered — and in
    particular it can never become part of a `src` path."""
    markup = flag(value)
    assert value not in markup
    assert "<script" not in markup.lower()


def test_placeholder_is_a_drawn_globe_not_a_word() -> None:
    """Sized like a flag, because it occupies a flag's slot. The word it replaced forced the whole
    column wider than any flag needed and still overlapped the latency beside it."""
    markup = flag(None)
    assert "<svg" in markup
    assert ">unknown<" not in markup
    # The meaning is not carried by a tooltip alone, which a keyboard user never sees.
    assert 'role="img"' in markup
    assert f'aria-label="{UNKNOWN_TITLE}"' in markup


# --------------------------------------------------------------------------- titles


@pytest.mark.parametrize("code", CODES)
def test_flag_title_known(code: str) -> None:
    assert flag_title(code) == COUNTRY_NAMES[code]


@pytest.mark.parametrize("value", [None, "", "XYZ", 7])
def test_flag_title_unknown(value: object) -> None:
    assert flag_title(value) == UNKNOWN_TITLE  # type: ignore[arg-type]


@pytest.mark.parametrize("code", CODES)
def test_flag_title_matches_the_title_attribute_in_flag(code: str) -> None:
    assert f'title="{flag_title(code)}"' in flag(code)
