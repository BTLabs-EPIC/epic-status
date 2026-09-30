"""Every HTML route renders, with and without a snapshot.

This file exists because /api returned 500 in production while 639 tests passed. The
reference page was rewritten to extend the shared layout, `render_api` kept passing four
hand-picked variables, and the Jinja environment uses `StrictUndefined` — so the first
key the layout needed and did not get was an exception, not a blank in the markup. No
test rendered that route, so nothing caught it.

The lesson is narrow and worth encoding: a template that extends the shared layout needs
the shared context, and the cheapest guard against a missing key is to render every page
in both states the service actually serves — before the first sweep, and after it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from epic_status.config import Settings
from epic_status.models import (
    Check,
    Kind,
    NetworkSummary,
    Snapshot,
    Source,
    State,
    Target,
    TargetStatus,
)
from epic_status.render import render_api, render_board, render_history, render_submit


def _checks(results: list[bool]) -> list[Check]:
    """Build a history strip from outcomes alone.

    `TargetStatus.history` became a list of `Check` when the recent-checks bars gained a time
    and a latency on hover — a bar a reader can point at should be able to say when it was, and
    a boolean cannot.
    """
    base = datetime.now(UTC)
    return [
        Check(ok=ok, at=base - timedelta(seconds=5 * (len(results) - i)), latency_ms=40)
        for i, ok in enumerate(results)
    ]



def target(kind: Kind, slug: str) -> Target:
    return Target(
        kind=kind,
        slug=slug,
        endpoint=f"https://{slug}",
        display_host=slug,
        operator="Example",
        source=Source.SEED,
    )


def status(kind: Kind, slug: str) -> TargetStatus:
    s = TargetStatus(
        target=target(kind, slug),
        state=State.HEALTHY,
        latency_ms=120,
        history=_checks([True, True, False, True]),
        uptime_1h=1.0,
        uptime_24h=0.9993,
        uptime_30d=0.997,
        last_ok_at=datetime.now(UTC),
        last_checked_at=datetime.now(UTC),
    )
    if kind is Kind.NODE:
        s.height = 3_721_000
        s.tip_lag = 0
        s.node_version = "4.0.2"
    elif kind is Kind.EPICBOX:
        s.protocol_version = "3.0.1"
        s.cert_expires_in_days = 40
    else:
        s.miners = 9
        s.last_block_at = datetime.now(UTC)
    return s


@pytest.fixture
def snapshot() -> Snapshot:
    return Snapshot(
        generated_at=datetime.now(UTC),
        prober_id="test",
        network=NetworkSummary(
            tip_height=3_721_000,
            tip_age_s=42,
            nodes_total=2,
            nodes_healthy=2,
            epicbox_total=1,
            epicbox_healthy=1,
            pools_total=1,
            pools_healthy=1,
            released_node_version="4.0.4",
            nodes_versioned=2,
            nodes_current=0,
            providers={"Vultr": 3, "Hetzner": 1},
            co_hosted=1,
            median_epicbox_latency_ms=480,
            median_pool_latency_ms=900,
        ),
        nodes=[status(Kind.NODE, "a.example"), status(Kind.NODE, "b.example")],
        epicbox=[status(Kind.EPICBOX, "relay.example")],
        pools=[status(Kind.POOL, "pool.example")],
    )


SETTINGS = Settings()


# --------------------------------------------------------------- with a snapshot


def test_board_renders(snapshot: Snapshot) -> None:
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert "<html" in html
    assert "The chain is" in html


def test_api_reference_renders() -> None:
    """The regression this file exists for: /api extends the shared layout and needs its
    whole context, and a missing key under StrictUndefined is a 500 rather than a blank."""
    html = render_api(settings=SETTINGS)
    assert "<html" in html
    assert "/api/v1/status.json" in html
    assert "/api/v1/nodes.json" in html


def test_history_renders(snapshot: Snapshot) -> None:
    html = render_history(snapshot=snapshot, settings=SETTINGS, bars={})
    assert "<html" in html


def test_submit_renders(snapshot: Snapshot) -> None:
    html = render_submit(snapshot=snapshot, settings=SETTINGS)
    assert "<html" in html


# ------------------------------------------------------------ before first sweep


def test_board_renders_with_no_snapshot() -> None:
    html = render_board(snapshot=None, settings=SETTINGS)
    assert "Starting up" in html


def test_history_renders_with_no_snapshot() -> None:
    html = render_history(snapshot=None, settings=SETTINGS, bars={})
    assert "<html" in html


# ------------------------------------------------------------------ shared layout


@pytest.mark.parametrize("page", ["board", "api", "history", "submit"])
def test_every_page_carries_the_layout_contract(page: str, snapshot: Snapshot) -> None:
    """The specific keys base.html reads. A page that extends the layout without them is
    a 500, and the failure is per-route rather than global — which is why it survived a
    full green suite."""
    html = {
        "board": lambda: render_board(snapshot=snapshot, settings=SETTINGS),
        "api": lambda: render_api(settings=SETTINGS),
        "history": lambda: render_history(snapshot=snapshot, settings=SETTINGS, bars={}),
        "submit": lambda: render_submit(snapshot=snapshot, settings=SETTINGS),
    }[page]()

    assert "data-epicbox-protocol=" in html
    # Versioned, and asserted as versioned. An unversioned `/static/app.js` is what let a
    # browser keep a script from before the network switch existed and poll the wrong
    # chain — writing mainnet's tip height onto a floonet board with no error anywhere.
    # Pinning the `?v=` here stops a future edit from quietly reverting to the URL that
    # caused it. See render.asset_version.
    assert 'src="/static/app.js?v=' in html
    assert 'href="/static/app.css?v=' in html
    # Every page carries the chain, because app.js reads it to decide what to poll.
    assert "data-chain=" in html
    # The nav must point at the human reference, not at raw JSON. It used to link
    # /api/v1/status.json, so clicking "API" dropped the reader into an unformatted dump.
    assert '<a href="/api"' in html
    assert '>API</a>' in html



# --------------------------------------------------------------- payload shape


def test_uptime_is_rounded_but_never_zeroed() -> None:
    """Four places, and None survives.

    `0.9977628635346756` is float64 noise presented as precision — the figure underneath is
    a ratio of integer check counts. But rounding must not reach None: a target with no
    history has no uptime, and publishing 0.0 for one says it was never up.
    """
    from epic_status.api import _serialise_target

    s = status(Kind.NODE, "a.example")
    s.uptime_1h = 0.9977628635346756
    s.uptime_24h = None
    row = _serialise_target(s)

    assert row["uptime"]["1h"] == 0.9978
    assert row["uptime"]["24h"] is None



# ------------------------------------------------- the header against its columns
#
# Column alignment on this board is structural: the <ul> owns one track list and every
# row and the header subgrid onto it. That only holds while the header emits exactly one
# cell per column, in column order — a header one cell short auto-places every label
# after the gap into the wrong track, and the page still renders, and nothing fails.
#
# It has gone wrong twice: once when a cell was dropped, and once when the per-kind
# `nth-child` alignment lists in app.css were left describing the column order from
# before Version moved into a shared slot. Both were found by screenshotting. These
# assertions are the cheap version of that.

_COLUMNS = 10
"""Tracks declared on `.rows` in app.css: dot, host, m1, m2, m3, location, latency,
24h, recent checks, state.

No eleventh for the expander: `.row-toggle` is absolutely positioned and only becomes
visible on keyboard focus, so it is out of flow and occupies no column. An empty header
cell for it would invent an eleventh implicit track."""


def _header_cells(html: str, group: str) -> list[str]:
    """The header row's direct children, as raw strings, for one table.

    The group class sits on the <section>; the <ul class="rows"> that owns the column
    track list is inside it.
    """
    section = html.split(f"group {group}", 1)[1]
    head = section.split('class="row-head"', 1)[1].split("</li>", 1)[0]
    return [f"<span{part}" for part in head.split("<span")[1:]]


@pytest.mark.parametrize("group", ["group-node", "group-epicbox", "group-pool"])
def test_header_has_one_cell_per_column(snapshot: Snapshot, group: str) -> None:
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    cells = _header_cells(html, group)
    # Each `th()` emits a <span> wrapping a <button>, so the button spans are not cells.
    outer = [c for c in cells if not c.startswith("<span><button")]
    assert len(outer) == _COLUMNS, f"{group} header has {len(outer)} cells, not {_COLUMNS}"


@pytest.mark.parametrize("group", ["group-node", "group-epicbox", "group-pool"])
def test_every_header_cell_after_the_host_carries_an_alignment_class(
    snapshot: Snapshot, group: str
) -> None:
    """A cell with no class gets the browser's default alignment, which is left — and a
    left label over a right-aligned number is the exact defect being fixed. The traffic
    light column is the one exception: it has no header and nothing to align."""
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    for cell in _header_cells(html, group)[1:]:
        if cell.startswith("<span><button"):
            continue
        assert 'class="h-' in cell, f"{group}: unclassed header cell {cell[:60]}"


def test_pools_have_no_version_header(snapshot: Snapshot) -> None:
    """A pool reports no version of its own, so labelling the column made it read as
    missing data. The track stays — Version is column 5 in all three tables — but the
    label goes, and with it the sort button that could not have sorted anything."""
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    pool_head = "".join(_header_cells(html, "group-pool"))
    assert "Version" not in pool_head
    assert '<span class="h-m3"></span>' in pool_head
    # The column itself is still there, in both the header and the rows.
    assert "h-m3" in pool_head
    assert "m3 m-empty" in html


@pytest.mark.parametrize("group", ["group-node", "group-epicbox"])
def test_nodes_and_relays_do_have_a_version_header(snapshot: Snapshot, group: str) -> None:
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert "Version" in "".join(_header_cells(html, group))


def test_capabilities_render_as_words(snapshot: Snapshot) -> None:
    """A published AAAA record that does not answer is a fault, and says so."""
    from epic_status.models import IPv6

    snapshot.nodes[0].ipv6 = IPv6.UNREACHABLE
    snapshot.nodes[0].browser_access = False
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert "AAAA record, not answering" in html
    assert "blocked (CORS)" in html
