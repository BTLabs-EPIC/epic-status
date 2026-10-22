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

_COLUMNS = 11
"""Tracks declared on `.rows` in app.css: dot, host, m1, m2, m3, peers, location,
latency, 24h, recent checks, state.

No twelfth for the expander: `.row-toggle` is absolutely positioned and only becomes
visible on keyboard focus, so it is out of flow and occupies no column. An empty header
cell for it would invent a twelfth implicit track."""


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


def test_an_unconfirmed_failure_is_amber_and_a_confirmed_one_red(snapshot: Snapshot) -> None:
    """One missed answer is not an outage and must not look like one."""
    base = datetime.now(UTC)
    snapshot.nodes[0].history = [
        Check(ok=False, at=base, state=State.DEGRADED),
        Check(ok=False, at=base, state=State.DOWN),
    ]
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert 'class="warn"' in html and "failed, confirming" in html
    assert 'class="bad"' in html


# ------------------------------------------------------------------ source link


def test_footer_links_to_the_public_repository(snapshot: Snapshot) -> None:
    """The footer's Source link once pointed at a misspelt account that does not exist.
    It now comes from `source_url`, and the Run-your-own link goes to the README section
    that explains how."""
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert SETTINGS.source_url == "https://github.com/blacktyger/epic-status"
    assert f'<a href="{SETTINGS.source_url}">Source</a>' in html
    assert f'<a href="{SETTINGS.source_url}#run-your-own-instance">Run your own</a>' in html
    assert "blacktyg3r" not in html
    api = render_api(settings=SETTINGS)
    assert f'href="{SETTINGS.source_url}#run-your-own-instance"' in api


def test_footer_rows_and_the_tor_row_only_off_the_onion(snapshot: Snapshot) -> None:
    """Links, then the Tor mirror, then the credit. The Tor row advertises the onion, so
    the onion itself does not carry it — decided by the request flag, not by a script."""
    from epic_status.web import onion_request

    onion = "t6furoapbsowxp3hvmjwp223zenmauwldfv2noddih7bfuuavwyvaqad.onion"
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert "Also on Tor:" in html
    assert "t6furoapbsow…fuuavwyvaqad.onion" in html
    assert f'data-copy="http://{onion}"' in html
    assert "Created by BT Labs for Epic Cash" in html
    assert html.index('class="foot-nav"') < html.index("Also on Tor:") < html.index("BT Labs")
    assert '<a href="/donate">Donate</a>' in html
    token = onion_request.set(True)
    try:
        on_onion = render_board(snapshot=snapshot, settings=SETTINGS)
    finally:
        onion_request.reset(token)
    assert "Also on Tor" not in on_onion
    assert onion not in on_onion
    assert "Created by BT Labs for Epic Cash" in on_onion


def test_header_mark_is_inline_and_matches_the_favicon(snapshot: Snapshot) -> None:
    """The mark is drawn into the page (an external SVG image did not show on the onion
    for some Tor readers) and uses the same ramp as the icon file the tab shows."""
    html = render_board(snapshot=snapshot, settings=SETTINGS)
    assert '<svg class="brand-mark"' in html
    assert 'class="brand-mark" src=' not in html
    assert 'href="/static/icon' in html


def test_source_url_is_configurable(snapshot: Snapshot) -> None:
    fork = Settings(source_url="https://example.org/fork/epic-status")
    html = render_board(snapshot=snapshot, settings=fork)
    assert '<a href="https://example.org/fork/epic-status">Source</a>' in html


def test_node_status_renders_peers_and_details(snapshot: Snapshot) -> None:
    from epic_status.models import StatusProbe, StatusSource

    ok, down = snapshot.nodes
    ok.peers = 43
    ok.tip_agrees = False
    ok.status_probe = StatusProbe(
        ok=True,
        source=StatusSource.OWNER,
        connections=43,
        user_agent="MW/Epic 4.1.0",
        protocol_version=2,
        sync_status="header_sync",
        height=3_721_000,
        tip_hash="f829" + "0" * 60,
    )
    down.status_probe = StatusProbe(
        ok=False, error="/v1/status: HTTP 401; owner get_status: HTTP 403"
    )
    html = render_board(snapshot=snapshot, settings=SETTINGS)

    row_ok = html.split('id="row-a.example"', 1)[1].split('id="row-b.example"', 1)[0]
    assert 'data-field="peers"' in row_ok and "<em>peers</em>43" in row_ok
    assert "syncing headers" in row_ok
    assert "MW/Epic 4.1.0 · protocol 2" in row_ok
    assert "f829000000…" in row_ok
    assert "differs from other nodes at this height" in row_ok
    assert "total difficulty" not in row_ok
    assert "owner get_status" in row_ok

    row_down = html.split('id="row-b.example"', 1)[1].split("</li>", 1)[0]
    assert "<em>peers</em>—" in row_down
    assert 'title="Status unavailable"' in row_down
    assert "unavailable · /v1/status: HTTP 401; owner get_status: HTTP 403" in html


def test_awaiting_peers_marker_and_sync_line(snapshot: Snapshot) -> None:
    """The marker beside the host, with its sentence, when the node keeps reporting
    `awaiting_peers`; hidden otherwise. The state word is untouched."""
    from epic_status.models import StatusProbe, StatusSource

    ok, down = snapshot.nodes
    ok.tip_lag = 0
    ok.consecutive_failures = 0
    ok.awaiting_peers = True
    ok.status_probe = StatusProbe(
        ok=True, source=StatusSource.V1, connections=38, sync_status="awaiting_peers"
    )
    html = render_board(snapshot=snapshot, settings=SETTINGS)

    row_ok = html.split('id="row-a.example"', 1)[1].split('id="row-b.example"', 1)[0]
    hint = row_ok.split('data-field="peers-hint"', 1)[1].split("</span>\n</span>", 1)[0]
    assert " hidden>" not in hint
    assert 'aria-describedby="ph-a.example"' in hint
    assert "Usually clears within seconds; it is still reachable and at tip." in hint
    assert '<b>waiting for peers</b> · usually clears within seconds' in row_ok
    assert "Online" in row_ok

    row_down = html.split('id="row-b.example"', 1)[1].split("</li>", 1)[0]
    assert 'data-field="peers-hint"' in row_down
    assert row_down.split('data-field="peers-hint"', 1)[1].split(">", 1)[0].endswith(" hidden")


def test_closed_status_api_and_cdn_node_read_as_a_choice_not_as_missing_data(
    snapshot: Snapshot,
) -> None:
    """A node behind Cloudflare whose operator refuses /v1/status and the owner API:
    sync comes from the foreign tip, peers are "not public", and location/network say
    what they are instead of dashes."""
    from epic_status.models import GeoInfo, StatusProbe

    closed, other = snapshot.nodes
    closed.target.geo = GeoInfo(provider="Cloudflare", country="US", asn="AS13335")
    closed.tip_lag = 12
    closed.status_probe = StatusProbe(
        ok=False, closed=True, error="/v1/status: HTTP 403; owner get_status: HTTP 403"
    )
    html = render_board(snapshot=snapshot, settings=SETTINGS)

    row = html.split('id="row-a.example"', 1)[1].split('id="row-b.example"', 1)[0]
    assert "<em>peers</em>not public" in row
    assert "12 behind" in row and "from the foreign API's tip" in row
    assert "status API closed by operator" in row
    assert "behind Cloudflare" in row and row.count("behind Cloudflare") == 2
    assert "not published" in row
    assert "unavailable ·" not in row

    # The other node is unchanged.
    row_other = html.split('id="row-b.example"', 1)[1].split("</li>", 1)[0]
    assert "behind Cloudflare" not in row_other and "not public" not in row_other


def test_derived_sync_at_tip_and_cdn_detection() -> None:
    from epic_status.models import GeoInfo, StatusProbe

    s = status(Kind.NODE, "n.example")
    s.tip_lag = 0
    s.status_probe = StatusProbe(ok=False, closed=True)
    assert s.status_closed and s.derived_sync == "at tip"
    s.tip_lag = 1_204
    assert s.derived_sync == "1,204 behind"
    s.status_probe = StatusProbe(ok=False, closed=False)
    assert not s.status_closed and s.derived_sync is None

    assert GeoInfo(provider="Cloudflare").cdn == "Cloudflare"
    assert GeoInfo(provider="Cloudflare, Inc.").cdn == "Cloudflare"
    assert GeoInfo(provider="Something", asn="AS54113").cdn == "Fastly"
    assert GeoInfo(provider="Hetzner").cdn is None
