"""Version reporting, and the board markup that depends on it.

Every test here pins a defect that shipped. The board used to attach the string
"running 4.0.2, newest is 4.0.3" to lagging nodes only, which produced three
separate problems from one decision:

* a node on the current release had no version shown anywhere, because its version
  only ever appeared as part of a complaint;
* the released version was repeated once per lagging row instead of stated once;
* the sparkline shared a flex line with that string, so its horizontal position
  depended on whether the node was out of date — a node on the latest release drew
  its bar flush left while its neighbours drew theirs mid-row.

The score had a fourth, quieter version of the same mistake: it compared the fleet
against the highest version *seen*, so a fleet uniformly one release behind scored
as unanimous.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from epic_status import releases
from epic_status.config import Settings, Thresholds
from epic_status.models import (
    Check,
    Kind,
    NetworkSummary,
    Source,
    State,
    Target,
    TargetStatus,
)
from epic_status.render import render_board
from epic_status.score import health_score, version_behind

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



THRESHOLDS = Thresholds()


def node(slug: str, *, version: str | None, height: int = 100, lag: int = 0) -> TargetStatus:
    return TargetStatus(
        target=Target(
            kind=Kind.NODE,
            slug=slug,
            endpoint=f"https://{slug}",
            display_host=slug,
            operator="Example",
            source=Source.SEED,
        ),
        state=State.HEALTHY,
        latency_ms=50,
        height=height,
        tip_lag=lag,
        node_version=version,
        history=_checks([True, True, False, True]),
    )


# ------------------------------------------------------------------- the score


def test_uniformly_stale_fleet_is_not_scored_as_unanimous() -> None:
    """The whole point of tracking a released version separately.

    Three nodes all on 4.0.2 agree with each other perfectly. Measured against what
    upstream actually published they are all behind, and the score has to say so —
    otherwise the one metric that exists to catch an unpatched fleet goes quiet
    exactly when the fleet is unpatched.
    """
    fleet = [node(f"n{i}", version="4.0.2") for i in range(3)]

    blind = health_score(fleet, forked=False, thresholds=THRESHOLDS)
    informed = health_score(
        fleet, forked=False, thresholds=THRESHOLDS, released_version="4.0.3"
    )

    assert blind == 100
    assert informed is not None and informed < blind


def test_current_fleet_scores_full_marks() -> None:
    fleet = [node(f"n{i}", version="4.0.3") for i in range(3)]
    assert (
        health_score(fleet, forked=False, thresholds=THRESHOLDS, released_version="4.0.3")
        == 100
    )


def test_missing_released_version_falls_back_to_newest_seen() -> None:
    """Configuration can be absent; a component must not silently zero because of it."""
    fleet = [node("a", version="4.0.3"), node("b", version="4.0.2")]

    fallback = health_score(fleet, forked=False, thresholds=THRESHOLDS)
    explicit = health_score(
        fleet, forked=False, thresholds=THRESHOLDS, released_version="4.0.3"
    )

    assert fallback == explicit


def test_nodes_with_no_version_do_not_drag_the_score() -> None:
    """A closed foreign API answers get_tip but not get_version. That is a
    reachability fact, already counted once as `degraded`, and counting it again as a
    stale version would penalise the same condition twice."""
    fleet = [node("a", version="4.0.3"), node("b", version=None)]
    assert (
        health_score(fleet, forked=False, thresholds=THRESHOLDS, released_version="4.0.3")
        == 100
    )


# ------------------------------------------------------------ released constant


def test_released_constant_is_a_plausible_version() -> None:
    """Mirrored by hand from epic-devhub's versions.js, so the guard is against a
    fat-fingered edit rather than against drift a test could detect."""
    assert releases.NODE.count(".") == 2
    assert all(part.isdigit() for part in releases.NODE.split("."))
    assert releases.NODE in releases.NODE_URL
    assert releases.NODE_URL.startswith("https://github.com/EpicCash/epic/releases/tag/v")


def test_settings_default_to_the_committed_release() -> None:
    assert Settings().released_node_version == releases.NODE


# -------------------------------------------------------------- board markup


def board(nodes: list[TargetStatus], **summary: object) -> str:
    network = NetworkSummary(
        tip_height=100,
        nodes_total=len(nodes),
        nodes_healthy=len(nodes),
        **summary,  # type: ignore[arg-type]
    )
    from epic_status.models import Snapshot
    from datetime import UTC, datetime

    snapshot = Snapshot(
        generated_at=datetime.now(UTC),
        prober_id="test",
        network=network,
        nodes=nodes,
    )
    return render_board(snapshot=snapshot, settings=Settings())


def test_every_node_shows_its_version_even_when_current() -> None:
    html = board(
        [node("current", version="4.0.3"), node("behind", version="4.0.2")],
        released_node_version="4.0.3",
        nodes_versioned=2,
        nodes_current=1,
    )
    assert html.count('data-field="version"') == 2
    assert "4.0.3" in html
    assert "4.0.2" in html


def test_released_version_is_stated_once_not_per_row() -> None:
    html = board(
        [node(f"behind{i}", version="4.0.2") for i in range(3)],
        released_node_version="4.0.3",
        nodes_versioned=3,
        nodes_current=0,
    )
    assert "newest is" not in html
    # Once in the node table's header as `latest: 4.0.3`, and once per row inside the
    # mismatch tooltip. What must not come back is the old sentence repeated in the body of
    # every row. The header states the release and nothing else: it used to add "is current"
    # and a count of how many nodes ran it, both of which the Version column already says.
    assert html.count("is released") == 3
    # Two `.rel` links now: the node release tag and the Epicbox relay repository. Still
    # one per group header, which is the property this test is about — the release is stated
    # once per table, never per row.
    assert html.count('class="rel"') == 2
    assert "latest:" in html
    assert "is current" not in html
    assert "running it" not in html


def test_out_of_date_node_is_marked_without_colour_alone() -> None:
    html = board(
        [node("behind", version="4.0.2")],
        released_node_version="4.0.3",
        nodes_versioned=1,
        nodes_current=0,
    )
    assert "ver-old" in html


def test_current_node_is_not_marked() -> None:
    html = board(
        [node("current", version="4.0.3")],
        released_node_version="4.0.3",
        nodes_versioned=1,
        nodes_current=1,
    )
    assert "ver-old" not in html


def test_sparkline_has_its_own_cell_not_the_reason_line() -> None:
    """The defect that started this: the spark used to be a flex sibling of the
    reason text, so its position moved with the length of a sentence that only
    existed for out-of-date nodes."""
    html = board(
        [node("current", version="4.0.3"), node("behind", version="4.0.2")],
        released_node_version="4.0.3",
        nodes_versioned=2,
        nodes_current=1,
    )
    assert html.count('class="row-spark"') == 2
    # Both rows place it identically; neither nests it inside the reason line.
    assert 'class="row-why"' not in html or html.index("row-spark") < html.index("row-why")


def test_ours_badge_is_gone_and_verified_replaces_it() -> None:
    """`ours` meant "operated by whoever runs this instance", which on a page a stranger
    opened read as *your* node. `verified` says something a reader can act on: an operator
    has checked this host and stands behind it."""
    nodes = [node("mine", version="4.0.3")]
    nodes[0].target.verified = True
    html = board(nodes, released_node_version="4.0.3", nodes_versioned=1, nodes_current=1)
    assert "badge-ours" not in html
    assert ">ours<" not in html
    assert "verified" in html


def test_hosting_is_not_on_the_board() -> None:
    html = board(
        [node("a", version="4.0.3")],
        released_node_version="4.0.3",
        nodes_versioned=1,
        nodes_current=1,
        providers={"Vultr": 4, "Hostinger": 1},
        co_hosted=2,
    )
    assert "Hosting" not in html
    assert "Vultr" not in html


def test_provider_is_not_appended_to_the_operator_line() -> None:
    """The row used to read `btlabs · Hostinger NOC`, putting an infrastructure vendor's name on
    every line of the board for a fact almost nobody came for.

    Narrowed from "Vultr appears nowhere" to "Vultr is not on the operator line", because the
    expandable per-row detail panel now lists it deliberately under `network` — opt-in, behind a
    disclosure, which is the opposite of appending it to every row.
    """
    nodes = [node("a", version="4.0.3")]
    nodes[0].target.geo.provider = "Vultr"
    html = board(nodes, released_node_version="4.0.3", nodes_versioned=1, nodes_current=1)

    operator_line = html[html.index("row-host") : html.index("row-meta")]
    assert "Example" in operator_line
    assert "Vultr" not in operator_line


def test_epicbox_protocol_reaches_the_client_as_an_attribute() -> None:
    """The service's own CSP has no `unsafe-inline`, so a server-rendered constant
    cannot travel in a <script> block. A data attribute is the channel that survives
    it, and app.js reads the released protocol from there."""
    html = board(
        [node("a", version="4.0.3")],
        released_node_version="4.0.3",
        nodes_versioned=1,
        nodes_current=1,
    )
    assert f'data-epicbox-protocol="{releases.EPICBOX_PROTOCOL}"' in html



# ------------------------------------------------- behind, not merely different


def test_ahead_of_the_release_is_not_marked_behind() -> None:
    """Caught by screenshotting the rendered board, not by a unit test.

    `releases.EPICBOX_PROTOCOL` said 3.0.0 while two relays on the network were
    already answering 3.0.1, and an equality test drew "out of date" under a relay
    that was ahead of the published number. A marker that fires on a healthy state
    trains the reader to ignore it.
    """
    assert version_behind("3.0.1", "3.0.0") is False
    assert version_behind("4.1.0", "4.0.3") is False
    assert version_behind("4.0.2", "4.0.3") is True


def test_equal_versions_are_not_behind() -> None:
    assert version_behind("4.0.3", "4.0.3") is False


def test_numeric_not_lexical_ordering() -> None:
    """4.0.10 is newer than 4.0.9, which string comparison gets backwards."""
    assert version_behind("4.0.10", "4.0.9") is False
    assert version_behind("4.0.9", "4.0.10") is True


def test_prerelease_segments_do_not_raise() -> None:
    assert version_behind("4.0.3-rc1", "4.0.3") is False
    assert version_behind("4.0.2-rc1", "4.0.3") is True


def test_absent_version_is_not_behind() -> None:
    """A node with a closed foreign API reports nothing. Nothing is not evidence of
    being out of date, and rendering it as such would invent a finding."""
    assert version_behind(None, "4.0.3") is False
    assert version_behind("4.0.2", None) is False


def test_relay_ahead_of_protocol_renders_unmarked() -> None:
    from epic_status.models import Snapshot
    from datetime import UTC, datetime

    relay = TargetStatus(
        target=Target(
            kind=Kind.EPICBOX,
            slug="relay.example",
            endpoint="wss://relay.example:443/",
            display_host="relay.example",
            operator="Example",
            source=Source.SEED,
        ),
        state=State.HEALTHY,
        latency_ms=400,
        protocol_version="3.0.1",
        cert_expires_in_days=40,
        history=_checks([True, True]),
    )
    html = render_board(
        snapshot=Snapshot(
            generated_at=datetime.now(UTC),
            prober_id="test",
            network=NetworkSummary(tip_height=100),
            epicbox=[relay],
        ),
        settings=Settings(),
    )
    assert "3.0.1" in html
    assert "ver-old" not in html
