"""The incident log: one row per incident, settled before it closes, resumed on restart."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from epic_status.chain import Reorg
from epic_status.db import Database
from epic_status.events import SETTLE_S, STALL_AFTER_S, EventTracker
from epic_status.models import (
    Chain,
    EventKind,
    Kind,
    NetworkSummary,
    Severity,
    Source,
    State,
    Target,
    TargetStatus,
)

T0 = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def _status(db: Database, state: State, *, kind: Kind = Kind.NODE, **fields: object) -> TargetStatus:
    target = Target(
        kind=kind,
        slug=f"{kind.value}.example.org",
        endpoint=f"https://{kind.value}.example.org",
        display_host=f"{kind.value}.example.org",
        source=Source.SEED,
    )
    target.id = db.insert_target(target)
    return TargetStatus(target=target, state=state, last_error="timed out", **fields)  # type: ignore[arg-type]


def _tracker(db: Database) -> EventTracker:
    return EventTracker(db, "test", cert_warn_days=14)


SUMMARY = NetworkSummary(chain=Chain.MAINNET, tip_height=100, tip_age_s=30)


def test_a_down_target_opens_one_event_not_one_per_sweep(db: Database) -> None:
    tracker = _tracker(db)
    down = _status(db, State.DOWN)
    for i in range(5):
        tracker.observe(Chain.MAINNET, [down], SUMMARY, now=T0 + timedelta(seconds=5 * i))

    events = db.events(Chain.MAINNET)
    assert len(events) == 1
    assert events[0].kind is EventKind.DOWN
    assert events[0].ongoing
    assert events[0].subject == "node.example.org"
    assert events[0].target_slug == "node.example.org"


def test_recovery_settles_before_closing_and_ends_when_it_first_cleared(
    db: Database,
) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=T0)

    healthy = status.model_copy(update={"state": State.HEALTHY})
    cleared = T0 + timedelta(seconds=30)
    tracker.observe(Chain.MAINNET, [healthy], SUMMARY, now=cleared)
    assert db.events(Chain.MAINNET)[0].ongoing

    tracker.observe(
        Chain.MAINNET, [healthy], SUMMARY, now=cleared + timedelta(seconds=SETTLE_S)
    )
    event = db.events(Chain.MAINNET)[0]
    assert not event.ongoing
    assert event.ended_at == cleared


def test_a_flap_inside_the_settle_window_is_the_same_incident(db: Database) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    healthy = status.model_copy(update={"state": State.HEALTHY})
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=T0)
    tracker.observe(Chain.MAINNET, [healthy], SUMMARY, now=T0 + timedelta(seconds=10))
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=T0 + timedelta(seconds=20))

    assert len(db.events(Chain.MAINNET)) == 1


def test_a_restart_resumes_the_open_incident(db: Database) -> None:
    status = _status(db, State.DOWN)
    _tracker(db).observe(Chain.MAINNET, [status], SUMMARY, now=T0)

    _tracker(db).observe(Chain.MAINNET, [status], SUMMARY, now=T0 + timedelta(minutes=5))

    assert len(db.events(Chain.MAINNET)) == 1


def test_a_target_leaving_the_board_closes_its_incident(db: Database) -> None:
    tracker = _tracker(db)
    tracker.observe(Chain.MAINNET, [_status(db, State.DOWN)], SUMMARY, now=T0)
    tracker.observe(Chain.MAINNET, [], SUMMARY, now=T0 + timedelta(seconds=5))

    assert not db.events(Chain.MAINNET)[0].ongoing


def test_a_stall_starts_when_the_last_block_was_mined(db: Database) -> None:
    mined = T0 - timedelta(seconds=STALL_AFTER_S + 60)
    stalled = NetworkSummary(
        chain=Chain.MAINNET, tip_height=100, tip_age_s=STALL_AFTER_S + 60, tip_mined_at=mined
    )
    _tracker(db).observe(Chain.MAINNET, [], stalled, now=T0)

    event = db.events(Chain.MAINNET)[0]
    assert event.kind is EventKind.STALL
    assert event.severity is Severity.BAD
    assert event.started_at == mined


def test_cert_expiry_is_an_info_event_on_relays(db: Database) -> None:
    relay = _status(db, State.HEALTHY, kind=Kind.EPICBOX, cert_expires_in_days=5)
    _tracker(db).observe(Chain.MAINNET, [relay], SUMMARY, now=T0)

    event = db.events(Chain.MAINNET)[0]
    assert event.kind is EventKind.CERT_EXPIRING
    assert event.severity is Severity.INFO
    assert db.events(Chain.MAINNET, min_severity=Severity.WARN) == []


def test_a_reorg_is_written_closed_with_its_depth(db: Database) -> None:
    reorg = Reorg(
        chain=Chain.MAINNET,
        fork_height=98,
        depth=3,
        depth_is_lower_bound=False,
        old_hash="a" * 64,
        new_hash="b" * 64,
        tip_height=101,
    )
    _tracker(db).record_reorg(reorg, source="node.example.org")

    event = db.events(Chain.MAINNET)[0]
    assert event.kind is EventKind.REORG
    assert event.depth == 3
    assert event.severity is Severity.WARN
    assert not event.ongoing
    assert "3 blocks replaced from height 98" in (event.detail or "")
