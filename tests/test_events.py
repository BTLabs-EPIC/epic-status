"""The incident log: one row per incident, settled before it closes, resumed on restart."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from epic_status.chain import Reorg
from epic_status.db import Database
from epic_status.events import DOWN_AFTER_S, SETTLE_S, STALL_AFTER_S, EventTracker
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


def _down_long_enough(tracker: EventTracker, statuses: list[TargetStatus], start: datetime) -> None:
    """Observe a sweep at `start` and again once DOWN_AFTER_S has passed."""
    tracker.observe(Chain.MAINNET, statuses, SUMMARY, now=start)
    tracker.observe(
        Chain.MAINNET, statuses, SUMMARY, now=start + timedelta(seconds=DOWN_AFTER_S)
    )


def test_a_down_target_opens_one_event_not_one_per_sweep(db: Database) -> None:
    tracker = _tracker(db)
    down = _status(db, State.DOWN)
    for i in range(20):
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
    _down_long_enough(tracker, [status], T0)

    healthy = status.model_copy(update={"state": State.HEALTHY})
    cleared = T0 + timedelta(seconds=DOWN_AFTER_S + 30)
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
    _down_long_enough(tracker, [status], T0)
    later = T0 + timedelta(seconds=DOWN_AFTER_S)
    tracker.observe(Chain.MAINNET, [healthy], SUMMARY, now=later + timedelta(seconds=10))
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=later + timedelta(seconds=20))

    assert len(db.events(Chain.MAINNET)) == 1


def test_a_restart_resumes_the_open_incident(db: Database) -> None:
    status = _status(db, State.DOWN)
    _down_long_enough(_tracker(db), [status], T0)

    _tracker(db).observe(Chain.MAINNET, [status], SUMMARY, now=T0 + timedelta(minutes=5))

    assert len(db.events(Chain.MAINNET)) == 1


def test_a_target_leaving_the_board_closes_its_incident(db: Database) -> None:
    tracker = _tracker(db)
    _down_long_enough(tracker, [_status(db, State.DOWN)], T0)
    tracker.observe(Chain.MAINNET, [], SUMMARY, now=T0 + timedelta(seconds=DOWN_AFTER_S + 5))

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


def test_a_floonet_stall_is_only_informational(db: Database) -> None:
    stalled = NetworkSummary(
        chain=Chain.FLOONET, tip_height=10, tip_age_s=STALL_AFTER_S * 10, tip_mined_at=T0
    )
    _tracker(db).observe(Chain.FLOONET, [], stalled, now=T0)
    assert db.events(Chain.FLOONET)[0].severity is Severity.INFO


def test_a_short_outage_never_reaches_the_log(db: Database) -> None:
    """Red on the board for half a minute, nothing in the feed."""
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=T0)
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=T0 + timedelta(seconds=30))
    healthy = status.model_copy(update={"state": State.HEALTHY})
    tracker.observe(Chain.MAINNET, [healthy], SUMMARY, now=T0 + timedelta(seconds=35))
    tracker.observe(Chain.MAINNET, [status], SUMMARY, now=T0 + timedelta(seconds=40))

    assert db.events(Chain.MAINNET) == []


def test_a_logged_outage_starts_when_it_began(db: Database) -> None:
    tracker = _tracker(db)
    _down_long_enough(tracker, [_status(db, State.DOWN)], T0)
    assert db.events(Chain.MAINNET)[0].started_at == T0


# ------------------------------------------------------- one line per source per day


def _reorg(depth: int, chain: Chain = Chain.FLOONET) -> Reorg:
    return Reorg(
        chain=chain,
        fork_height=1000,
        depth=depth,
        depth_is_lower_bound=False,
        old_hash="a" * 64,
        new_hash="b" * 64,
        tip_height=1001,
    )


def _outage(
    tracker: EventTracker, status: TargetStatus, start: datetime, down_for_s: float
) -> datetime:
    """One logged outage from `start`, cleared after `down_for_s` and settled.
    Returns the moment it cleared, which is the recorded end."""
    healthy = status.model_copy(update={"state": State.HEALTHY})
    _down_long_enough(tracker, [status], start)
    cleared = start + timedelta(seconds=down_for_s)
    tracker.observe(Chain.MAINNET, [healthy], SUMMARY, now=cleared)
    tracker.observe(
        Chain.MAINNET, [healthy], SUMMARY, now=cleared + timedelta(seconds=SETTLE_S)
    )
    return cleared


def test_repeat_outages_inside_a_day_are_one_entry_with_a_count(db: Database) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    ends = [
        _outage(tracker, status, T0 + timedelta(hours=h), down_for_s=120 + 60 * h)
        for h in range(7)
    ]

    events = db.events(Chain.MAINNET)
    assert len(events) == 1
    event = events[0]
    assert event.occurrences == 7
    assert event.started_at == T0
    assert event.last_started_at == T0 + timedelta(hours=6)
    assert event.ended_at == ends[-1]
    assert not event.ongoing
    # 120 + 180 + ... + 480 seconds: each outage's own length, gaps excluded.
    assert event.active_s == sum(120 + 60 * h for h in range(7))
    assert event.last_duration_s == 480


def test_every_occurrence_is_kept(db: Database) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    for h in range(3):
        _outage(tracker, status, T0 + timedelta(hours=h), down_for_s=300)

    event = db.events(Chain.MAINNET)[0]
    assert event.id is not None
    times = db.occurrence_times([event.id])[event.id]
    assert [start for start, _ in times] == [T0 + timedelta(hours=h) for h in (2, 1, 0)]
    assert all(end is not None for _, end in times)


def test_a_repeat_after_the_window_opens_a_new_entry(db: Database) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    _outage(tracker, status, T0, down_for_s=300)
    _outage(tracker, status, T0 + timedelta(hours=23), down_for_s=300)
    # Twenty-four hours after the *first* occurrence, not the latest: the bound on
    # one entry per rolling day depends on anchoring there.
    _outage(tracker, status, T0 + timedelta(hours=24, minutes=1), down_for_s=300)

    events = db.events(Chain.MAINNET)
    assert [e.occurrences for e in events] == [1, 2]
    assert events[0].started_at == T0 + timedelta(hours=24, minutes=1)
    assert (events[0].started_at - events[1].started_at) >= timedelta(hours=24)


def test_down_up_down_reopens_the_same_entry_as_ongoing(db: Database) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    _outage(tracker, status, T0, down_for_s=300)
    first = db.events(Chain.MAINNET)[0]
    assert not first.ongoing

    again = T0 + timedelta(hours=1)
    _down_long_enough(tracker, [status], again)

    events = db.events(Chain.MAINNET)
    assert len(events) == 1
    assert events[0].id == first.id
    assert events[0].ongoing
    assert events[0].occurrences == 2
    assert events[0].last_started_at == again
    # The closed occurrence is counted; the running one is added only in the total.
    assert events[0].active_s == 300
    assert events[0].active_total_s >= 300


def test_active_time_accumulates_on_close(db: Database) -> None:
    tracker = _tracker(db)
    status = _status(db, State.DOWN)
    _outage(tracker, status, T0, down_for_s=200)
    _outage(tracker, status, T0 + timedelta(hours=2), down_for_s=400)

    event = db.events(Chain.MAINNET)[0]
    assert event.active_s == 600
    assert event.active_total_s == 600


def test_a_restart_mid_repeat_does_not_duplicate(db: Database) -> None:
    status = _status(db, State.DOWN)
    first = _tracker(db)
    _outage(first, status, T0, down_for_s=300)
    _down_long_enough(first, [status], T0 + timedelta(hours=1))

    second = _tracker(db)
    second.observe(Chain.MAINNET, [status], SUMMARY, now=T0 + timedelta(hours=1, minutes=5))
    assert len(db.ongoing_events()) == 1
    healthy = status.model_copy(update={"state": State.HEALTHY})
    cleared = T0 + timedelta(hours=1, minutes=10)
    second.observe(Chain.MAINNET, [healthy], SUMMARY, now=cleared)
    second.observe(Chain.MAINNET, [healthy], SUMMARY, now=cleared + timedelta(seconds=SETTLE_S))

    events = db.events(Chain.MAINNET)
    assert len(events) == 1
    assert events[0].occurrences == 2
    assert events[0].ended_at == cleared
    assert db.ongoing_events() == []


def test_reorgs_fold_with_a_count_and_stay_instants(db: Database) -> None:
    tracker = _tracker(db)
    for i in range(5):
        tracker.record_reorg(_reorg(1), source="n", now=T0 + timedelta(hours=i))

    events = db.events(Chain.FLOONET)
    assert len(events) == 1
    event = events[0]
    assert event.occurrences == 5
    assert event.kind is EventKind.REORG
    assert not event.ongoing
    assert event.ended_at == T0 + timedelta(hours=4)
    # The chain panel still counts each reorg, not each row.
    assert db.reorg_depths_since(Chain.FLOONET, T0 - timedelta(hours=1)) == [1] * 5


def test_a_deeper_reorg_escalates_the_entry(db: Database) -> None:
    tracker = _tracker(db)
    tracker.record_reorg(_reorg(1), source="n", now=T0)
    tracker.record_reorg(_reorg(4), source="n", now=T0 + timedelta(hours=1))
    tracker.record_reorg(_reorg(2), source="n", now=T0 + timedelta(hours=2))

    event = db.events(Chain.FLOONET)[0]
    assert event.occurrences == 3
    assert event.severity is Severity.WARN
    assert event.depth == 4
    # The detail is the latest occurrence's; the worst is kept in severity and depth.
    assert "2 blocks replaced" in (event.detail or "")
    assert db.events(Chain.FLOONET, min_severity=Severity.WARN)[0].id == event.id


def test_different_sources_and_kinds_do_not_fold(db: Database) -> None:
    tracker = _tracker(db)
    tracker.record_reorg(_reorg(1, Chain.FLOONET), source="n", now=T0)
    tracker.record_reorg(_reorg(1, Chain.MAINNET), source="n", now=T0)
    node = _status(db, State.DOWN)
    relay = _status(db, State.DOWN, kind=Kind.EPICBOX)
    _down_long_enough(tracker, [node, relay], T0)

    assert len(db.events(Chain.FLOONET)) == 1
    mainnet = db.events(Chain.MAINNET)
    assert sorted((e.kind.value, e.subject) for e in mainnet) == [
        ("down", "epicbox.example.org"),
        ("down", "node.example.org"),
        ("reorg", "Mainnet chain"),
    ]
    assert all(e.occurrences == 1 for e in mainnet)


def test_a_recurring_entry_sorts_by_its_latest_occurrence(db: Database) -> None:
    tracker = _tracker(db)
    node = _status(db, State.DOWN)
    _outage(tracker, node, T0, down_for_s=120)
    tracker.record_reorg(_reorg(1, Chain.MAINNET), source="n", now=T0 + timedelta(hours=1))
    _outage(tracker, node, T0 + timedelta(hours=2), down_for_s=120)

    assert [e.kind for e in db.events(Chain.MAINNET)] == [EventKind.DOWN, EventKind.REORG]
