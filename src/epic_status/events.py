"""The incident log: turning a sequence of snapshots into a list of things that happened.

A snapshot says what is true now. A reader arriving after an outage wants to know what
was true an hour ago, when it started, and whether it is over — and a feed reader wants
exactly one entry per incident, not one per sweep. This module holds the difference.

**Open and close, not append.** Each condition — a target down, a fork, a stalled chain,
a certificate about to lapse — opens one row when it starts and closes the same row when
it ends. The log therefore has a duration for every incident and a feed has a stable id
per incident.

**Settling before closing.** A host that answers once in the middle of an outage has not
recovered. A condition must stay clear for `settle_s` before its event closes, and the
recorded end is the moment it first cleared — so a flapping host produces one long
incident rather than a dozen short ones, and the duration is still honest.

**Resuming after a restart.** Open events are loaded from the database at start-up, so
a restart during an outage continues the incident instead of opening a duplicate.

Reorgs are the exception: they are instants rather than conditions, reported by
`chain.ChainTracker`, and are written already closed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from .chain import Reorg
from .db import Database
from .models import (
    Chain,
    Event,
    EventKind,
    Kind,
    NetworkSummary,
    Severity,
    State,
    TargetStatus,
)

log = logging.getLogger("epic_status.events")

#: One block is a minute. Fifteen minutes without one has odds of roughly e^-15 under a
#: steady hashrate, so this fires on a real stall and not on bad luck.
STALL_AFTER_S = 900

#: How long a condition must stay clear before its event closes.
SETTLE_S = 60.0

#: How long a target must stay down before its outage is logged. The board goes red at
#: the third failed check; the log waits a minute more, so a host that drops out for one
#: sweep and comes back is a red bar on the board and not an entry in anyone's feed.
#: The entry is backdated to when the target first went down, so its duration is honest.
DOWN_AFTER_S = 60.0

#: Depth at which a reorg stops being routine. One- and two-block reorgs are orphan
#: races, which every proof-of-work chain has; three or more is worth a second look.
DEEP_REORG = 3

_Key = tuple[str, str, str]
"""(chain, kind, subject id) — one open event per key at most."""


@dataclass
class _Open:
    event_id: int
    clear_since: datetime | None = None


class EventTracker:
    def __init__(self, db: Database, prober_id: str, *, cert_warn_days: int) -> None:
        self.db = db
        self.prober_id = prober_id
        self.cert_warn_days = cert_warn_days
        self._open: dict[_Key, _Open] = {}
        self._pending: dict[_Key, datetime] = {}
        """Conditions active but not yet for long enough to be logged, and since when."""
        for event, target_id in db.ongoing_events():
            key = _key(event.chain, event.kind, target_id, "chain")
            self._open[key] = _Open(event.id or 0)

    # ------------------------------------------------------------------ observe

    def observe(
        self,
        chain: Chain,
        statuses: list[TargetStatus],
        summary: NetworkSummary,
        *,
        now: datetime | None = None,
    ) -> None:
        """Open, keep, or settle every condition for one chain after one sweep."""
        now = now or datetime.now(UTC)
        seen: set[_Key] = set()

        for status in statuses:
            target = status.target
            if target.id is None or status.state is State.UNKNOWN:
                continue
            down = self._condition(
                key=_key(chain, EventKind.DOWN, target.id),
                active=status.state is State.DOWN,
                now=now,
                target_id=target.id,
                open_after_s=DOWN_AFTER_S,
                event=Event(
                    chain=chain,
                    kind=EventKind.DOWN,
                    severity=Severity.WARN,
                    subject=status.target.display_host,
                    detail=status.detail or status.last_error,
                    prober_id=self.prober_id,
                    started_at=now,
                ),
            )
            seen.add(down)
            if target.kind is Kind.EPICBOX:
                days = status.cert_expires_in_days
                seen.add(
                    self._condition(
                        key=_key(chain, EventKind.CERT_EXPIRING, target.id),
                        active=days is not None and days <= self.cert_warn_days,
                        now=now,
                        target_id=target.id,
                        # Closes as soon as it is renewed: there is no flapping to
                        # smooth over in a certificate date.
                        settle_s=0.0,
                        event=Event(
                            chain=chain,
                            kind=EventKind.CERT_EXPIRING,
                            severity=Severity.INFO,
                            subject=status.target.display_host,
                            detail=f"TLS certificate expires in {days} days",
                            prober_id=self.prober_id,
                            started_at=now,
                        ),
                    )
                )

        seen.add(
            self._condition(
                key=_key(chain, EventKind.FORK, None, "chain"),
                active=summary.forked,
                now=now,
                event=Event(
                    chain=chain,
                    kind=EventKind.FORK,
                    severity=Severity.BAD,
                    subject=f"{chain.label} chain",
                    detail=summary.fork_detail,
                    prober_id=self.prober_id,
                    started_at=now,
                ),
            )
        )
        stalled = summary.tip_age_s is not None and summary.tip_age_s >= STALL_AFTER_S
        seen.add(
            self._condition(
                key=_key(chain, EventKind.STALL, None, "chain"),
                active=stalled,
                now=now,
                settle_s=0.0,
                event=Event(
                    chain=chain,
                    kind=EventKind.STALL,
                    # A test network is mined when someone is testing. A long gap on
                    # floonet is the normal state of affairs, worth recording and not
                    # worth a red line in anybody's feed.
                    severity=Severity.BAD if chain is Chain.MAINNET else Severity.INFO,
                    subject=f"{chain.label} chain",
                    detail=(
                        f"no new block since height {summary.tip_height:,}"
                        if summary.tip_height is not None
                        else "no new block"
                    ),
                    prober_id=self.prober_id,
                    # When the chain stopped, not when this noticed: the last block's
                    # own timestamp is the start of the stall.
                    started_at=summary.tip_mined_at or now,
                ),
            )
        )

        # A target that left the board — disabled, removed, moved chain — takes its
        # open incidents with it. Left open, they would read as ongoing forever.
        for key in [k for k in self._open if k[0] == chain.value and k not in seen]:
            self.db.close_event(self._open.pop(key).event_id, now)

    def record_reorg(self, reorg: Reorg, *, source: str) -> Event:
        """Write a reorg as an already-closed event."""
        now = datetime.now(UTC)
        depth = f"at least {reorg.depth}" if reorg.depth_is_lower_bound else str(reorg.depth)
        blocks = "block" if reorg.depth == 1 and not reorg.depth_is_lower_bound else "blocks"
        event = Event(
            chain=reorg.chain,
            kind=EventKind.REORG,
            severity=Severity.WARN if reorg.depth >= DEEP_REORG else Severity.INFO,
            subject=f"{reorg.chain.label} chain",
            detail=(
                f"{depth} {blocks} replaced from height {reorg.fork_height:,}"
                f" ({reorg.old_hash[:10]}… → {reorg.new_hash[:10]}…), seen via {source}"
            ),
            depth=reorg.depth,
            prober_id=self.prober_id,
            started_at=now,
            ended_at=now,
        )
        event.id = self.db.open_event(event)
        log.info("reorg on %s: %s", reorg.chain.value, event.detail)
        return event

    # ------------------------------------------------------------------ helpers

    def _condition(
        self,
        *,
        key: _Key,
        active: bool,
        now: datetime,
        event: Event,
        target_id: int | None = None,
        settle_s: float = SETTLE_S,
        open_after_s: float = 0.0,
    ) -> _Key:
        """Open the event if `active` and none is open; otherwise settle and close.

        The event is only written when it opens, so the one passed on every other
        sweep is discarded — constructing it unconditionally keeps each call site a
        single expression instead of a branch.
        """
        current = self._open.get(key)
        if active:
            if current is None:
                since = self._pending.setdefault(key, now)
                if (now - since).total_seconds() < open_after_s:
                    return key
                del self._pending[key]
                if open_after_s:
                    event = event.model_copy(update={"started_at": since})
                self._open[key] = _Open(self.db.open_event(event, target_id))
                log.info("event opened: %s %s", event.kind.value, event.subject)
            else:
                current.clear_since = None
            return key
        self._pending.pop(key, None)
        if current is not None:
            if current.clear_since is None:
                current.clear_since = now
            if (now - current.clear_since).total_seconds() >= settle_s:
                self.db.close_event(current.event_id, current.clear_since)
                del self._open[key]
        return key


def _key(chain: Chain, kind: EventKind, target_id: int | None, subject: str = "") -> _Key:
    return (chain.value, kind.value, str(target_id) if target_id is not None else subject)
