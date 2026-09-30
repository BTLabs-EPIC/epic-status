"""Turning probe results into the three states and the one number.

Two pieces of judgement live here and both are worth arguing with.

**Why three states.** A two-state light is wrong in three common situations, all
of them visible to the operators being reported on: a node whose foreign API needs
credentials is up and in consensus but unpollable; a node 5,000 blocks behind
answers `get_tip` flawlessly; and a probe that failed from *our* host is not proof
of anything about theirs. Amber is not hedging, it is the only honest bucket for
those.

**Why fork detection waits.** Two nodes reporting the same height with different
tip hashes genuinely hold different blocks at that height — but that is also what a
normal orphan race looks like for a few seconds on any proof-of-work chain. A
status page for a small PoW coin announcing a fork every time a block is orphaned
would be worse than useless; it would cause the panic it is meant to detect. So a
conflict has to persist across consecutive sweeps before it is called a fork, and
below that threshold it is reported as a reorg in progress.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from .config import Thresholds
from .models import (
    EpicboxProbe,
    Kind,
    NodeProbe,
    PoolProbe,
    Reason,
    State,
    Target,
    TargetStatus,
)


def fleet_tip(probes: dict[str, NodeProbe]) -> int | None:
    """The highest height any node reported this sweep.

    The *highest*, not the median or the mode. A node's job is to have the tip; a
    single node that is ahead is a node that is working, and comparing against a
    consensus average would let a slow majority define correctness.
    """
    heights = [p.height for p in probes.values() if p.ok and p.height is not None]
    return max(heights) if heights else None


@dataclass
class ForkDetector:
    """Stateful because a single sweep cannot distinguish a fork from an orphan.

    Keyed by (height, frozenset of conflicting hashes) so that a *different*
    conflict appearing next sweep resets the count rather than accumulating
    towards a false positive.
    """

    confirmations_required: int = 3
    _last_key: tuple[int, frozenset[str]] | None = field(default=None, init=False)
    _count: int = field(default=0, init=False)

    def observe(self, probes: dict[str, NodeProbe]) -> tuple[bool, str | None]:
        by_height: dict[int, set[str]] = {}
        for probe in probes.values():
            if probe.ok and probe.height is not None and probe.tip_hash:
                by_height.setdefault(probe.height, set()).add(probe.tip_hash)

        conflicts = {h: hashes for h, hashes in by_height.items() if len(hashes) > 1}
        if not conflicts:
            self._last_key = None
            self._count = 0
            return False, None

        height = max(conflicts)
        key = (height, frozenset(conflicts[height]))
        if key == self._last_key:
            self._count += 1
        else:
            self._last_key = key
            self._count = 1

        detail = (
            f"{len(conflicts[height])} different blocks reported at height {height:,}"
        )
        if self._count >= self.confirmations_required:
            return True, detail
        return False, f"reorg in progress — {detail}"


def node_state(
    target: Target,
    probe: NodeProbe,
    *,
    tip: int | None,
    consecutive_failures: int,
    thresholds: Thresholds,
    p2p_alive: bool | None = None,
) -> tuple[State, Reason, str | None]:
    """The verdict for one node row."""

    if probe.ok:
        if probe.reason is Reason.TLS:
            # Serving the chain correctly over a certificate that does not verify.
            # Up, and worth telling the operator about.
            return State.DEGRADED, Reason.TLS, "reachable, TLS certificate not valid"

        if tip is not None and probe.height is not None:
            lag = tip - probe.height
            if lag >= thresholds.tip_lag_down:
                return (
                    State.DOWN,
                    Reason.TIP_LAG,
                    f"{lag:,} blocks behind — not following this chain",
                )
            if lag > thresholds.tip_lag_healthy:
                return (
                    State.DEGRADED,
                    Reason.TIP_LAG,
                    f"{lag:,} blocks behind the network tip",
                )
        return State.HEALTHY, Reason.OK, None

    if probe.reason is Reason.API_RESTRICTED:
        # The single most common non-success, and the one most likely to generate a
        # complaint if handled as an outage. If P2P answers, we know it is running.
        if p2p_alive:
            return (
                State.DEGRADED,
                Reason.API_RESTRICTED,
                "running — public API requires credentials",
            )
        return (
            State.DEGRADED,
            Reason.API_RESTRICTED,
            "public API requires credentials, P2P not verified",
        )

    if p2p_alive:
        return (
            State.DEGRADED,
            Reason.P2P_ONLY,
            "P2P port answers, HTTP API does not",
        )

    if consecutive_failures < thresholds.down_after_failures:
        # One dropped packet is not an outage. At a five-second cadence this window
        # is fifteen seconds, which is short enough to stay useful and long enough
        # to stop a single lost SYN turning a row red.
        return (
            State.DEGRADED,
            probe.reason,
            probe.error or "not responding — confirming",
        )

    return State.DOWN, probe.reason, probe.error


def epicbox_state(
    probe: EpicboxProbe,
    *,
    consecutive_failures: int,
    thresholds: Thresholds,
) -> tuple[State, Reason, str | None]:
    """The verdict for one relay row: did the relay serve a wallet, or not.

    **Certificate expiry is deliberately not a state here, and used to be.** A relay
    inside the warning window was returned as amber with the detail "certificate
    expires in 14 days", which was wrong in both directions at once. It painted a
    relay that had just completed a websocket handshake and sent its challenge frame
    as impaired, on the strength of something that has not happened yet and that in
    the overwhelming majority of cases never will — the operator's renewal runs and
    the row silently goes green again. Meanwhile it bought nothing on the day the
    certificate actually lapses: an expired certificate fails verification, so the
    probe fails, and the ordinary confirm-then-fail path below takes the row to red
    without any help from a cert threshold. Amber was therefore only ever shown while
    the relay was fine, and never when it broke.

    Expiry is a maintenance fact with a future date attached, which is a different
    kind of claim from "this endpoint is not serving right now". It is published as a
    marker on the TLS column with the day count in its tooltip, where a reader who
    cares can see it and a reader choosing a relay is not warned off a working one.
    `Thresholds.cert_warn_days` still decides when that marker appears; it is consumed
    by the view now rather than here.
    """
    if probe.ok:
        return State.HEALTHY, Reason.OK, None

    if consecutive_failures < thresholds.down_after_failures:
        return State.DEGRADED, probe.reason, probe.error or "not responding — confirming"
    return State.DOWN, probe.reason, probe.error


def pool_state(
    probe: PoolProbe,
    *,
    consecutive_failures: int,
    thresholds: Thresholds,
) -> tuple[State, Reason, str | None]:
    """The verdict for one pool row: reachable, with a parseable stats payload.

    Deliberately no chain-lag check, and no staleness check on the last block
    found. The tempting version of this function compares the pool's block height
    to the fleet tip and degrades the laggard — but the pools' `currentHeight` is
    the last block they *found*, not their node's tip (see probes.pool), and the
    expected gap is inversely proportional to the pool's share of the network.
    Applying it marked a healthy nine-miner pool degraded next to a healthy
    hundred-miner one, which is a red light for being small.

    Time since the last block has the same defect for the same reason: eighteen
    minutes is alarming for the largest pool and unremarkable for the smallest, and
    this service does not know either one's hashrate share. It is published as a
    fact for a reader to interpret, and no threshold is applied to it.
    """
    if probe.ok:
        return State.HEALTHY, Reason.OK, None

    if consecutive_failures < thresholds.down_after_failures:
        return State.DEGRADED, probe.reason, probe.error or "not responding — confirming"
    return State.DOWN, probe.reason, probe.error


# ------------------------------------------------------------------------- score


def _latency_points(latencies: list[int]) -> float:
    """Latency scored on a curve that flattens past a second.

    Linear scoring lets one distant node dominate a fleet-wide number, and the
    difference between 40 ms and 90 ms is invisible to a user while the difference
    between 200 ms and 2,000 ms is not.
    """
    if not latencies:
        return 0.0
    median = statistics.median(latencies)
    if median <= 150:
        return 1.0
    if median >= 3000:
        return 0.0
    # 150 ms scores 1.0, 3,000 ms scores 0.0, logarithmic in between.
    import math

    return max(0.0, 1.0 - math.log10(median / 150) / math.log10(3000 / 150))


def health_score(
    statuses: list[TargetStatus],
    *,
    forked: bool,
    thresholds: Thresholds,
    released_version: str | None = None,
) -> int | None:
    """One number, 0-100, for nodes only.

    Epicbox and pools are deliberately excluded. A dead relay breaks one transport
    for the wallets configured to use it, and a dead pool costs its own miners;
    a forked or stalled chain breaks everything. Averaging failure domains with
    different blast radii produces a number that means nothing in any of them.

    `released_version` is what upstream has published. When it is known the version
    component measures the fleet against *that*; without it the best available
    comparison is the highest version seen, which scores a uniformly stale fleet as
    perfect. The fallback is kept because the published version is configuration and
    can be absent, and a missing constant must not silently zero a component.
    """
    nodes = [s for s in statuses if s.target.kind is Kind.NODE]
    if not nodes:
        return None

    # Reachability counts amber as a half. A node with a private API is
    # participating in consensus even though we cannot see it, and scoring it zero
    # would make a well-run private-API fleet look like an outage.
    reach = sum(
        1.0 if s.state is State.HEALTHY else 0.5 if s.state is State.DEGRADED else 0.0
        for s in nodes
    ) / len(nodes)

    visible = [s for s in nodes if s.height is not None]
    if visible:
        agreeing = sum(
            1
            for s in visible
            if s.tip_lag is not None and s.tip_lag <= thresholds.tip_lag_healthy
        )
        agreement = agreeing / len(visible)
    else:
        # Nothing to compare. Not scored as disagreement — that would report a
        # monitoring failure as a consensus failure.
        agreement = reach

    latencies = [s.latency_ms for s in nodes if s.latency_ms is not None]
    latency = _latency_points(latencies)

    versions = [s.node_version for s in nodes if s.node_version]
    if versions:
        # Against the published release when it is known, so a fleet that is
        # uniformly one release behind scores as uniformly behind rather than as
        # unanimous. `max()` is the fallback, not the intent.
        target = released_version or max(versions, key=_version_key)
        version = sum(1 for v in versions if v == target) / len(versions)
    else:
        version = 1.0

    score = 100.0 * (
        0.40 * reach + 0.35 * agreement + 0.15 * latency + 0.10 * version
    )
    if forked:
        # Flat and large. A public fork on a small proof-of-work chain matters more
        # than every other input combined, and a percentage penalty would let a
        # healthy fleet mask it.
        score -= 25.0
    return max(0, min(100, round(score)))


def _version_key(version: str) -> tuple[int, ...]:
    """Sort versions numerically so 4.0.10 beats 4.0.9.

    Non-numeric parts sort as 0 rather than raising: a node reporting
    "4.0.3-beta" must not break the comparison for the whole fleet.
    """
    parts: list[int] = []
    for chunk in version.replace("-", ".").split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def version_behind(reported: str | None, released: str | None) -> bool:
    """True only when `reported` is strictly older than `released`.

    Equality is not the test, and this is not pedantry: the released Epicbox protocol
    constant said 3.0.0 while two relays on the network were already answering 3.0.1,
    so a `!=` comparison drew "out of date" under a relay that was ahead of the
    published number. Being ahead of a release is a normal state for an operator
    running a build from master, and flagging it teaches readers to ignore the marker.

    Unparseable segments sort as 0 rather than raising, the same rule the score uses,
    so a node reporting "4.0.3-rc1" compares as 4.0.3.0 instead of breaking the row.
    """
    if not reported or not released:
        return False
    return _version_key(reported) < _version_key(released)
