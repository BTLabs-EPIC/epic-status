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
    cert_days: int | None,
    thresholds: Thresholds,
) -> tuple[State, Reason, str | None]:
    """The verdict for one relay row."""
    if probe.ok:
        if cert_days is not None and cert_days <= thresholds.cert_warn_days:
            return (
                State.DEGRADED,
                Reason.CERT_EXPIRING,
                f"certificate expires in {cert_days} days",
            )
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
) -> int | None:
    """One number, 0-100, for nodes only.

    Epicbox is deliberately excluded. A dead relay breaks one transport for the
    wallets configured to use it; a forked or stalled chain breaks everything.
    Averaging two failure domains with different blast radii produces a number
    that means nothing in either.
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
        newest = max(versions, key=_version_key)
        version = sum(1 for v in versions if v == newest) / len(versions)
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


def newest_version(statuses: list[TargetStatus]) -> str | None:
    versions = [s.node_version for s in statuses if s.node_version]
    return max(versions, key=_version_key) if versions else None
