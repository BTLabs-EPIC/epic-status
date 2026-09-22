"""The poller.

One sweep every five seconds for nodes, with the slower probes folded in on their
own schedules, all inside a single asyncio task. Everything writes `checks` rows
and then rebuilds an in-memory snapshot that the web layer serves without touching
the database.

The architectural point, which is the one thing that must not be got wrong:
**nothing probes on page load.** The Epicbox relays already demonstrate the
failure — rendering their own status page fires three outbound TLS connections to
other relays, so every visitor amplifies. A status page that fans out per request
turns a traffic spike into a distributed attack on exactly the hosts it exists to
help. One poller writes state; every visitor reads a cached snapshot.

Why a resident loop rather than a systemd timer: sub-minute granularity on a
five-second cadence means spawning a process 17,000 times a day, and the web
process is resident anyway. Concurrency is bounded and each probe carries its own
timeout, so a hung third-party host cannot stall the sweep.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta

import httpx

from .config import Settings
from .db import Database, parse_iso
from .geo import lookup as geo_lookup
from .geo import merge as geo_merge
from .models import (
    EpicboxProbe,
    GeoInfo,
    Kind,
    NetworkSummary,
    NodeProbe,
    Reason,
    Snapshot,
    State,
    Target,
    TargetStatus,
)
from .net import (
    Resolved,
    TargetRejected,
    build_client,
    peer_certificate_expiry,
    resolve_endpoint,
    tcp_probe,
)
from .probes.epicbox import probe_relay
from .probes.node import probe_tip, probe_tip_age, probe_version
from .score import (
    ForkDetector,
    epicbox_state,
    fleet_tip,
    health_score,
    newest_version,
    node_state,
)

log = logging.getLogger("epic_status.poller")

_RESOLVE_TTL_S = 300.0
"""How long a validated address is reused. Long enough that the sweep is not a
DNS flood, short enough that a legitimate DNS change is picked up within minutes.
Safe at any length, because the connection always goes to the address that was
validated rather than to a freshly resolved one."""

_UPTIME_TTL_S = 60.0
"""Uptime percentages move slowly; recomputing them 17,000 times a day would be
the most expensive query in the system for no visible benefit."""

_GEO_PER_SWEEP = 2
"""Enrichment lookups per sweep. On a cold start every target is due at once, and
the RDAP bootstrap service answers 429 to a burst of a dozen."""

_GEO_RETRY_S = 3600.0
"""Retry interval after a rate-limited or failed lookup — an hour, not the weekly
refresh interval, so one 429 does not cost a target its provider for a week."""


class Poller:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.snapshot: Snapshot | None = None
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._fork = ForkDetector(
            confirmations_required=settings.thresholds.down_after_failures
        )

        self._client: httpx.AsyncClient | None = None
        self._insecure: httpx.AsyncClient | None = None

        self._resolved: dict[str, tuple[float, Resolved | TargetRejected]] = {}
        self._uptime: dict[int, tuple[float, tuple[float | None, float | None, float | None]]] = {}
        self._next_version: dict[int, float] = {}
        self._next_header: dict[int, float] = {}
        self._next_p2p: dict[int, float] = {}
        self._next_cert: dict[int, float] = {}
        self._next_epicbox: dict[int, float] = {}
        self._next_geo: dict[int, float] = {}
        self._p2p_alive: dict[int, bool] = {}
        self._cert_days: dict[int, int | None] = {}
        self._last_epicbox: dict[int, tuple[float, EpicboxProbe]] = {}
        self._relay_persisted: dict[int, float] = {}
        self._tip_age: tuple[float, datetime] | None = None
        self._next_prune = 0.0
        self._background: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------ lifecycle

    async def __aenter__(self) -> Poller:
        self._client = build_client(timeout=self.settings.http_timeout_s)
        self._insecure = build_client(
            timeout=self.settings.http_timeout_s, verify=False
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        # Cancel enrichment in flight before the clients close under it, otherwise
        # shutdown logs a spray of "client has been closed" errors that look like a
        # fault and are not one.
        for task in list(self._background):
            task.cancel()
        if self._background:
            await asyncio.gather(*self._background, return_exceptions=True)
        for client in (self._client, self._insecure):
            if client is not None:
                await client.aclose()

    async def run(self) -> None:
        """Sweep forever. A failure in one sweep must never end the loop — the
        process staying up with a stale snapshot, clearly labelled stale, beats the
        process exiting and the page 502-ing."""
        while True:
            started = asyncio.get_running_loop().time()
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("sweep failed")
            elapsed = asyncio.get_running_loop().time() - started
            await asyncio.sleep(max(0.5, self.settings.cadence.node_tip_s - elapsed))

    # --------------------------------------------------------------------- sweep

    async def sweep(self) -> None:
        """One tick. Must stay bounded by the slowest *tip* probe, nothing else.

        The slow enrichment passes — versions, tip age, P2P fallback, certificates,
        RDAP — are fired as background tasks rather than awaited. Awaiting them made
        a sweep take twenty seconds on a cold start against four unreachable seeds,
        which delayed every healthy row's update behind hosts that were never going
        to answer. They write into state that the next sweep reads, so being a tick
        behind costs nothing: none of them changes on a five-second timescale.
        """
        now = asyncio.get_running_loop().time()
        targets = self.db.targets()
        nodes = [t for t in targets if t.kind is Kind.NODE]
        relays = [t for t in targets if t.kind is Kind.EPICBOX]

        node_probes = dict(await asyncio.gather(*(self._probe_node(t) for t in nodes)))

        # Relays are polled on their own slower cadence, so most sweeps reuse the
        # previous result rather than opening a new connection.
        relay_probes = dict(
            await asyncio.gather(*(self._probe_relay_if_due(t, now) for t in relays))
        )

        tip = fleet_tip(node_probes)
        forked, fork_detail = self._fork.observe(node_probes)

        self._spawn(self._refresh_versions(nodes, node_probes, now))
        self._spawn(self._refresh_tip_age(nodes, node_probes, tip, now))
        self._spawn(self._refresh_p2p(nodes, node_probes, now))
        self._spawn(self._refresh_certs(relays, now))
        self._spawn(self._refresh_geo(targets, now))

        node_statuses = [self._node_status(t, node_probes[t.slug], tip) for t in nodes]
        relay_statuses = [self._relay_status(t, relay_probes[t.slug]) for t in relays]

        self._persist(node_statuses, node_probes)
        self._persist_relays(relay_statuses, relay_probes)
        self._reap(node_statuses + relay_statuses)

        for status in node_statuses + relay_statuses:
            self._attach_history(status)

        self.snapshot = self._build_snapshot(
            node_statuses, relay_statuses, tip, forked, fork_detail
        )

        if now >= self._next_prune:
            removed = self.db.prune(self.settings.keep_success_days)
            if removed:
                log.info("pruned %d old successful checks", removed)
            self._next_prune = now + 3600.0

    def _spawn(self, coro: Coroutine[object, object, None]) -> None:
        """Fire a background refresh, at most one of each kind at a time.

        The `_next_*` gates already prevent a second run from doing any work, but
        holding a strong reference matters for a different reason: a task that is
        only referenced by the event loop can be garbage-collected mid-flight, and
        the failure mode is enrichment that silently stops happening.
        """
        task = asyncio.ensure_future(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        task.add_done_callback(_log_task_exception)

    # -------------------------------------------------------------------- probes

    async def _resolve(self, endpoint: str) -> Resolved | TargetRejected:
        now = asyncio.get_running_loop().time()
        cached = self._resolved.get(endpoint)
        if cached and cached[0] > now:
            return cached[1]
        try:
            result: Resolved | TargetRejected = await resolve_endpoint(
                endpoint, allow_private=self.settings.allow_private_targets
            )
        except TargetRejected as exc:
            result = exc
        self._resolved[endpoint] = (now + _RESOLVE_TTL_S, result)
        return result

    async def _probe_node(self, target: Target) -> tuple[str, NodeProbe]:
        assert self._client is not None and self._insecure is not None
        async with self._sem:
            resolved = await self._resolve(target.endpoint)
            if isinstance(resolved, TargetRejected):
                return target.slug, NodeProbe(
                    ok=False, reason=resolved.reason, error=resolved.message
                )
            return target.slug, await probe_tip(self._client, self._insecure, resolved)

    async def _probe_relay_if_due(
        self, target: Target, now: float
    ) -> tuple[str, EpicboxProbe]:
        """Relay result for this sweep.

        Awaited only on the first sweep for a given relay, where there is nothing
        cached and a one-off cold-start cost is the right trade. After that the
        30-second refresh runs in the background and the sweep reads the cache, so a
        relay that takes the full WebSocket timeout to fail does not add eight
        seconds to every sixth sweep.
        """
        assert target.id is not None
        cached = self._last_epicbox.get(target.id)
        if cached is None:
            self._next_epicbox[target.id] = now + self.settings.cadence.epicbox_s
            return target.slug, await self._one_relay(target)
        if now >= self._next_epicbox.get(target.id, 0.0):
            self._next_epicbox[target.id] = now + self.settings.cadence.epicbox_s
            self._spawn(self._refresh_one_relay(target))
        return target.slug, cached[1]

    async def _refresh_one_relay(self, target: Target) -> None:
        await self._one_relay(target)

    async def _one_relay(self, target: Target) -> EpicboxProbe:
        assert target.id is not None
        async with self._sem:
            resolved = await self._resolve(target.endpoint)
            if isinstance(resolved, TargetRejected):
                probe = EpicboxProbe(
                    ok=False, reason=resolved.reason, error=resolved.message
                )
            else:
                probe = await probe_relay(resolved, timeout=self.settings.ws_timeout_s)
                if probe.protocol_version:
                    self.db.set_protocol_version(target.id, probe.protocol_version)
        self._last_epicbox[target.id] = (asyncio.get_running_loop().time(), probe)
        return probe

    async def _refresh_versions(
        self, nodes: list[Target], probes: dict[str, NodeProbe], now: float
    ) -> None:
        assert self._client is not None
        due = [
            t
            for t in nodes
            if t.id is not None
            and probes[t.slug].ok
            and now >= self._next_version.get(t.id, 0.0)
        ]
        for target in due:
            assert target.id is not None
            self._next_version[target.id] = now + self.settings.cadence.node_version_s
        await asyncio.gather(*(self._one_version(t) for t in due))

    async def _one_version(self, target: Target) -> None:
        assert self._client is not None and target.id is not None
        resolved = await self._resolve(target.endpoint)
        if isinstance(resolved, TargetRejected):
            return
        async with self._sem:
            result = await probe_version(self._client, resolved)
        if result.ok:
            self.db.set_node_version(target.id, result.node_version)

    async def _refresh_tip_age(
        self,
        nodes: list[Target],
        probes: dict[str, NodeProbe],
        tip: int | None,
        now: float,
    ) -> None:
        """Ask exactly one healthy node for the tip block's timestamp.

        "The chain is moving" is a property of the chain, not of a node, so asking
        every node would be N requests for one fact. The node chosen is the fastest
        one that agrees with the fleet tip.
        """
        assert self._client is not None
        if tip is None or (self._tip_age and now < self._tip_age[0]):
            return
        candidates = sorted(
            (
                t
                for t in nodes
                if probes[t.slug].ok
                and probes[t.slug].height == tip
                and probes[t.slug].latency_ms is not None
            ),
            key=lambda t: probes[t.slug].latency_ms or 10**9,
        )
        for target in candidates[:2]:
            resolved = await self._resolve(target.endpoint)
            if isinstance(resolved, TargetRejected):
                continue
            async with self._sem:
                result = await probe_tip_age(self._client, resolved, tip)
            if result.ok and result.timestamp is not None:
                self._tip_age = (now + self.settings.cadence.node_header_s, result.timestamp)
                return

    async def _refresh_p2p(
        self, nodes: list[Target], probes: dict[str, NodeProbe], now: float
    ) -> None:
        """TCP liveness for nodes whose HTTP API did not answer.

        Only for those: there is no reason to knock on the P2P port of a node that
        just answered a JSON-RPC call, and doing so would double our footprint on
        every healthy host for no information.

        Run concurrently. Sequentially, a cold start against four unreachable seeds
        added four timeouts' worth of latency to the sweep — which then delayed
        every other row's update behind hosts that were not going to answer.
        """
        due: list[Target] = []
        for target in nodes:
            if target.id is None or not target.p2p:
                continue
            if probes[target.slug].ok:
                self._p2p_alive.pop(target.id, None)
                continue
            if now < self._next_p2p.get(target.id, 0.0):
                continue
            self._next_p2p[target.id] = now + self.settings.cadence.node_p2p_s
            due.append(target)
        await asyncio.gather(*(self._one_p2p(t) for t in due))

    async def _one_p2p(self, target: Target) -> None:
        assert target.id is not None and target.p2p is not None
        host, _, port_text = target.p2p.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            return
        # Reuses resolve_endpoint for the SSRF check. The scheme only selects a
        # default port and TLS-ness, neither of which applies here because the port
        # is explicit and only the validated address is used.
        resolved = await self._resolve(f"https://{host}:{port}")
        if not isinstance(resolved, Resolved):
            self._p2p_alive[target.id] = False
            return
        async with self._sem:
            alive, _ = await tcp_probe(resolved.primary, port, self.settings.http_timeout_s)
        self._p2p_alive[target.id] = alive

    async def _refresh_certs(self, relays: list[Target], now: float) -> None:
        due: list[Target] = []
        for target in relays:
            if target.id is None or now < self._next_cert.get(target.id, 0.0):
                continue
            self._next_cert[target.id] = now + self.settings.cadence.epicbox_cert_s
            due.append(target)
        await asyncio.gather(*(self._one_cert(t) for t in due))

    async def _one_cert(self, target: Target) -> None:
        assert target.id is not None
        resolved = await self._resolve(target.endpoint)
        if isinstance(resolved, TargetRejected):
            self._cert_days[target.id] = None
            return
        async with self._sem:
            days = await peer_certificate_expiry(resolved, self.settings.ws_timeout_s)
        self._cert_days[target.id] = days
        if days is not None:
            self.db.set_cert_expiry(target.id, datetime.now(UTC) + timedelta(days=days))

    async def _refresh_geo(self, targets: list[Target], now: float) -> None:
        """Enrich a couple of targets per sweep, never the whole fleet at once.

        The RDAP bootstrap service answers 429 to a burst, and on a cold start every
        target is due simultaneously. Two per sweep fills a twelve-target fleet in
        half a minute and never trips the limit.
        """
        assert self._client is not None
        due = [
            t for t in targets if t.id is not None and now >= self._next_geo.get(t.id, 0.0)
        ]
        for target in due[:_GEO_PER_SWEEP]:
            assert target.id is not None
            resolved = await self._resolve(target.endpoint)
            if isinstance(resolved, TargetRejected):
                # No address to look up. Try again on the slow cadence rather than
                # hammering a name that does not resolve.
                self._next_geo[target.id] = now + self.settings.cadence.geo_refresh_s
                continue
            async with self._sem:
                fresh = await geo_lookup(self._client, resolved.primary)
            if fresh is None:
                # Rate limited or a transport error. Retry in an hour; caching this
                # for a week would silently lose the target's provider.
                self._next_geo[target.id] = now + _GEO_RETRY_S
                continue
            self._next_geo[target.id] = now + self.settings.cadence.geo_refresh_s
            merged: GeoInfo = geo_merge(target.geo, fresh)
            self.db.set_geo(target.id, merged)
            target.geo = merged

    # ------------------------------------------------------------------ statuses

    def _node_status(
        self, target: Target, probe: NodeProbe, tip: int | None
    ) -> TargetStatus:
        assert target.id is not None
        row = self.db.conn.execute(
            """
            SELECT last_ok_at, last_checked_at, last_error, consecutive_failures,
                   node_version
              FROM targets WHERE id = ?
            """,
            (target.id,),
        ).fetchone()

        # `consecutive_failures` in the row is the count *before* this probe, so a
        # first failure must be counted here or the down-after-N window is off by
        # one and a single dropped packet turns a row red.
        failures = int(row["consecutive_failures"]) + (0 if probe.ok else 1)

        state, reason, detail = node_state(
            target,
            probe,
            tip=tip,
            consecutive_failures=failures,
            thresholds=self.settings.thresholds,
            p2p_alive=self._p2p_alive.get(target.id),
        )

        status = TargetStatus(
            target=target,
            state=state,
            reason=reason,
            detail=detail,
            latency_ms=probe.latency_ms,
            height=probe.height,
            tip_lag=(tip - probe.height) if tip is not None and probe.height else None,
            tip_hash=probe.tip_hash,
            node_version=row["node_version"],
            last_checked_at=datetime.now(UTC),
            last_ok_at=datetime.now(UTC) if probe.ok else parse_iso(row["last_ok_at"]),
            last_error=None if probe.ok else (probe.error or row["last_error"]),
            consecutive_failures=0 if probe.ok else failures,
        )
        self._attach_uptime(status)
        return status

    def _relay_status(self, target: Target, probe: EpicboxProbe) -> TargetStatus:
        assert target.id is not None
        row = self.db.conn.execute(
            """
            SELECT last_ok_at, last_error, consecutive_failures, protocol_version
              FROM targets WHERE id = ?
            """,
            (target.id,),
        ).fetchone()
        failures = int(row["consecutive_failures"]) + (0 if probe.ok else 1)
        cert_days = self._cert_days.get(target.id)

        state, reason, detail = epicbox_state(
            probe,
            consecutive_failures=failures,
            cert_days=cert_days,
            thresholds=self.settings.thresholds,
        )

        status = TargetStatus(
            target=target,
            state=state,
            reason=reason,
            detail=detail,
            latency_ms=probe.latency_ms,
            protocol_version=probe.protocol_version or row["protocol_version"],
            cert_expires_in_days=cert_days,
            last_checked_at=datetime.now(UTC),
            last_ok_at=datetime.now(UTC) if probe.ok else parse_iso(row["last_ok_at"]),
            last_error=None if probe.ok else (probe.error or row["last_error"]),
            consecutive_failures=0 if probe.ok else failures,
        )
        self._attach_uptime(status)
        return status

    def _attach_uptime(self, status: TargetStatus) -> None:
        target_id = status.target.id
        assert target_id is not None
        now = asyncio.get_running_loop().time()
        cached = self._uptime.get(target_id)
        if cached is None or cached[0] <= now:
            values = (
                self.db.uptime(target_id, timedelta(hours=1)),
                self.db.uptime(target_id, timedelta(hours=24)),
                self.db.uptime(target_id, timedelta(days=30)),
            )
            self._uptime[target_id] = (now + _UPTIME_TTL_S, values)
            cached = self._uptime[target_id]
        status.uptime_1h, status.uptime_24h, status.uptime_30d = cached[1]

    def _attach_history(self, status: TargetStatus) -> None:
        assert status.target.id is not None
        status.history = self.db.history(
            status.target.id, self.settings.history_points
        )

    # ------------------------------------------------------------------- persist

    def _persist(
        self, statuses: list[TargetStatus], probes: dict[str, NodeProbe]
    ) -> None:
        for status in statuses:
            probe = probes[status.target.slug]
            assert status.target.id is not None
            self.db.record_check(
                target_id=status.target.id,
                ok=probe.ok,
                state=status.state.value,
                reason=status.reason.value,
                latency_ms=probe.latency_ms,
                height=probe.height,
                tip_hash=probe.tip_hash,
                error=probe.error,
            )

    def _persist_relays(
        self, statuses: list[TargetStatus], probes: dict[str, EpicboxProbe]
    ) -> None:
        """Record a relay check once per actual probe, not once per sweep.

        Relays are probed every 30 seconds and the sweep reads a cache in between.
        Writing a row on every sweep would insert six duplicate observations for
        each real one and make every uptime percentage a fiction.
        """
        for status in statuses:
            target_id = status.target.id
            assert target_id is not None
            stamped = self._last_epicbox.get(target_id)
            if stamped is None:
                continue
            if self._relay_persisted.get(target_id) == stamped[0]:
                continue
            self._relay_persisted[target_id] = stamped[0]
            probe = probes[status.target.slug]
            self.db.record_check(
                target_id=target_id,
                ok=probe.ok,
                state=status.state.value,
                reason=status.reason.value,
                latency_ms=probe.latency_ms,
                height=None,
                tip_hash=None,
                error=probe.error,
            )

    def _reap(self, statuses: list[TargetStatus]) -> None:
        """Self-removal, so the list stays honest without a moderator.

        Only ever removes a *submitted* target that has never once succeeded — the
        SQL in `delete_target` enforces both conditions, so this cannot destroy the
        history of something that was once real. Seeds are never removed at all:
        `node.epiccash.com` being down is the most important thing this page can
        say, so it must not vanish for being down.
        """
        limit = self.settings.thresholds.remove_after_failures
        for status in statuses:
            if (
                status.target.source.value == "submitted"
                and status.last_ok_at is None
                and status.consecutive_failures >= limit
                and status.target.id is not None
            ):
                log.info(
                    "removing %s after %d consecutive failures and no success",
                    status.target.slug,
                    status.consecutive_failures,
                )
                self.db.delete_target(status.target.id)

    # ------------------------------------------------------------------ snapshot

    def _build_snapshot(
        self,
        nodes: list[TargetStatus],
        relays: list[TargetStatus],
        tip: int | None,
        forked: bool,
        fork_detail: str | None,
    ) -> Snapshot:
        newest = newest_version(nodes)
        tip_hash = next(
            (s.tip_hash for s in nodes if s.height == tip and s.tip_hash), None
        )

        tip_age_s: int | None = None
        if self._tip_age is not None:
            tip_age_s = max(
                0, int((datetime.now(UTC) - self._tip_age[1]).total_seconds())
            )

        providers: dict[str, int] = {}
        countries: list[str] = []
        addresses: dict[str, int] = {}
        for status in nodes + relays:
            geo = status.target.geo
            if geo.provider:
                providers[geo.provider] = providers.get(geo.provider, 0) + 1
            shown = geo.display_country
            if shown and shown not in countries:
                countries.append(shown)
            cached = self._resolved.get(status.target.endpoint)
            if cached and isinstance(cached[1], Resolved):
                addr = cached[1].primary
                addresses[addr] = addresses.get(addr, 0) + 1

        summary = NetworkSummary(
            tip_height=tip,
            tip_hash=tip_hash,
            tip_age_s=tip_age_s,
            forked=forked,
            fork_detail=fork_detail,
            nodes_total=len(nodes),
            nodes_healthy=sum(1 for s in nodes if s.state is State.HEALTHY),
            nodes_degraded=sum(1 for s in nodes if s.state is State.DEGRADED),
            nodes_down=sum(1 for s in nodes if s.state is State.DOWN),
            epicbox_total=len(relays),
            epicbox_healthy=sum(1 for s in relays if s.state is State.HEALTHY),
            epicbox_degraded=sum(1 for s in relays if s.state is State.DEGRADED),
            epicbox_down=sum(1 for s in relays if s.state is State.DOWN),
            median_node_latency_ms=_median_latency(nodes),
            median_epicbox_latency_ms=_median_latency(relays),
            countries=sorted(countries),
            providers=dict(sorted(providers.items(), key=lambda kv: -kv[1])),
            co_hosted=sum(1 for count in addresses.values() if count > 1),
        )
        summary.health_score = health_score(
            nodes, forked=forked, thresholds=self.settings.thresholds
        )

        # Newest version is attached after scoring so the board can mark laggards
        # without the score having to be recomputed.
        for status in nodes:
            if newest and status.node_version and status.node_version != newest:
                if status.state is State.HEALTHY and status.detail is None:
                    status.detail = f"running {status.node_version}, newest is {newest}"

        return Snapshot(
            generated_at=datetime.now(UTC),
            prober_id=self.settings.prober_id,
            network=summary,
            nodes=_sorted(nodes),
            epicbox=_sorted(relays),
            stale=False,
        )


def _median_latency(statuses: list[TargetStatus]) -> int | None:
    values = [
        s.latency_ms
        for s in statuses
        if s.latency_ms is not None and s.state is not State.DOWN
    ]
    if not values:
        return None
    import statistics

    return int(statistics.median(values))


_STATE_ORDER = {State.HEALTHY: 0, State.DEGRADED: 1, State.UNKNOWN: 2, State.DOWN: 3}


def _sorted(statuses: list[TargetStatus]) -> list[TargetStatus]:
    """Health first, then latency. Not alphabetical, and not our own hosts first.

    Sorting by anything that favours the instance operator's own infrastructure on
    a page the operator controls is the kind of thing readers notice.
    """
    return sorted(
        statuses,
        key=lambda s: (
            _STATE_ORDER.get(s.state, 9),
            s.latency_ms if s.latency_ms is not None else 10**9,
            s.target.slug,
        ),
    )


def _log_task_exception(task: asyncio.Task[None]) -> None:
    """A background refresh that dies must say so.

    Without this the exception is only reported when the task is garbage-collected,
    which for a long-lived process means enrichment quietly stopping with nothing in
    the journal to explain it.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("background refresh failed: %r", exc)
