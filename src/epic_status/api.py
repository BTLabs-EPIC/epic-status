"""HTTP layer: the board, the JSON API, and the submit endpoint.

Everything a visitor touches is served from the in-memory snapshot. No request path
probes anything, with one deliberate exception: `POST /api/v1/check`, the quick node
check, which probes the one host the visitor typed, once, behind the guards and rate
limits in `quickcheck`. That is the most important property of this file — see the
poller's module docstring for why a status page that fans out per visitor becomes an
attack on the hosts it monitors.

The JSON schema matches grin.fail's field-for-field where they overlap, because that
is already the de-facto shape in this ecosystem and anyone integrating has probably
read it. Two fields are borrowed from cosmos.directory instead: `last_error`, so an
operator can diagnose their own endpoint without contacting us, and `operator`, so
credit is attributed.

CORS is opened by hand on the read-only JSON routes rather than with a global
middleware. A blanket `allow_origins=["*"]` would also open the submit endpoint to
cross-origin POSTs from any page on the internet.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import admin_routes, schemas
from .badges import badge_for
from .config import Settings, load_seed_targets
from .config import settings as get_settings
from .db import Database
from .models import Chain, Event, Kind, Severity, Snapshot, State, Target, TargetStatus
from .net import build_client
from .poller import Poller
from .quickcheck import QuickChecker, QuickCheckResult, run_check
from .render import (
    probe_url,
    render_api,
    render_board,
    render_feed,
    render_history,
    render_submit,
)
from .submit import SubmissionError, Validator, accept
from .vantage import Ingest, Rejected, parse_keys
from .web import client_address, cors, json_response, security_headers, stamp

log = logging.getLogger("epic_status.api")

STATIC_DIR = Path(__file__).parent / "static"

_HISTORY_EVENTS = 50
"""Incidents shown on /history. The JSON route and the feed page further back."""

_FEED_EVENTS = 50

_VALIDATOR_INTERVAL_S = 15.0
"""How often pending submissions are checked. Slow on purpose: a pending submission
is an unvetted host and must not share a deadline with the probes the board needs."""

_API_DESCRIPTION = """
Everything on the board is available here. Read routes send
`access-control-allow-origin: *`, so a browser can consume them directly without a
proxy.

**Nothing is probed when you call this.** One poller writes state on a fixed cadence
and every caller reads the same cached snapshot. Calling this API does not generate
traffic to any monitored server, which is why it is open.

### Cadence

Nodes are checked every 5 seconds with a single unauthenticated `get_tip`. Epicbox
relays every 30 seconds, by opening a WebSocket and reading the one `Challenge` frame
the relay sends unprompted. Mining pools every 30 seconds, with one GET against the
pool's own stats endpoint. Node versions every 5 minutes, certificate expiry every 6
hours.

### What is not here

Peer counts and sync status. Those live on a node's owner API and need an
`api_secret`, so no third party can publish them — for anyone's node, not just ours.
Anything claiming otherwise is guessing.

### Reading the numbers

`latency_ms` is the round trip from one prober, named in the `prober` object. It
describes that host's path to the target as much as the target itself.

`state` has three values, not two. `degraded` is the honest bucket for a node that is
up but not fully usable — a private API, a lagging tip — and for a failure this prober
has not yet confirmed.

`tip_lag` is the number worth alerting on. A node can answer every request while
thousands of blocks behind.

### Pools are not nodes

A pool row carries `miners`, `workers`, `fee_percent` and `last_block_height`, and no
height or `tip_lag`. `last_block_height` is the last block that pool **found** — the
pools' own `currentHeight` field is the same number despite its name, and none of them
publishes its node's chain tip.

Do not compare it with `network.tip_height`. A pool finds blocks in proportion to its
share of the network, so the gap is large for a small pool and near zero for a large
one, and it measures pool size rather than pool health. For the same reason no
threshold is applied to the age of the last block: `green` on a pool row means its API
answered with valid stats.

Every pool's API is a different shape, so pools are integrated by hand. Submitting one
records a request rather than starting an automatic check.
"""


class Service:
    """Holds the long-lived objects.

    An instance rather than module globals, so the app is testable and two instances
    can coexist in one process.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db, settings.prober_id)
        self.poller = Poller(self.db, settings)
        self.validator = Validator(self.db, settings)
        # Parsed here so a malformed key list fails at boot, not on the first push.
        keys = parse_keys(settings.prober_keys)
        self.ingest = Ingest(self.db, keys) if keys else None
        # Rotated per process and never persisted. The submitter hashes in the
        # database therefore cannot be reversed even by someone holding the
        # database, and stop being linkable across restarts — the right trade for a
        # value whose only job is rate limiting.
        self.submitter_salt = secrets.token_hex(16)
        self.quickcheck = QuickChecker(settings)

    async def quick_check(
        self, raw: str, *, client_ip: str, use_defaults: bool = False
    ) -> QuickCheckResult:
        """Run a quick node check against the live snapshots.

        The entry point for both the JSON route and the board's HTML form. Tips come
        from the in-memory snapshots — no database read — and the listed targets
        from every chain, so a typed hostname that is already on the board is named.
        """
        tips: dict[Chain, int | None] = {}
        listed: list[Target] = []
        for chain in Chain:
            snap = self.snapshot_for(chain)
            tips[chain] = snap.network.tip_height if snap is not None else None
            if snap is not None:
                listed.extend(s.target for s in snap.nodes)
        return await run_check(
            self.quickcheck,
            raw,
            client_ip=client_ip,
            use_defaults=use_defaults,
            tips=tips,
            listed=listed,
        )

    @property
    def snapshot(self) -> Snapshot | None:
        """Mainnet's snapshot.

        Kept as a property, and kept meaning mainnet, so that everything whose answer
        is not chain-specific — the submit form, the service's own health — reads the
        same as before. Anything that renders or serialises a chain's data uses
        `snapshot_for` instead and says which chain it means.
        """
        return self.snapshot_for(Chain.MAINNET)

    def snapshot_for(self, chain: Chain) -> Snapshot | None:
        snap = self.poller.snapshots.get(chain)
        if snap is None:
            return None
        age = (datetime.now(UTC) - snap.generated_at).total_seconds()
        # Say so rather than presenting frozen numbers as live. A status page that
        # lies about its own freshness has no claim to be trusted about anything.
        snap.stale = age > self.settings.thresholds.stale_snapshot_s
        return snap

    def chains(self) -> list[Chain]:
        """Chains with at least one enabled target, in enum order.

        Read from the database rather than from the enum, so the navbar offers a
        network that is actually being monitored. It also means the switch disappears
        entirely on an instance configured with only mainnet: a segmented control with
        one segment is a label pretending to be a choice.
        """
        configured = self.db.chains()
        return [c for c in Chain if c in configured]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    service = Service(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        service.db.reconcile_seeds(load_seed_targets(settings.targets_file))
        async with service.poller:
            poll_task = asyncio.create_task(service.poller.run(), name="poller")
            validate_task = asyncio.create_task(
                _run_validator(service), name="validator"
            )
            try:
                yield
            finally:
                for task in (poll_task, validate_task):
                    task.cancel()
                await asyncio.gather(poll_task, validate_task, return_exceptions=True)
                await service.quickcheck.aclose()
        service.db.close()

    app = FastAPI(
        title="Epic Cash status API",
        summary="Live health, uptime and consensus state for Epic Cash public nodes, "
        "Epicbox relays and mining pools, on mainnet and floonet.",
        description=_API_DESCRIPTION,
        version="0.1.0",
        lifespan=lifespan,
        # FastAPI's built-in docs load Swagger UI from a CDN, which this service's
        # own Content-Security-Policy blocks — it rendered a blank page. Replaced by
        # /api, which serves a self-hosted reference against this same document.
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        openapi_tags=[
            {"name": "status", "description": "Read the current board."},
            {"name": "lists", "description": "Endpoint lists for wallets and failover configs."},
            {"name": "service", "description": "Health of this monitor, not of the network."},
            {"name": "submit", "description": "Add a server to be monitored."},
        ],
        contact={"name": "Source", "url": "https://github.com/blacktyg3r/epic-status"},
        license_info={"name": "MIT", "identifier": "MIT"},
    )
    # HEAD is registered alongside GET on every read route. FastAPI does not add
    # it automatically, and the 405 that results is not academic: uptime monitors
    # and load balancers commonly probe with HEAD, so `/api/v1/health` — the route
    # this project tells operators to point their alerting at — would have reported
    # itself broken to exactly the tools most likely to watch it.
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.state.service = service

    # ------------------------------------------------------------------ pages

    @app.api_route(
        "/",
        methods=["GET", "HEAD"],
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def board(request: Request, chain: str = "mainnet") -> HTMLResponse:
        """The board for one chain.

        A query parameter rather than a path, and defaulting to mainnet, so that `/`
        keeps meaning exactly what it has always meant: every link, bookmark and
        search result pointing at this service continues to land on the mainnet board.
        `/?chain=floonet` is the second network.
        """
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        html = render_board(
            snapshot=snap,
            settings=settings,
            chain=selected,
            chains=service.chains(),
        )
        return HTMLResponse(
            html,
            headers={
                # The board is a live document. Caching it for even a few seconds
                # means a reader refreshing during an outage sees the outage
                # they already saw.
                "cache-control": "no-store",
                # Built from the chain on screen, because the in-browser probe button
                # can only reach the hosts this page is showing. A union across both
                # chains would widen the policy on the mainnet board to origins it
                # never contacts.
                **security_headers(connect=_probe_origins(snap)),
            },
        )

    @app.api_route(
        "/history",
        methods=["GET", "HEAD"],
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def history(chain: str = "mainnet") -> HTMLResponse:
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        bars = {}
        if snap is not None:
            for status in snap.nodes + snap.epicbox + snap.pools:
                if status.target.id is not None:
                    bars[status.target.slug] = service.db.daily_uptime(
                        status.target.id, 90
                    )
        html = render_history(
            snapshot=snap,
            settings=settings,
            bars=bars,
            events=service.db.events(selected, limit=_HISTORY_EVENTS),
            chain=selected,
            chains=service.chains(),
        )
        return HTMLResponse(
            html, headers={"cache-control": "no-store", **security_headers()}
        )

    @app.api_route("/feed.atom", methods=["GET", "HEAD"], include_in_schema=False)
    async def feed(
        request: Request,
        chain: str = "mainnet",
        min_severity: Annotated[str, Query(alias="min")] = "warn",
    ) -> Response:
        """The incident log as Atom. `?min=info` includes routine one-block reorgs and
        certificate notices; the default leaves them out, because a feed that posts
        every orphan race is a feed people unsubscribe from."""
        selected = _chain_or_404(chain)
        severity = _severity_or_400(min_severity)
        events = service.db.events(selected, limit=_FEED_EVENTS, min_severity=severity)
        body = render_feed(
            events=events,
            settings=settings,
            chain=selected,
            self_url=f"{settings.site_url.rstrip('/')}{request.url.path}"
            + (f"?{request.url.query}" if request.url.query else ""),
        )
        return Response(
            body,
            media_type="application/atom+xml",
            headers={
                # A feed reader polls; a minute of caching costs nothing here, since
                # an incident is minutes long by construction.
                "cache-control": "public, max-age=60",
                **cors(),
                **security_headers(),
            },
        )

    @app.api_route(
        "/add",
        methods=["GET", "HEAD"],
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def add_form() -> HTMLResponse:
        return HTMLResponse(
            render_submit(snapshot=service.snapshot, settings=settings),
            headers={"cache-control": "no-store", **security_headers()},
        )

    @app.post("/add", response_class=HTMLResponse, include_in_schema=False)
    async def add_submit(
        request: Request,
        kind: Annotated[str, Form()] = "node",
        host: Annotated[str, Form()] = "",
        operator: Annotated[str, Form()] = "",
        country: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        message, error = await _do_submit(
            service, request, kind, host, operator, country
        )
        return HTMLResponse(
            render_submit(
                snapshot=service.snapshot,
                settings=settings,
                message=message,
                error=error,
                submitted_host=host,
            ),
            status_code=200 if message else 400,
            headers={"cache-control": "no-store", **security_headers()},
        )

    # Both forms. nginx normalises /api to /api/ because a /api/ prefix location
    # exists, and with only the bare path registered that redirect landed on a 404.
    @app.api_route("/api", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/api/", methods=["GET", "HEAD"], include_in_schema=False)
    async def api_reference() -> HTMLResponse:
        return HTMLResponse(
            render_api(settings=settings),
            headers={"cache-control": "no-store", **security_headers()},
        )

    @app.api_route("/api/docs", methods=["GET", "HEAD"], include_in_schema=False)
    async def api_docs_redirect() -> Response:
        """Kept so the old path still lands somewhere. It was a CDN-backed Swagger
        page that could not load under this service's CSP."""
        return Response(status_code=308, headers={"location": "/api"})

    admin_routes.register(app, service)

    # -------------------------------------------------------------------- api

    @app.head("/api/v1/status.json", include_in_schema=False)
    @app.get(
        "/api/v1/status.json",
        tags=["status"],
        summary="The whole board",
        description=(
            "Everything the page shows, in one document. Carries an `ETag`; send it "
            "back as `If-None-Match` and a repeat request costs nothing when nothing "
            "has changed.\n\n"
            "Field names follow grin.fail's schema where they overlap, since that is "
            "already the de-facto shape in this ecosystem."
        ),
        responses={
            200: {"model": schemas.StatusResponse},
            304: {"description": "Unchanged since the ETag you sent."},
            503: {"model": schemas.ErrorResponse, "description": "No sweep has completed yet."},
        },
    )
    async def statusjson_response(request: Request, chain: str = "mainnet") -> Response:
        """`?chain=floonet` for the test network. Absent means mainnet, so every
        existing consumer of this endpoint keeps receiving exactly what it did."""
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return json_response(
                {"error": "no data yet", "generated_at": None},
                status_code=503,
            )
        payload = _serialise(snap, settings)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        # The chain is inside the payload, so the two chains cannot collide on one
        # ETag: the hash is over a document that names the network it describes.
        etag = '"' + hashlib.sha256(body.encode()).hexdigest()[:32] + '"'
        if request.headers.get("if-none-match") == etag:
            # A poller consuming this API costs nothing when nothing has changed,
            # which is the difference between being integrable and being a burden.
            return Response(status_code=304, headers={"etag": etag, **cors()})
        return Response(
            body,
            media_type="application/json",
            headers={"etag": etag, "cache-control": "no-store", **cors()},
        )

    @app.head("/api/v1/nodes.json", include_in_schema=False)
    @app.get(
        "/api/v1/nodes.json",
        tags=["lists"],
        summary="Node endpoints, as a plain list",
        responses={
            200: {"model": schemas.EndpointList},
            503: {"model": schemas.ErrorResponse},
        },
    )
    async def nodesjson_response(healthy: bool = False, chain: str = "mainnet") -> Response:
        """A bare list of endpoints, which is what a wallet or an exchange failover
        config actually wants. `?healthy=true` filters to the ones worth using.

        One chain per response, mainnet by default. A wallet asking for node endpoints
        must never be handed a floonet address mixed in with mainnet ones — it would
        connect, sync a different chain, and look broken for reasons nothing on this
        page explains."""
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return json_response({"error": "no data yet"}, status_code=503)
        rows = [
            s
            for s in snap.nodes
            if not healthy or s.state is State.HEALTHY
        ]
        return json_response(
            {
                "meta": _list_meta(
                    describes=f"Epic Cash {selected.value} public node endpoints",
                    healthy=healthy,
                    count=len(rows),
                    total=len(snap.nodes),
                    cadence_s=settings.cadence.node_tip_s,
                    settings=settings,
                ),
                "generated_at": stamp(snap.generated_at),
                "chain": snap.network.chain.value,
                "tip_height": snap.network.tip_height,
                "nodes": [s.target.endpoint for s in rows],
            }
        )

    @app.head("/api/v1/epicbox.json", include_in_schema=False)
    @app.get(
        "/api/v1/epicbox.json",
        tags=["lists"],
        summary="Epicbox hosts, as a plain list",
        responses={
            200: {"model": schemas.EpicboxList},
            503: {"model": schemas.ErrorResponse},
        },
    )
    async def epicboxjson_response(healthy: bool = False, chain: str = "mainnet") -> Response:
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return json_response({"error": "no data yet"}, status_code=503)
        rows = [s for s in snap.epicbox if not healthy or s.state is State.HEALTHY]
        return json_response(
            {
                "meta": _list_meta(
                    describes="Epicbox relay hosts, the transport wallets use for addresses",
                    healthy=healthy,
                    count=len(rows),
                    total=len(snap.epicbox),
                    cadence_s=settings.cadence.epicbox_s,
                    settings=settings,
                ),
                "generated_at": stamp(snap.generated_at),
                "chain": snap.network.chain.value,
                "epicbox": [s.target.display_host for s in rows],
            }
        )

    @app.head("/api/v1/pools.json", include_in_schema=False)
    @app.get(
        "/api/v1/pools.json",
        tags=["lists"],
        summary="Mining pools, as a plain list",
        description=(
            "Pool hosts, for a miner-facing switcher or a wallet's pool picker. "
            "`?healthy=true` filters to the ones answering right now."
        ),
        responses={
            200: {"model": schemas.PoolList},
            503: {"model": schemas.ErrorResponse},
        },
    )
    async def poolsjson_response(healthy: bool = False, chain: str = "mainnet") -> Response:
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return json_response({"error": "no data yet"}, status_code=503)
        rows = [s for s in snap.pools if not healthy or s.state is State.HEALTHY]
        return json_response(
            {
                "meta": _list_meta(
                    describes="Mining pools whose stats API answered",
                    healthy=healthy,
                    count=len(rows),
                    total=len(snap.pools),
                    cadence_s=settings.cadence.pool_s,
                    settings=settings,
                ),
                "generated_at": stamp(snap.generated_at),
                "chain": snap.network.chain.value,
                "pools": [s.target.display_host for s in rows],
            }
        )

    @app.api_route(
        "/badge/{slug}.svg", methods=["GET", "HEAD"], include_in_schema=False
    )
    async def badge(slug: str, kind: str | None = None, label: str | None = None) -> Response:
        """An embeddable badge for one target: state and 30-day uptime.

        Looked up by the target's `id` across every chain. `?kind=` disambiguates when
        a node and a relay share a slug; `?label=` replaces the left-hand text.
        Unknown targets get a grey badge with a 404, so an embed of a removed host
        says so instead of showing a broken image.
        """
        wanted = _kind_or_none(kind)
        found: TargetStatus | None = None
        for chain_ in service.chains():
            snap = service.snapshot_for(chain_)
            if snap is None:
                continue
            for status in (*snap.nodes, *snap.epicbox, *snap.pools):
                if status.target.slug == slug and wanted in (None, status.target.kind):
                    found = status
                    break
            if found is not None:
                break
        text = label or (_badge_label(found) if found is not None else "epic status")
        return Response(
            badge_for(found, label=text),
            status_code=200 if found is not None else 404,
            media_type="image/svg+xml",
            headers={
                # Image proxies such as GitHub's camo honour this. A minute is the
                # granularity anyone reading a README could care about.
                "cache-control": "public, max-age=60",
                **cors(),
                # Served as an image, but reachable as a document: nothing in it may run.
                "content-security-policy": "default-src 'none'",
                "x-content-type-options": "nosniff",
            },
        )

    @app.head("/api/v1/events.json", include_in_schema=False)
    @app.get(
        "/api/v1/events.json",
        tags=["status"],
        summary="The incident log",
        description=(
            "Outages, reorgs, forks, chain stalls and certificates close to expiry, "
            "newest first. A condition is one entry from start to end — `ended_at` is "
            "null while it is ongoing — and a reorg is an instant with its `depth`.\n\n"
            "`?min=warn` drops routine one-block reorgs and certificate notices; "
            "`?min=bad` leaves forks and stalls only. Also available as Atom at "
            "`/feed.atom`, which defaults to `warn`."
        ),
        responses={200: {"model": schemas.EventList}},
    )
    async def events_json(
        chain: str = "mainnet",
        min_severity: Annotated[str, Query(alias="min")] = "info",
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> Response:
        selected = _chain_or_404(chain)
        severity = _severity_or_400(min_severity)
        events = service.db.events(selected, limit=limit, min_severity=severity)
        return json_response(
            {
                "generated_at": stamp(datetime.now(UTC)),
                "chain": selected.value,
                "min_severity": severity.value,
                "events": [_serialise_event(e) for e in events],
            }
        )

    if service.ingest is not None:
        ingest = service.ingest

        @app.post("/api/v1/probes", include_in_schema=False)
        async def probes_push(request: Request) -> Response:
            """Signed batches from remote probers. Not in the public schema: it is an
            operator-to-operator interface, and it only exists when keys are set."""
            body = await request.body()
            try:
                accepted, skipped = ingest.accept(request.headers, body)
            except Rejected as exc:
                log.warning("probe batch refused: %s", exc.message)
                return json_response({"ok": False, "error": exc.message}, exc.status)
            return json_response({"ok": True, "accepted": accepted, "skipped": skipped})

    if settings.quickcheck_enabled:

        @app.post("/api/v1/check", include_in_schema=False)
        async def quick_check_api(request: Request) -> Response:
            """One quick check of a typed node address, for the board's own page.

            Same-origin only, by three separate means: no CORS headers, so a browser
            on another site cannot read the answer; a JSON content type is required,
            which a cross-site HTML form cannot send without a preflight this route
            never answers; and `sec-fetch-site: cross-site` is refused outright.
            Not in the public schema: it makes this server connect somewhere, which
            is not something to advertise as an API.
            """
            return await _quick_check_route(service, request)

    @app.head("/api/v1/health", include_in_schema=False)
    @app.get(
        "/api/v1/health",
        tags=["service"],
        summary="Is this monitor working",
        description=(
            "Point your alerting here. 503 means **this observer** is broken or its "
            "data is stale — it says nothing about the Epic Cash network, and "
            "conflating the two is the most damaging mistake a status page can make."
        ),
        responses={
            200: {"model": schemas.HealthResponse},
            503: {"model": schemas.HealthResponse, "description": "Stale or no data."},
        },
    )
    async def health() -> Response:
        """Liveness of *this service*, not of the network.

        Kept separate and named unambiguously because a monitoring system pointed
        at `/` would otherwise report our uptime as Epic Cash's uptime.

        Across every configured chain, not just mainnet. A sweep that stopped
        producing floonet snapshots while mainnet kept flowing is a broken observer,
        and an alert pointed here has to fire for it. The per-chain detail is
        published alongside so the page an operator opens next tells them which.
        """
        chains = service.chains()
        snaps = {c: service.snapshot_for(c) for c in chains}
        # `all()` over an empty mapping is True, which would report a service with no
        # targets at all as perfectly healthy. It has no data, so it is not.
        ok = bool(snaps) and all(s is not None and not s.stale for s in snaps.values())
        newest = [s.generated_at for s in snaps.values() if s is not None]
        return json_response(
            {
                "service": "epic-status",
                "version": "0.1.0",
                "prober_id": settings.prober_id,
                "has_data": any(s is not None for s in snaps.values()),
                "stale": not ok,
                "generated_at": stamp(max(newest)) if newest else None,
                "chains": {
                    c.value: {
                        "has_data": snap is not None,
                        "stale": snap.stale if snap is not None else True,
                        "generated_at": (
                            stamp(snap.generated_at) if snap is not None else None
                        ),
                    }
                    for c, snap in snaps.items()
                },
            },
            status_code=200 if ok else 503,
        )

    @app.post(
        "/api/v1/submit",
        tags=["submit"],
        summary="Add a node or relay",
        description=(
            "Accepts a form body. The target is validated and queued; it is probed "
            "out of band and appears on the board once it answers three times, 60 "
            "seconds apart.\n\n"
            "Hosts resolving to private, loopback, link-local or reserved addresses "
            "are refused before anything is stored or contacted. Epicbox hostnames "
            "may contain only letters, digits and dots — a hyphen means the relay "
            "handshakes fine but no wallet can parse an address on it."
        ),
        responses={
            202: {"model": schemas.SubmitAccepted, "description": "Queued for checking."},
            400: {"model": schemas.SubmitRejected, "description": "Refused, with the reason."},
        },
    )
    async def submit_api(
        request: Request,
        kind: Annotated[str, Form()] = "node",
        host: Annotated[str, Form()] = "",
        operator: Annotated[str, Form()] = "",
        country: Annotated[str, Form()] = "",
    ) -> Response:
        message, error = await _do_submit(
            service, request, kind, host, operator, country
        )
        if error:
            return json_response({"ok": False, "error": error}, status_code=400)
        # `message` is written for a human reading the form; a script needs the same facts
        # as values. `review_required` is unconditionally true and says so explicitly —
        # this field previously read `auto_promoted: true`, which stopped being true the
        # moment submissions started waiting for a decision, and a stale boolean in a
        # response is worse than no boolean at all. A caller polling for its host to
        # appear needs to know that nothing will happen until a person acts.
        return json_response(
            {
                "ok": True,
                "message": message,
                "next": {
                    "review_required": True,
                    "probed_automatically": kind != "pool",
                    "checks_required": settings.submit_probes_required,
                    "check_interval_s": settings.submit_probe_interval_s,
                    "then": "reviewed by an operator before it appears on the board",
                },
            },
            status_code=202,
        )

    return app


# --------------------------------------------------------------------- helpers


async def _run_validator(service: Service) -> None:
    """The submission validation loop.

    Its own clients, not the poller's: a pending submission is an unvetted host, and
    giving it a connection pool shared with the probes the board depends on would let
    a slow attacker-supplied host occupy slots the real work needs.
    """
    async with (
        build_client(timeout=service.settings.http_timeout_s) as client,
        build_client(timeout=service.settings.http_timeout_s, verify=False) as insecure,
    ):
        while True:
            try:
                await service.validator.tick(client, insecure)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("validator tick failed")
            await asyncio.sleep(_VALIDATOR_INTERVAL_S)


_CHECK_BODY_LIMIT = 4096


def _check_response(payload: dict[str, Any], status_code: int) -> Response:
    # No cors() here, deliberately: see quick_check_api.
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"cache-control": "no-store", **security_headers()},
    )


async def _quick_check_route(service: Service, request: Request) -> Response:
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return _check_response({"error": "cross-site requests are refused"}, 403)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return _check_response({"error": "send application/json"}, 415)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _CHECK_BODY_LIMIT:
            return _check_response({"error": "request body too large"}, 413)
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        data = None
    address = data.get("address") if isinstance(data, dict) else None
    defaults = data.get("defaults", False) if isinstance(data, dict) else False
    if not isinstance(address, str) or not isinstance(defaults, bool):
        return _check_response(
            {"error": 'send {"address": "<host[:port]>", "defaults": false}'}, 400
        )
    result = await service.quick_check(
        address, client_ip=client_address(request), use_defaults=defaults
    )
    # 429 for a visitor or target over its limit; 503 when every check slot is in use,
    # which is this server's state rather than anything the caller did.
    status = {"rate_limited": 429, "busy": 503}.get(result.error_kind or "", 200)
    response = _check_response(result.model_dump(mode="json"), status)
    if result.retry_after_s:
        response.headers["retry-after"] = str(result.retry_after_s)
    return response


async def _do_submit(
    service: Service,
    request: Request,
    kind: str,
    host: str,
    operator: str,
    country: str = "",
) -> tuple[str | None, str | None]:
    try:
        parsed_kind = Kind(kind.strip().lower())
    except ValueError:
        return None, "Choose a node, an Epicbox relay or a mining pool."
    try:
        message = await accept(
            service.db,
            service.settings,
            kind=parsed_kind,
            raw_host=host,
            operator=operator or None,
            submitter_address=client_address(request),
            salt=service.submitter_salt,
            country=country or None,
        )
    except SubmissionError as exc:
        return None, str(exc)
    return message, None




def _chain_or_404(raw: str) -> Chain:
    """Parse a `chain` parameter, or refuse.

    404 rather than a silent fallback to mainnet. `?chain=floonett` quietly serving
    mainnet numbers under a floonet-looking URL is the failure mode worth avoiding —
    it is indistinguishable from the real thing, and a reader would trust it.
    """
    try:
        return Chain(raw.lower())
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail=f"unknown chain {raw!r}; known chains are "
            f"{[c.value for c in Chain]}",
        ) from None


def _kind_or_none(raw: str | None) -> Kind | None:
    if raw is None:
        return None
    try:
        return Kind(raw.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown kind {raw!r}") from None


def _badge_label(status: TargetStatus) -> str:
    """`epic node`, `floonet relay` — the network and the role, not the host name,
    which the embedding page almost always prints beside the badge already."""
    network = "epic" if status.target.chain is Chain.MAINNET else status.target.chain.value
    role = {Kind.NODE: "node", Kind.EPICBOX: "epicbox", Kind.POOL: "pool"}[status.target.kind]
    return f"{network} {role}"


def _severity_or_400(raw: str) -> Severity:
    """Parse `?min=`, or refuse. A typo silently widening a feed to every notice is
    the kind of quiet wrongness this service avoids everywhere else."""
    try:
        return Severity(raw.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"unknown severity {raw!r}; use one of {[s.value for s in Severity]}",
        ) from None


def _serialise_event(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "kind": event.kind.value,
        "severity": event.severity.value,
        "subject": event.subject,
        "target": event.target_slug,
        "detail": event.detail,
        "depth": event.depth,
        "started_at": stamp(event.started_at),
        "ended_at": stamp(event.ended_at),
        "duration_s": event.duration_s,
        "measured_from": event.prober_id,
    }


def _probe_origins(snapshot: Snapshot | None) -> list[str]:
    """The origins the board's own rows point at, for `connect-src`.

    Enumerated rather than opened up. `connect-src https: wss:` would be one word and
    would let any future injection on this page talk to anywhere; this list says the page
    may talk to exactly the hosts it is currently displaying, and shrinks by itself when a
    target is removed. It is only attached to the board, because the board is the only
    page that asks the browser to connect anywhere.

    A CSP source is an origin, so the path is dropped: `https://host:3413`, not the
    `/v2/foreign` the fetch actually uses.
    """
    if snapshot is None:
        return []
    origins: set[str] = set()
    for status in (*snapshot.nodes, *snapshot.epicbox, *snapshot.pools):
        url = probe_url(status.target)
        if not url:
            continue
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            origins.add(f"{parts.scheme}://{parts.netloc}")
    return sorted(origins)




def _serialise(snap: Snapshot, settings: Settings) -> dict[str, Any]:
    net = snap.network
    return {
        # The payload says what it is. Anything that reaches this route without having
        # read the reference page — a script, a search result, someone else's dashboard —
        # can still tell what the numbers are and what they are not.
        "meta": {
            "describes": "Health of Epic Cash mainnet public nodes, Epicbox relays and mining pools",
            "states": {
                "healthy": "answered its last check, and for a node is within the tip-lag threshold",
                "degraded": "reachable but not fully usable, or a failure not yet confirmed",
                "down": "failed consecutive checks",
            },
            "fields": {
                "tip_lag": "blocks behind the highest tip seen; the field to alert on",
                "last_block_height": "pools only: the last block that pool FOUND, not a chain tip",
                "uptime": "fractions, or null where there is no history — never 0",
            },
            "absent": [
                "peer_count and sync status need a node's owner API secret",
                "latency is measured from one vantage point only",
                "country is a registry guess, provider is reliable",
            ],
            "docs": f"{settings.site_url.rstrip('/')}/api",
            "schema": f"{settings.site_url.rstrip('/')}/api/openapi.json",
        },
        "generated_at": stamp(snap.generated_at),
        "stale": snap.stale,
        "prober": {
            "id": snap.prober_id,
            "region": settings.prober_region,
            "measures": "reachability and round-trip latency from this host only",
        },
        "network": {
            # `.value`, not the member. `Chain` subclasses `str` so json.dumps would
            # in fact emit "mainnet" — but relying on that means the wire format is
            # decided by an implementation detail of the enum base class, and a later
            # change to a plain Enum would silently start publishing "Chain.MAINNET".
            "chain": net.chain.value,
            "tip_height": net.tip_height,
            "tip_hash": net.tip_hash,
            "tip_age_s": net.tip_age_s,
            "tip_mined_at": stamp(net.tip_mined_at),
            "health_score": net.health_score,
            "forked": net.forked,
            "fork_detail": net.fork_detail,
            "nodes_total": net.nodes_total,
            "nodes_healthy": net.nodes_healthy,
            "nodes_degraded": net.nodes_degraded,
            "nodes_down": net.nodes_down,
            "epicbox_total": net.epicbox_total,
            "epicbox_healthy": net.epicbox_healthy,
            "epicbox_degraded": net.epicbox_degraded,
            "epicbox_down": net.epicbox_down,
            "pools_total": net.pools_total,
            "pools_healthy": net.pools_healthy,
            "pools_degraded": net.pools_degraded,
            "pools_down": net.pools_down,
            "median_node_latency_ms": net.median_node_latency_ms,
            "median_epicbox_latency_ms": net.median_epicbox_latency_ms,
            "median_pool_latency_ms": net.median_pool_latency_ms,
            "countries": net.countries,
            "providers": net.providers,
            "co_hosted_addresses": net.co_hosted,
            "released_node_version": net.released_node_version,
            "nodes_current": net.nodes_current,
            "nodes_versioned": net.nodes_versioned,
            "activity": (
                net.activity.model_dump(mode="json") if net.activity is not None else None
            ),
        },
        "nodes": [_serialise_target(s) for s in snap.nodes],
        "epicbox": [_serialise_target(s) for s in snap.epicbox],
        "pools": [_serialise_target(s) for s in snap.pools],
    }


def _round4(value: float | None) -> float | None:
    """Four decimal places, preserving None.

    None is not zero anywhere in this payload: a target with no history has no uptime, and
    publishing 0.0 for one is how a status page libels an operator.
    """
    return None if value is None else round(value, 4)


def _list_meta(
    *,
    describes: str,
    healthy: bool,
    count: int,
    total: int,
    cadence_s: float,
    settings: Settings,
) -> dict[str, Any]:
    """The self-description carried by every list route.

    A bare array of URLs is not usable without knowing whether it was filtered, how
    stale it can be, and where the measurements behind it came from. That used to be
    documented only on /api, which a script cannot read. Answering it in the response
    costs four keys and means the route needs no prose at all.
    """
    return {
        "describes": describes,
        "filtered": "healthy" if healthy else "all",
        "count": count,
        "total_monitored": total,
        "refreshed_every_s": cadence_s,
        "measured_from": settings.prober_id,
        "docs": f"{settings.site_url.rstrip('/')}/api",
    }


def _serialise_target(status: TargetStatus) -> dict[str, Any]:
    target = status.target
    row: dict[str, Any] = {
        "id": target.slug,
        "kind": target.kind.value,
        "host": target.display_host,
        "endpoint": target.endpoint,
        "operator": target.operator,
        "label": target.label,
        "notes": target.notes,
        # Renamed from `self_hosted`. That field meant "run by the instance operator",
        # which told a consumer something about us rather than something about the host.
        # `verified` says an operator has checked this server and stands behind it, and
        # `listing` gives the same fact as the value the board groups by.
        "verified": target.verified,
        "listing": target.listing,
        "source": target.source.value,
        "state": status.state.value,
        "reason": status.reason.value,
        "detail": status.detail,
        "latency_ms": status.latency_ms,
        "last_checked_at": stamp(status.last_checked_at),
        "last_ok_at": stamp(status.last_ok_at),
        "last_error": status.last_error,
        "error_count": status.consecutive_failures,
        # Rounded to four places. `0.9977628635346756` is float64 noise dressed as
        # precision: the underlying figure is a ratio of integer check counts, nobody
        # alerts on the eleventh decimal, and four places resolves a single basis point —
        # finer than the data justifies already. None stays None; rounding it to 0.0 would
        # turn "no history" into "never up".
        "uptime": {
            "1h": _round4(status.uptime_1h),
            "24h": _round4(status.uptime_24h),
            "30d": _round4(status.uptime_30d),
        },
        "location": {
            "country": target.geo.display_country,
            "country_registry": target.geo.country,
            "city": target.geo.display_city,
            "provider": target.geo.display_provider,
            "network_name": target.geo.network_name,
            # Flagged as a registry guess rather than presented as a fact. RDAP
            # records are inconsistent about country and some carry none at all.
            "source": "registry",
        },
        # Other probers' newest checks. Evidence beside `state`, never an input to it.
        "vantages": [
            {
                "prober": v.prober_id,
                "ok": v.ok,
                "latency_ms": v.latency_ms,
                "error": v.error,
                "checked_at": stamp(v.at),
            }
            for v in status.vantages
        ],
    }
    # Exhaustive on purpose rather than if-node-else: an `else` arm silently
    # serialised every future kind as a relay, with null protocol and cert fields
    # and none of its own.
    if target.kind is Kind.NODE:
        row["height"] = status.height
        row["tip_lag"] = status.tip_lag
        row["tip_hash"] = status.tip_hash
        row["node_version"] = status.node_version
        row["ipv6"] = status.ipv6.value if status.ipv6 is not None else None
        row["browser_access"] = status.browser_access
    elif target.kind is Kind.EPICBOX:
        row["protocol_version"] = status.protocol_version
        row["cert_expires_in_days"] = status.cert_expires_in_days
        row["ipv6"] = status.ipv6.value if status.ipv6 is not None else None
    elif target.kind is Kind.POOL:
        row["miners"] = status.miners
        row["workers"] = status.workers
        row["fee_percent"] = status.fee_percent
        # The last block the pool FOUND, not its chain tip. Named so that no
        # consumer mistakes it for one and compares it to tip_height.
        row["last_block_height"] = status.last_block_height
        row["last_block_at"] = stamp(status.last_block_at)
    return row
