"""HTTP layer: the board, the JSON API, and the submit endpoint.

Everything a visitor touches is served from the in-memory snapshot. No request path
probes anything. That is the most important property of this file — see the poller's
module docstring for why a status page that fans out per visitor becomes an attack
on the hosts it monitors.

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

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import Settings, load_seed_targets
from .config import settings as get_settings
from .db import Database
from .models import Kind, Snapshot, State, TargetStatus
from .net import build_client
from .poller import Poller
from .render import render_board, render_history, render_submit
from .submit import SubmissionError, Validator, accept

log = logging.getLogger("epic_status.api")

STATIC_DIR = Path(__file__).parent / "static"

_VALIDATOR_INTERVAL_S = 15.0
"""How often pending submissions are checked. Slow on purpose: a pending submission
is an unvetted host and must not share a deadline with the probes the board needs."""


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
        # Rotated per process and never persisted. The submitter hashes in the
        # database therefore cannot be reversed even by someone holding the
        # database, and stop being linkable across restarts — the right trade for a
        # value whose only job is rate limiting.
        self.submitter_salt = secrets.token_hex(16)

    @property
    def snapshot(self) -> Snapshot | None:
        snap = self.poller.snapshot
        if snap is None:
            return None
        age = (datetime.now(UTC) - snap.generated_at).total_seconds()
        # Say so rather than presenting frozen numbers as live. A status page that
        # lies about its own freshness has no claim to be trusted about anything.
        snap.stale = age > self.settings.thresholds.stale_snapshot_s
        return snap


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
        service.db.close()

    app = FastAPI(
        title="epic-status",
        description="Health and uptime for Epic Cash public nodes and Epicbox relays",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.state.service = service

    # ------------------------------------------------------------------ pages

    @app.get("/", response_class=HTMLResponse)
    async def board(request: Request) -> HTMLResponse:
        html = render_board(
            snapshot=service.snapshot,
            settings=settings,
            request_region=_reader_region(request),
        )
        return HTMLResponse(
            html,
            headers={
                # The board is a live document. Caching it for even a few seconds
                # means a reader refreshing during an outage sees the outage
                # they already saw.
                "cache-control": "no-store",
                **_security_headers(),
            },
        )

    @app.get("/history", response_class=HTMLResponse)
    async def history() -> HTMLResponse:
        snap = service.snapshot
        bars = {}
        if snap is not None:
            for status in snap.nodes + snap.epicbox:
                if status.target.id is not None:
                    bars[status.target.slug] = service.db.daily_uptime(
                        status.target.id, 90
                    )
        html = render_history(snapshot=snap, settings=settings, bars=bars)
        return HTMLResponse(
            html, headers={"cache-control": "no-store", **_security_headers()}
        )

    @app.get("/add", response_class=HTMLResponse)
    async def add_form() -> HTMLResponse:
        return HTMLResponse(
            render_submit(snapshot=service.snapshot, settings=settings),
            headers={"cache-control": "no-store", **_security_headers()},
        )

    @app.post("/add", response_class=HTMLResponse)
    async def add_submit(
        request: Request,
        kind: Annotated[str, Form()] = "node",
        host: Annotated[str, Form()] = "",
        operator: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        message, error = await _do_submit(service, request, kind, host, operator)
        return HTMLResponse(
            render_submit(
                snapshot=service.snapshot,
                settings=settings,
                message=message,
                error=error,
                submitted_host=host,
            ),
            status_code=200 if message else 400,
            headers={"cache-control": "no-store", **_security_headers()},
        )

    # -------------------------------------------------------------------- api

    @app.get("/api/v1/status.json")
    async def status_json(request: Request) -> Response:
        snap = service.snapshot
        if snap is None:
            return _json(
                {"error": "no data yet", "generated_at": None},
                status_code=503,
            )
        payload = _serialise(snap, settings)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        etag = '"' + hashlib.sha256(body.encode()).hexdigest()[:32] + '"'
        if request.headers.get("if-none-match") == etag:
            # A poller consuming this API costs nothing when nothing has changed,
            # which is the difference between being integrable and being a burden.
            return Response(status_code=304, headers={"etag": etag, **_cors()})
        return Response(
            body,
            media_type="application/json",
            headers={"etag": etag, "cache-control": "no-store", **_cors()},
        )

    @app.get("/api/v1/nodes.json")
    async def nodes_json(healthy: bool = False) -> Response:
        """A bare list of endpoints, which is what a wallet or an exchange failover
        config actually wants. `?healthy=true` filters to the ones worth using."""
        snap = service.snapshot
        if snap is None:
            return _json({"error": "no data yet"}, status_code=503)
        rows = [
            s
            for s in snap.nodes
            if not healthy or s.state is State.HEALTHY
        ]
        return _json(
            {
                "generated_at": _stamp(snap.generated_at),
                "chain": snap.network.chain,
                "tip_height": snap.network.tip_height,
                "nodes": [s.target.endpoint for s in rows],
            }
        )

    @app.get("/api/v1/epicbox.json")
    async def epicbox_json(healthy: bool = False) -> Response:
        snap = service.snapshot
        if snap is None:
            return _json({"error": "no data yet"}, status_code=503)
        rows = [s for s in snap.epicbox if not healthy or s.state is State.HEALTHY]
        return _json(
            {
                "generated_at": _stamp(snap.generated_at),
                "epicbox": [s.target.display_host for s in rows],
            }
        )

    @app.get("/api/v1/health")
    async def health() -> Response:
        """Liveness of *this service*, not of the network.

        Kept separate and named unambiguously because a monitoring system pointed
        at `/` would otherwise report our uptime as Epic Cash's uptime.
        """
        snap = service.snapshot
        return _json(
            {
                "service": "epic-status",
                "version": "0.1.0",
                "prober_id": settings.prober_id,
                "has_data": snap is not None,
                "stale": snap.stale if snap else True,
                "generated_at": _stamp(snap.generated_at) if snap else None,
            },
            status_code=200 if snap is not None and not snap.stale else 503,
        )

    @app.post("/api/v1/submit")
    async def submit_api(
        request: Request,
        kind: Annotated[str, Form()] = "node",
        host: Annotated[str, Form()] = "",
        operator: Annotated[str, Form()] = "",
    ) -> Response:
        message, error = await _do_submit(service, request, kind, host, operator)
        if error:
            return _json({"ok": False, "error": error}, status_code=400)
        return _json({"ok": True, "message": message}, status_code=202)

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


async def _do_submit(
    service: Service, request: Request, kind: str, host: str, operator: str
) -> tuple[str | None, str | None]:
    try:
        parsed_kind = Kind(kind.strip().lower())
    except ValueError:
        return None, "Choose either a node or an Epicbox relay."
    try:
        message = await accept(
            service.db,
            service.settings,
            kind=parsed_kind,
            raw_host=host,
            operator=operator or None,
            submitter_address=_client_address(request),
            salt=service.submitter_salt,
        )
    except SubmissionError as exc:
        return None, str(exc)
    return message, None


def _client_address(request: Request) -> str:
    """The submitter's address, for rate limiting only.

    `x-forwarded-for` is trusted because this service is designed to run behind a
    reverse proxy on loopback and cannot be reached directly. If you bind it to a
    public interface — which the settings tell you not to do — this becomes
    spoofable and the rate limit becomes decorative.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _reader_region(request: Request) -> str | None:
    """A coarse hint for ordering, if the proxy supplies one.

    Deliberately limited to a header a reverse proxy or CDN may already set. This
    service does not geolocate its readers: their address is in the access log
    because they made a request, and turning that into a stored location is a
    different thing from serving a page.
    """
    for header in ("cf-ipcountry", "x-country-code"):
        value = request.headers.get(header)
        if value and len(value) == 2 and value.isalpha():
            return value.upper()
    return None


def _security_headers() -> dict[str, str]:
    """Set here rather than in nginx so a self-hoster behind any proxy gets them.

    The CSP has no `unsafe-inline` for scripts: the board's JavaScript is a real
    file under /static, which is also why it is auditable.
    """
    return {
        "content-security-policy": (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            # Without this the self-hosted Montserrat files are blocked by
            # default-src and the page silently falls back to the system stack.
            # Caught by screenshotting the real page rather than by any test.
            "font-src 'self'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        ),
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        "cross-origin-opener-policy": "same-origin",
    }


def _cors() -> dict[str, str]:
    """Read-only cross-origin access, on the JSON routes only.

    Open on purpose: the point of publishing this is that wallets, explorers and
    exchanges can read it from a browser without proxying it.
    """
    return {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET",
        "vary": "origin",
    }


def _json(payload: dict[str, Any], status_code: int = 200) -> Response:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"cache-control": "no-store", **_cors()},
    )


def _stamp(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialise(snap: Snapshot, settings: Settings) -> dict[str, Any]:
    net = snap.network
    return {
        "generated_at": _stamp(snap.generated_at),
        "stale": snap.stale,
        "prober": {
            "id": snap.prober_id,
            "region": settings.prober_region,
            # Spelled out because a latency figure from a single vantage point is a
            # statement about that vantage point's network, not about the target.
            "note": "latency is measured from this prober only",
        },
        "network": {
            "chain": net.chain,
            "tip_height": net.tip_height,
            "tip_hash": net.tip_hash,
            "tip_age_s": net.tip_age_s,
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
            "median_node_latency_ms": net.median_node_latency_ms,
            "median_epicbox_latency_ms": net.median_epicbox_latency_ms,
            "countries": net.countries,
            "providers": net.providers,
            "co_hosted_addresses": net.co_hosted,
        },
        "nodes": [_serialise_target(s) for s in snap.nodes],
        "epicbox": [_serialise_target(s) for s in snap.epicbox],
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
        "self_hosted": target.ours,
        "source": target.source.value,
        "state": status.state.value,
        "reason": status.reason.value,
        "detail": status.detail,
        "latency_ms": status.latency_ms,
        "last_checked_at": _stamp(status.last_checked_at),
        "last_ok_at": _stamp(status.last_ok_at),
        "last_error": status.last_error,
        "error_count": status.consecutive_failures,
        "uptime": {
            "1h": status.uptime_1h,
            "24h": status.uptime_24h,
            "30d": status.uptime_30d,
        },
        "history": status.history,
        "location": {
            "country": target.geo.display_country,
            "country_registry": target.geo.country,
            "city": target.geo.city,
            "provider": target.geo.provider,
            "network_name": target.geo.network_name,
            # Flagged as a registry guess rather than presented as a fact. RDAP
            # records are inconsistent about country and some carry none at all.
            "source": "registry",
        },
    }
    if target.kind is Kind.NODE:
        row["height"] = status.height
        row["tip_lag"] = status.tip_lag
        row["tip_hash"] = status.tip_hash
        row["node_version"] = status.node_version
    else:
        row["protocol_version"] = status.protocol_version
        row["cert_expires_in_days"] = status.cert_expires_in_days
    return row
