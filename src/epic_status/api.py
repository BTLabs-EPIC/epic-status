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
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import admin
from .config import Settings, load_seed_targets
from .config import settings as get_settings
from .db import Database
from .models import Chain, Kind, Snapshot, Source, State, Target, TargetStatus
from .net import build_client
from .poller import Poller
from .render import (
    probe_url,
    render_admin,
    render_admin_login,
    render_api,
    render_board,
    render_history,
    render_submit,
)
from . import schemas
from .submit import SubmissionError, Validator, accept

log = logging.getLogger("epic_status.api")

STATIC_DIR = Path(__file__).parent / "static"

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
        # Rotated per process and never persisted. The submitter hashes in the
        # database therefore cannot be reversed even by someone holding the
        # database, and stop being linkable across restarts — the right trade for a
        # value whose only job is rate limiting.
        self.submitter_salt = secrets.token_hex(16)

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
                **_security_headers(connect=_probe_origins(snap)),
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
            chain=selected,
            chains=service.chains(),
        )
        return HTMLResponse(
            html, headers={"cache-control": "no-store", **_security_headers()}
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
            headers={"cache-control": "no-store", **_security_headers()},
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
            headers={"cache-control": "no-store", **_security_headers()},
        )

    # Both forms. nginx normalises /api to /api/ because a /api/ prefix location
    # exists, and with only the bare path registered that redirect landed on a 404.
    @app.api_route("/api", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/api/", methods=["GET", "HEAD"], include_in_schema=False)
    async def api_reference() -> HTMLResponse:
        return HTMLResponse(
            render_api(settings=settings),
            headers={"cache-control": "no-store", **_security_headers()},
        )

    @app.api_route("/api/docs", methods=["GET", "HEAD"], include_in_schema=False)
    async def api_docs_redirect() -> Response:
        """Kept so the old path still lands somewhere. It was a CDN-backed Swagger
        page that could not load under this service's CSP."""
        return Response(status_code=308, headers={"location": "/api"})


    # ------------------------------------------------------------------- admin
    #
    # The one surface that is not public and not read-only. Approving a submission makes
    # this service start probing a stranger's host and publishes it to every consumer of
    # the API, so it sits behind a login, a CSRF token and a rate limit.
    #
    # Registered only when a password hash is configured. Without one these routes do not
    # exist and /admin is an ordinary 404 — not a login form, which would advertise the
    # surface, and not a default credential, which on a self-hosted service is a published
    # one.
    sessions = admin.Sessions()

    if settings.admin_password_hash:
        _ADMIN_COOKIE = "epic_status_admin"

        def _admin_cookie(response: Response, token: str) -> None:
            response.set_cookie(
                _ADMIN_COOKIE,
                token,
                max_age=admin.SESSION_TTL_S,
                httponly=True,
                secure=settings.admin_cookie_secure,
                samesite="strict",
                path="/admin",
            )

        def _session(request: Request) -> admin.Session | None:
            return sessions.get(request.cookies.get(_ADMIN_COOKIE))

        def _login_page(error: str | None = None, status_code: int = 200) -> HTMLResponse:
            return HTMLResponse(
                render_admin_login(settings=settings, error=error),
                status_code=status_code,
                headers={"cache-control": "no-store", **_security_headers()},
            )

        def _dashboard(session: admin.Session, notice: str | None = None) -> HTMLResponse:
            return HTMLResponse(
                render_admin(
                    settings=settings,
                    submissions=service.db.submissions(),
                    counts=service.db.submission_counts(),
                    # The number actually on the board, not the number of submissions ever
                    # approved. Those differ for every seed target, which is most of them:
                    # the old value read 0 while eight hosts were being published.
                    on_board=len(service.db.targets()),
                    # Disabled targets included: a disabled host is exactly the one an
                    # admin needs to find in order to re-enable it, and hiding it here
                    # would make the action unreachable.
                    targets=service.db.targets(enabled_only=False),
                    csrf=session.csrf,
                    user=session.user,
                    notice=notice,
                ),
                headers={
                    "cache-control": "no-store",
                    # A review dashboard has no business in a shared cache or a
                    # search index, and `noindex` is cheap insurance against the
                    # latter even behind a login.
                    "x-robots-tag": "noindex, nofollow",
                    **_security_headers(),
                },
            )

        @app.api_route(
            "/admin", methods=["GET", "HEAD"], response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def admin_home(request: Request) -> HTMLResponse:
            session = _session(request)
            return _dashboard(session) if session else _login_page()

        @app.post("/admin/login", response_class=HTMLResponse, include_in_schema=False)
        async def admin_login(
            request: Request,
            user: Annotated[str, Form()] = "",
            password: Annotated[str, Form()] = "",
        ) -> Response:
            client = _client_address(request)
            if sessions.locked_out(client):
                log.warning("admin login refused, too many attempts from %s", client)
                return _login_page("Too many attempts. Try again later.", 429)
            if not admin.check_credentials(
                user=user,
                password=password,
                expected_user=settings.admin_user,
                stored_hash=settings.admin_password_hash,
            ):
                sessions.record_failure(client)
                log.warning("admin login failed from %s", client)
                # One message for both halves. "No such user" would let anyone
                # enumerate the account name.
                return _login_page("Wrong username or password.", 401)
            sessions.clear_failures(client)
            session = sessions.create(settings.admin_user)
            log.info("admin login from %s", client)
            # Redirect rather than render, so a refresh does not repost the password.
            response = Response(status_code=303, headers={"location": "/admin"})
            _admin_cookie(response, session.token)
            return response

        @app.post("/admin/logout", include_in_schema=False)
        async def admin_logout(request: Request) -> Response:
            sessions.destroy(request.cookies.get(_ADMIN_COOKIE))
            response = Response(status_code=303, headers={"location": "/admin"})
            response.delete_cookie(_ADMIN_COOKIE, path="/admin")
            return response

        # ---- JSON endpoints, for the dashboard's per-field saves ----
        #
        # The form POSTs below still work and still re-render the page; these exist so the
        # page does not have to. Keeping both means the dashboard degrades to plain forms
        # with JavaScript off, which for the one surface that edits the board is worth the
        # duplication.

        def _json_session(request: Request, csrf: str) -> tuple[admin.Session | None, Response | None]:
            session = _session(request)
            if session is None:
                return None, _json({"ok": False, "error": "signed out"}, status_code=401)
            if not sessions.valid_csrf(session, csrf):
                return None, _json({"ok": False, "error": "stale token"}, status_code=403)
            return session, None

        @app.post("/admin/api/patch", include_in_schema=False)
        async def admin_patch(
            request: Request,
            target_id: Annotated[int, Form()] = 0,
            field: Annotated[str, Form()] = "",
            value: Annotated[str, Form()] = "",
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            """Write one field and say what happened. No redirect, no re-render."""
            _, refusal = _json_session(request, csrf)
            if refusal is not None:
                return refusal
            target = service.db.target(target_id)
            if target is None:
                return _json({"ok": False, "error": "no such target"}, status_code=404)
            if not service.db.set_target_field(target_id, field, value):
                return _json({"ok": False, "error": "field not editable"}, status_code=400)
            saved = service.db.target(target_id)
            assert saved is not None
            log.info("admin set %s.%s", saved.slug, field)
            # The stored value is returned rather than echoed from the request, so the page
            # shows what the database holds — a trimmed string or an uppercased country code
            # is not what was typed.
            return _json(
                {
                    "ok": True,
                    "host": saved.display_host,
                    "field": field,
                    "listing": saved.listing,
                    "verified": saved.verified,
                    "enabled": saved.enabled,
                    "value": {
                        "operator": saved.operator or "",
                        "label": saved.label or "",
                        "notes": saved.notes or "",
                        "country": saved.geo.country_manual or "",
                        "provider": saved.geo.provider_manual or "",
                        "city": saved.geo.city_manual or "",
                    }.get(field, value),
                }
            )

        @app.post("/admin/api/request/remove", include_in_schema=False)
        async def admin_request_remove(
            request: Request,
            submission_id: Annotated[int, Form()] = 0,
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            """Delete a request outright, as opposed to rejecting it.

            Rejecting keeps the record and, through the unique constraint on (kind, host),
            keeps the host from being resubmitted. Deleting frees it — right for a typo or a
            test entry, wrong for something genuinely declined.
            """
            _, refusal = _json_session(request, csrf)
            if refusal is not None:
                return refusal
            row = service.db.submission(submission_id)
            if row is None:
                return _json({"ok": False, "error": "gone"}, status_code=404)
            host = str(row["host"])
            if not service.db.delete_submission(submission_id):
                return _json({"ok": False, "error": "nothing removed"}, status_code=409)
            log.info("admin deleted request %s", host)
            return _json({"ok": True, "host": host})

        @app.post("/admin/api/remove", include_in_schema=False)
        async def admin_api_remove(
            request: Request,
            target_id: Annotated[int, Form()] = 0,
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            _, refusal = _json_session(request, csrf)
            if refusal is not None:
                return refusal
            target = service.db.target(target_id)
            if target is None:
                return _json({"ok": False, "error": "no such target"}, status_code=404)
            if not service.db.delete_target_admin(target_id):
                return _json({"ok": False, "error": "nothing removed"}, status_code=409)
            log.warning("admin removed target %s and its history", target.slug)
            return _json(
                {
                    "ok": True,
                    "host": target.display_host,
                    # A seed is reloaded from config/targets.toml at every boot, so the row
                    # is gone but the target is not. The page says so instead of implying a
                    # permanence it does not have.
                    "returns_on_restart": target.source is Source.SEED,
                }
            )

        @app.post("/admin/review/json", include_in_schema=False)
        async def admin_review_json(
            request: Request,
            submission_id: Annotated[int, Form()] = 0,
            decision: Annotated[str, Form()] = "",
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            _, refusal = _json_session(request, csrf)
            if refusal is not None:
                return refusal
            row = service.db.submission(submission_id)
            if row is None:
                return _json({"ok": False, "error": "gone"}, status_code=404)
            if row["status"] in ("accepted", "rejected"):
                return _json({"ok": False, "error": "already decided"}, status_code=409)
            host = str(row["host"])
            if decision == "approve":
                service.db.insert_target(
                    Target(
                        kind=Kind(row["kind"]),
                        # Public submissions are mainnet. The form does not offer a
                        # chain and should not: floonet hosts are ours and belong in
                        # the committed registry, where a reviewer can see them, and a
                        # stranger's endpoint claiming to be floonet is a claim this
                        # service has no way to check.
                        chain=Chain.MAINNET,
                        slug=host,
                        endpoint=str(row["endpoint"]),
                        display_host=host,
                        operator=row["operator"],
                        source=Source.SUBMITTED,
                    )
                )
                if row["country"]:
                    for candidate in service.db.targets(enabled_only=False):
                        if candidate.slug == host and candidate.id is not None:
                            service.db.set_target_field(
                                candidate.id, "country", str(row["country"])
                            )
                            break
                service.db.review_submission(
                    submission_id, status="accepted", note="approved"
                )
                log.info("admin approved %s", host)
                return _json({"ok": True, "host": host, "status": "accepted"})
            if decision == "reject":
                service.db.review_submission(
                    submission_id, status="rejected", note="rejected"
                )
                log.info("admin rejected %s", host)
                return _json({"ok": True, "host": host, "status": "rejected"})
            return _json({"ok": False, "error": "unknown decision"}, status_code=400)

        @app.post("/admin/remove", response_class=HTMLResponse, include_in_schema=False)
        async def admin_remove(
            request: Request,
            target_id: Annotated[int, Form()] = 0,
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            """Delete a target and everything measured about it.

            Irreversible, and it takes real history with it: `checks` and `rollup_hourly`
            cascade on `target_id`, and nothing can reconstruct when a host was last up.
            That is why the alternative exists and is one click away — unticking `Checked`
            stops the probing and keeps the record, which is what an operator wants almost
            every time. Removal is for a row that should never have been created.
            """
            session = _session(request)
            if session is None:
                return _login_page("Session expired.", 401)
            if not sessions.valid_csrf(session, csrf):
                return _dashboard(session, notice="Request rejected: stale form. Retry.")
            target = service.db.target(target_id)
            if target is None:
                return _dashboard(session, notice="No such target.")
            if not service.db.delete_target_admin(target_id):
                return _dashboard(session, notice="Nothing was removed.")
            log.warning("admin removed target %s and its history", target.slug)
            if target.source is Source.SEED:
                # A seed is reloaded from config/targets.toml at every boot, so deleting the
                # row here is temporary. Saying so is the difference between a working
                # control and one that appears to work until the next restart.
                return _dashboard(
                    session,
                    notice=(
                        f"{target.display_host} removed — but it is a seed target and will "
                        "return on the next restart unless it is also deleted from "
                        "config/targets.toml. Untick Checked to keep it off the board."
                    ),
                )
            return _dashboard(session, notice=f"{target.display_host} removed.")

        @app.post("/admin/request/remove", response_class=HTMLResponse, include_in_schema=False)
        async def admin_request_remove_form(
            request: Request,
            submission_id: Annotated[int, Form()] = 0,
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            """The no-JavaScript path for the same thing."""
            session = _session(request)
            if session is None:
                return _login_page("Session expired.", 401)
            if not sessions.valid_csrf(session, csrf):
                return _dashboard(session, notice="Request rejected: stale form. Retry.")
            row = service.db.submission(submission_id)
            if row is None:
                return _dashboard(session, notice="That request no longer exists.")
            host = str(row["host"])
            service.db.delete_submission(submission_id)
            log.info("admin deleted request %s", host)
            return _dashboard(session, notice=f"Request for {host} deleted.")

        @app.post("/admin/review", response_class=HTMLResponse, include_in_schema=False)
        async def admin_review(
            request: Request,
            submission_id: Annotated[int, Form()] = 0,
            decision: Annotated[str, Form()] = "",
            csrf: Annotated[str, Form()] = "",
        ) -> Response:
            session = _session(request)
            if session is None:
                return _login_page("Session expired.", 401)
            if not sessions.valid_csrf(session, csrf):
                log.warning("admin review rejected: bad CSRF token")
                return _dashboard(session, notice="Request rejected: stale form. Retry.")

            row = service.db.submission(submission_id)
            if row is None:
                return _dashboard(session, notice="That request no longer exists.")
            if row["status"] in ("accepted", "rejected"):
                return _dashboard(session, notice="Already decided.")

            host = str(row["host"])
            if decision == "approve":
                # The target is created here, by a person, rather than by the validator.
                # This is the only path onto the board for a submitted host.
                service.db.insert_target(
                    Target(
                        kind=Kind(row["kind"]),
                        # Mainnet, for the reason given at the other approval site: the
                        # form offers no chain, and an unverifiable claim to be floonet
                        # is not a claim this service should publish.
                        chain=Chain.MAINNET,
                        slug=host,
                        endpoint=str(row["endpoint"]),
                        display_host=host,
                        operator=row["operator"],
                        source=Source.SUBMITTED,
                    )
                )
                # The submitter's country hint becomes the hand-set override, which is
                # where a correction belongs: RDAP is routinely wrong and the person running
                # the host is not. An admin can change or clear it in the editor below.
                if row["country"]:
                    created = service.db.targets(enabled_only=False)
                    for candidate in created:
                        if candidate.slug == host and candidate.id is not None:
                            service.db.set_geo_overrides(
                                candidate.id,
                                country=str(row["country"]),
                                provider="",
                                city="",
                            )
                            break
                service.db.review_submission(
                    submission_id, status="accepted", note="approved"
                )
                log.info("admin approved %s", host)
                return _dashboard(session, notice=f"{host} added to the board.")

            if decision == "reject":
                service.db.review_submission(
                    submission_id, status="rejected", note="rejected"
                )
                log.info("admin rejected %s", host)
                return _dashboard(session, notice=f"{host} rejected.")

            return _dashboard(session, notice="Unknown decision.")


        @app.post("/admin/target", response_class=HTMLResponse, include_in_schema=False)
        async def admin_target(
            request: Request,
            target_id: Annotated[int, Form()] = 0,
            csrf: Annotated[str, Form()] = "",
            operator: Annotated[str, Form()] = "",
            label: Annotated[str, Form()] = "",
            notes: Annotated[str, Form()] = "",
            country: Annotated[str, Form()] = "",
            provider: Annotated[str, Form()] = "",
            city: Annotated[str, Form()] = "",
            toggle: Annotated[str, Form()] = "",
        ) -> Response:
            """Edit a monitored target.

            Everything editable here is a fact nothing can derive: who runs a host, what to
            call it, and the location fields where RDAP is routinely wrong. Identity —
            `slug`, `kind`, `endpoint` — is not editable, because `checks.target_id` points
            at this row and repointing it would attribute one host's history to another.

            The geo values are written as `*_manual` overrides rather than over the
            registry's own answer, so a weekly refresh cannot undo a correction and an
            empty field restores whatever RDAP said.
            """
            session = _session(request)
            if session is None:
                return _login_page("Session expired.", 401)
            if not sessions.valid_csrf(session, csrf):
                return _dashboard(session, notice="Request rejected: stale form. Retry.")

            target = service.db.target(target_id)
            if target is None:
                return _dashboard(session, notice="No such target.")

            # The two flags are no longer checkboxes on this form, so they are not read from
            # it: an absent checkbox is indistinguishable from an unticked one, and with the
            # inputs gone that would have silently cleared both on every text edit. They move
            # only through an explicit toggle, which is what the tags submit.
            service.db.update_target_fields(
                target_id,
                operator=operator.strip(),
                label=label.strip(),
                notes=notes.strip(),
                verified=target.verified,
                enabled=target.enabled,
            )
            if toggle == "verified":
                service.db.set_target_field(
                    target_id, "verified", "0" if target.verified else "1"
                )
            elif toggle == "enabled":
                service.db.set_target_field(
                    target_id, "enabled", "0" if target.enabled else "1"
                )
            service.db.set_geo_overrides(
                target_id, country=country, provider=provider, city=city
            )
            # No cache to invalidate: `Poller.sweep` reads `db.targets()` at the top of
            # every sweep, so an edit is live on the next one — within 5 seconds for a node.
            log.info("admin edited target %s", target.slug)
            return _dashboard(session, notice=f"{target.display_host} updated.")

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
    async def status_json(request: Request, chain: str = "mainnet") -> Response:
        """`?chain=floonet` for the test network. Absent means mainnet, so every
        existing consumer of this endpoint keeps receiving exactly what it did."""
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return _json(
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
            return Response(status_code=304, headers={"etag": etag, **_cors()})
        return Response(
            body,
            media_type="application/json",
            headers={"etag": etag, "cache-control": "no-store", **_cors()},
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
    async def nodes_json(healthy: bool = False, chain: str = "mainnet") -> Response:
        """A bare list of endpoints, which is what a wallet or an exchange failover
        config actually wants. `?healthy=true` filters to the ones worth using.

        One chain per response, mainnet by default. A wallet asking for node endpoints
        must never be handed a floonet address mixed in with mainnet ones — it would
        connect, sync a different chain, and look broken for reasons nothing on this
        page explains."""
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return _json({"error": "no data yet"}, status_code=503)
        rows = [
            s
            for s in snap.nodes
            if not healthy or s.state is State.HEALTHY
        ]
        return _json(
            {
                "meta": _list_meta(
                    describes=f"Epic Cash {selected.value} public node endpoints",
                    healthy=healthy,
                    count=len(rows),
                    total=len(snap.nodes),
                    cadence_s=settings.cadence.node_tip_s,
                    settings=settings,
                ),
                "generated_at": _stamp(snap.generated_at),
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
    async def epicbox_json(healthy: bool = False, chain: str = "mainnet") -> Response:
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return _json({"error": "no data yet"}, status_code=503)
        rows = [s for s in snap.epicbox if not healthy or s.state is State.HEALTHY]
        return _json(
            {
                "meta": _list_meta(
                    describes="Epicbox relay hosts, the transport wallets use for addresses",
                    healthy=healthy,
                    count=len(rows),
                    total=len(snap.epicbox),
                    cadence_s=settings.cadence.epicbox_s,
                    settings=settings,
                ),
                "generated_at": _stamp(snap.generated_at),
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
    async def pools_json(healthy: bool = False, chain: str = "mainnet") -> Response:
        selected = _chain_or_404(chain)
        snap = service.snapshot_for(selected)
        if snap is None:
            return _json({"error": "no data yet"}, status_code=503)
        rows = [s for s in snap.pools if not healthy or s.state is State.HEALTHY]
        return _json(
            {
                "meta": _list_meta(
                    describes="Mining pools whose stats API answered",
                    healthy=healthy,
                    count=len(rows),
                    total=len(snap.pools),
                    cadence_s=settings.cadence.pool_s,
                    settings=settings,
                ),
                "generated_at": _stamp(snap.generated_at),
                "chain": snap.network.chain.value,
                "pools": [s.target.display_host for s in rows],
            }
        )

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
        return _json(
            {
                "service": "epic-status",
                "version": "0.1.0",
                "prober_id": settings.prober_id,
                "has_data": any(s is not None for s in snaps.values()),
                "stale": not ok,
                "generated_at": _stamp(max(newest)) if newest else None,
                "chains": {
                    c.value: {
                        "has_data": snap is not None,
                        "stale": snap.stale if snap is not None else True,
                        "generated_at": (
                            _stamp(snap.generated_at) if snap is not None else None
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
            return _json({"ok": False, "error": error}, status_code=400)
        # `message` is written for a human reading the form; a script needs the same facts
        # as values. `review_required` is unconditionally true and says so explicitly —
        # this field previously read `auto_promoted: true`, which stopped being true the
        # moment submissions started waiting for a decision, and a stale boolean in a
        # response is worse than no boolean at all. A caller polling for its host to
        # appear needs to know that nothing will happen until a person acts.
        return _json(
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
            submitter_address=_client_address(request),
            salt=service.submitter_salt,
            country=country or None,
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


def _security_headers(*, connect: Sequence[str] = ()) -> dict[str, str]:
    """Set here rather than in nginx so a self-hoster behind any proxy gets them.

    No `unsafe-inline` anywhere, for scripts or styles. Every page's JavaScript is a real
    file under /static, which is also why it is auditable, and every style is a class in
    app.css rather than a `style=` attribute.

    This function used to take `relaxed=True`, which added `style-src 'unsafe-inline'`
    for `/api` alone: the reference was a vendored web component that injected styles
    into its own shadow roots, and no narrower keyword allows that. The reference is now
    a first-party page, so the exception is gone and the policy is the same on every
    route. Deleting a special case in a CSP is worth more than the page that needed it.

    `connect` is the one remaining variation, and it is additive rather than relaxing: the
    board passes the origins of the hosts it lists so a reader can measure them from their
    own browser. Every other route is left at `'self'`.
    """
    connect_src = " ".join(("'self'", *connect))
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
            f"connect-src {connect_src}; "
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
        "generated_at": _stamp(snap.generated_at),
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
            "tip_mined_at": _stamp(net.tip_mined_at),
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
        "last_checked_at": _stamp(status.last_checked_at),
        "last_ok_at": _stamp(status.last_ok_at),
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
    }
    # Exhaustive on purpose rather than if-node-else: an `else` arm silently
    # serialised every future kind as a relay, with null protocol and cert fields
    # and none of its own.
    if target.kind is Kind.NODE:
        row["height"] = status.height
        row["tip_lag"] = status.tip_lag
        row["tip_hash"] = status.tip_hash
        row["node_version"] = status.node_version
    elif target.kind is Kind.EPICBOX:
        row["protocol_version"] = status.protocol_version
        row["cert_expires_in_days"] = status.cert_expires_in_days
    elif target.kind is Kind.POOL:
        row["miners"] = status.miners
        row["workers"] = status.workers
        row["fee_percent"] = status.fee_percent
        # The last block the pool FOUND, not its chain tip. Named so that no
        # consumer mistakes it for one and compares it to tip_height.
        row["last_block_height"] = status.last_block_height
        row["last_block_at"] = _stamp(status.last_block_at)
    return row
