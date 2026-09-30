"""Routes for the review dashboard at `/admin`.

The one surface that is not public and not read-only. Approving a submission makes this
service start probing a stranger's host and publishes it to every consumer of the API, so
it sits behind a login, a CSRF token and a rate limit — see `admin` for the reasoning
behind each.

Registered only when a password hash is configured. Without one these routes do not
exist and /admin is an ordinary 404 — not a login form, which would advertise the
surface, and not a default credential, which on a self-hosted service is a published one.

Split out of `api.py`, which it made twice as long while sharing nothing with the public
routes but the response helpers in `web`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, Response

from . import admin
from .models import Chain, Kind, Source, Target
from .render import render_admin, render_admin_login
from .web import client_address, json_response, security_headers

if TYPE_CHECKING:
    from .api import Service

log = logging.getLogger("epic_status.admin")

_ADMIN_COOKIE = "epic_status_admin"


def register(app: FastAPI, service: Service) -> None:
    """Attach the dashboard to `app`, or do nothing when no password is configured."""
    settings = service.settings
    if not settings.admin_password_hash:
        return
    sessions = admin.Sessions()

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
            headers={"cache-control": "no-store", **security_headers()},
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
                **security_headers(),
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
        client = client_address(request)
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
            return None, json_response({"ok": False, "error": "signed out"}, status_code=401)
        if not sessions.valid_csrf(session, csrf):
            return None, json_response({"ok": False, "error": "stale token"}, status_code=403)
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
            return json_response({"ok": False, "error": "no such target"}, status_code=404)
        if not service.db.set_target_field(target_id, field, value):
            return json_response({"ok": False, "error": "field not editable"}, status_code=400)
        saved = service.db.target(target_id)
        assert saved is not None
        log.info("admin set %s.%s", saved.slug, field)
        # The stored value is returned rather than echoed from the request, so the page
        # shows what the database holds — a trimmed string or an uppercased country code
        # is not what was typed.
        return json_response(
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
            return json_response({"ok": False, "error": "gone"}, status_code=404)
        host = str(row["host"])
        if not service.db.delete_submission(submission_id):
            return json_response({"ok": False, "error": "nothing removed"}, status_code=409)
        log.info("admin deleted request %s", host)
        return json_response({"ok": True, "host": host})

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
            return json_response({"ok": False, "error": "no such target"}, status_code=404)
        if not service.db.delete_target_admin(target_id):
            return json_response({"ok": False, "error": "nothing removed"}, status_code=409)
        log.warning("admin removed target %s and its history", target.slug)
        return json_response(
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
    async def admin_reviewjson_response(
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
            return json_response({"ok": False, "error": "gone"}, status_code=404)
        if row["status"] in ("accepted", "rejected"):
            return json_response({"ok": False, "error": "already decided"}, status_code=409)
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
            return json_response({"ok": True, "host": host, "status": "accepted"})
        if decision == "reject":
            service.db.review_submission(
                submission_id, status="rejected", note="rejected"
            )
            log.info("admin rejected %s", host)
            return json_response({"ok": True, "host": host, "status": "rejected"})
        return json_response({"ok": False, "error": "unknown decision"}, status_code=400)

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
