"""Response helpers shared by the public routes in `api` and the dashboard in
`admin_routes`: security headers, CORS, JSON responses, timestamps, and the client address.

Kept in their own module so neither route module has to import the other.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from contextvars import ContextVar

from fastapi import Request
from fastapi.responses import JSONResponse, Response

onion_request: ContextVar[bool] = ContextVar("onion_request", default=False)
"""True while rendering a request that arrived through the onion service.

Set by the middleware in `api` from the `x-epic-onion` header, which only the onion
nginx block sends (`ops/nginx/status-onion.conf`) and the clearnet block blanks. It
decides one thing: the footer's "Also on Tor" row, which is advertising and is left out
on the onion itself. Decided server-side rather than by a script reading
`location.hostname`, because Tor Browser's stricter levels run no script at all and the
row would have reappeared exactly for the readers it is pointless for.

A clearnet client that sends the header itself gets a page without the row. Nothing is
protected by it, so nothing is lost.
"""


def client_address(request: Request) -> str:
    """The visitor's address, for rate limiting only.

    The proxy's own statement of who connected to it, never the visitor's. nginx sets
    `x-real-ip` to `$remote_addr`, replacing anything the client sent, so it is read
    first. Failing that, the **last** `x-forwarded-for` entry: `$proxy_add_x_forwarded_for`
    appends the real peer to whatever list the client supplied, so the first entry is
    the client's to choose — and reading it, as this function once did, let anyone
    reset the submit, login and quick-check limits by varying one header.

    Both are trusted only because this service binds loopback behind a proxy. Bound to
    a public interface — which the settings tell you not to do — they are spoofable.
    """
    real = request.headers.get("x-real-ip", "").strip()
    if real:
        return real
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        last = forwarded.split(",")[-1].strip()
        if last:
            return last
    return request.client.host if request.client else "unknown"


def security_headers(*, connect: Sequence[str] = ()) -> dict[str, str]:
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


def cors() -> dict[str, str]:
    """Read-only cross-origin access, on the JSON routes only.

    Open on purpose: the point of publishing this is that wallets, explorers and
    exchanges can read it from a browser without proxying it.
    """
    return {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET",
        "vary": "origin",
    }


def json_response(payload: dict[str, Any], status_code: int = 200) -> Response:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"cache-control": "no-store", **cors()},
    )


def stamp(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
