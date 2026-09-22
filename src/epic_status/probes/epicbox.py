"""Epicbox relay probe.

The relay sends its challenge **unprompted, immediately on connect**, before the
client has written a single byte. So the complete health check is: open the
WebSocket, read exactly one frame, assert `type == "Challenge"`, close.

Verified against mainnet: `wss://epicbox.epiccash.com/` returns 101 and then
pushes `{"type":"Challenge","str":"7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc"}`.

That one frame proves strictly more than a TCP or TLS check: TLS terminates, the
reverse proxy's upgrade path works, the relay process is alive, and its event loop
is responsive — because the challenge is emitted synchronously inside the
connection handler. A TCP check cannot distinguish any of that from nginx serving
a holding page with the relay dead.

Three things this deliberately does not do:

* **No HTTP GET.** Rendering a relay's own status page fires three outbound TLS
  connections to other relays so it can draw their status dots. Polling it would
  make this service an amplifier aimed at the hosts it exists to help.
* **No Subscribe.** It would work — the signing scheme is reproducible without a
  wallet — but it registers a throwaway key in a stranger's datastore on every
  poll, and it costs the relay a fork-exec of its crypto helper.
* **No PostSlate, ever.** That writes a row into someone else's database.

Cadence is 30 seconds, not 5. A wallet opens one connection and holds it for its
whole life, speaking once a minute. Connect-and-drop every five seconds is a churn
pattern no legitimate client produces, and relays fronted by nginx commonly cap
concurrent connections in single digits and answer 429 past that.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from typing import Any

import websockets
from websockets.asyncio.client import connect as ws_connect

from ..models import EpicboxProbe, Reason
from ..net import Resolved

_CHALLENGE = "Challenge"

# The first challenge is a fixed string, kept for backward compatibility with
# protocol 2.0.0 clients; the relay only switches to a per-connection random value
# once a client declares a newer version. Seeing the same value every time is
# expected and is not evidence of a stuck or replayed response.
STATIC_CHALLENGE = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc"

# Epicbox address parsing permits only [a-zA-Z0-9.] in the domain — no hyphen, no
# underscore. A hyphenated relay hostname completes the WebSocket handshake
# perfectly and would show green here, while every address on it is unparseable
# and no transaction can ever complete. Validating this at submission is the
# difference between a useful page and one that publishes a permanently broken
# endpoint as healthy.
EPICBOX_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.]+$")


def domain_is_addressable(hostname: str) -> bool:
    return bool(EPICBOX_DOMAIN_RE.match(hostname))


async def probe_relay(
    resolved: Resolved,
    *,
    timeout: float,
    want_version: bool = True,
) -> EpicboxProbe:
    """One handshake. Connects to the validated address, not the name.

    `server_hostname` carries the real hostname for SNI and the `Host` header,
    which is what makes both certificate verification and virtual hosting work
    against an IP-addressed connection.
    """
    loop = asyncio.get_running_loop()
    start = loop.time()

    ctx = ssl.create_default_context() if resolved.is_tls else None

    try:
        async with asyncio.timeout(timeout):
            async with ws_connect(
                resolved_uri(resolved),
                open_timeout=timeout,
                # One frame is read and the socket is closed, so keepalive pings
                # would only add traffic to someone else's server.
                ping_interval=None,
                close_timeout=2,
                max_size=64 * 1024,
                ssl=ctx,
                host=resolved.primary,
                port=resolved.port,
                server_hostname=resolved.hostname if resolved.is_tls else None,
            ) as ws:
                raw = await ws.recv()
                latency_ms = int((loop.time() - start) * 1000)
                frame = _parse(raw)
                if frame is None:
                    return EpicboxProbe(
                        ok=False,
                        latency_ms=latency_ms,
                        reason=Reason.BAD_RESPONSE,
                        error="first frame was not JSON",
                    )
                if frame.get("type") != _CHALLENGE:
                    return EpicboxProbe(
                        ok=False,
                        latency_ms=latency_ms,
                        reason=Reason.BAD_RESPONSE,
                        error=f"expected Challenge, got {str(frame.get('type'))[:40]!r}",
                    )

                version = await _try_version(ws, timeout) if want_version else None

                return EpicboxProbe(
                    ok=True,
                    latency_ms=latency_ms,
                    challenge_seen=True,
                    protocol_version=version,
                )

    except asyncio.TimeoutError:
        return EpicboxProbe(
            ok=False, reason=Reason.TIMEOUT, error="timed out during handshake"
        )
    except ssl.SSLCertVerificationError:
        return EpicboxProbe(
            ok=False, reason=Reason.TLS, error="TLS certificate not valid"
        )
    except ssl.SSLError:
        return EpicboxProbe(ok=False, reason=Reason.TLS, error="TLS error")
    except websockets.InvalidStatus as exc:
        status = getattr(exc.response, "status_code", None)
        if status == 429:
            return EpicboxProbe(
                ok=False, reason=Reason.RATE_LIMITED, error="rate limited (HTTP 429)"
            )
        # Our own deployment answers 400 on alias hostnames on purpose, so this
        # is a real and expected case: TLS and the proxy are fine, but this name
        # is not the one that serves the relay.
        return EpicboxProbe(
            ok=False,
            reason=Reason.BAD_RESPONSE,
            error=f"upgrade refused (HTTP {status})",
        )
    except websockets.WebSocketException as exc:
        return EpicboxProbe(
            ok=False, reason=Reason.BAD_RESPONSE, error=type(exc).__name__
        )
    except OSError as exc:
        return EpicboxProbe(
            ok=False, reason=Reason.REFUSED, error=exc.strerror or "could not connect"
        )


def resolved_uri(resolved: Resolved) -> str:
    """The relay has no path component — the server binds the root and the wallet
    builds its URL with none either."""
    return f"{resolved.scheme}://{resolved.hostname}:{resolved.port}/"


async def _try_version(ws: Any, timeout: float) -> str | None:
    """`{"type":"getversion"}` on an already-open socket.

    Free, safe, and needs no crypto — it does not touch the fork-exec path that
    Subscribe and PostSlate do. Failure is not a health signal: older relays do
    not implement it, so a timeout here leaves the probe green with no version.
    """
    try:
        await ws.send(json.dumps({"type": "getversion"}))
        async with asyncio.timeout(min(timeout, 3.0)):
            reply = _parse(await ws.recv())
        if reply is None:
            return None
        value = reply.get("str") or reply.get("version")
        return str(value) if value else None
    except (asyncio.TimeoutError, websockets.WebSocketException, OSError):
        return None


def _parse(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, bytes | bytearray):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None
