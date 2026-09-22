"""Epicbox relay probe.

The one integration test here runs a real WebSocket server on 127.0.0.1 rather
than mocking the websockets library. Mocking library internals would assert that
the mock behaves as written, not that a relay handshake works; the relay's whole
contract is that it pushes a frame before the client writes anything, and only a
real socket demonstrates that.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from websockets.asyncio.server import serve

from epic_status.config import Settings
from epic_status.models import Reason
from epic_status.net import Resolved, resolve_endpoint
from epic_status.probes.epicbox import (
    STATIC_CHALLENGE,
    _parse,
    domain_is_addressable,
    probe_relay,
    resolved_uri,
)

# ------------------------------------------------------------- domain addressability
#
# Epicbox address parsing permits only [a-zA-Z0-9.] in the domain: no hyphen, no
# underscore. This check is load-bearing rather than cosmetic. A hyphenated relay
# hostname completes the WebSocket handshake perfectly and would show GREEN here,
# while every epicbox address on it is unparseable by every wallet and no
# transaction can ever complete. Publishing such a host as healthy is worse than
# not listing it, so the constraint is enforced at submission.

ADDRESSABLE = [
    ("epicbox.epiccash.com", True),
    ("epicbox.epicnet.us", True),
    ("epicbox.stackwallet.com", True),
    ("epicbox.51pool.online", True),  # digits are fine, and this relay is real
    ("floo-epicbox.btlabs.uk", False),  # handshakes fine, addresses unusable
    ("epic_box.example.com", False),
    ("epicbox-1.example.com", False),
    ("", False),
    ("epicbox.example.com:443", False),  # a port is not part of the domain
    ("epicbox.example.com/", False),
]


@pytest.mark.parametrize(("hostname", "expected"), ADDRESSABLE)
def test_domain_is_addressable(hostname: str, expected: bool) -> None:
    assert domain_is_addressable(hostname) is expected


# -------------------------------------------------------------------------- _parse


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('{"type":"Challenge","str":"abc"}', {"type": "Challenge", "str": "abc"}),
        (b'{"type":"Challenge","str":"abc"}', {"type": "Challenge", "str": "abc"}),
        (bytearray(b'{"ok":1}'), {"ok": 1}),
        ("[1,2,3]", None),  # valid JSON, not an object
        ('"just a string"', None),
        ("42", None),
        ("not json at all", None),
        ("", None),
        (b"\xff\xfe invalid utf8", None),
        (None, None),
        (12345, None),
    ],
)
def test_parse(raw: Any, expected: dict[str, Any] | None) -> None:
    """A relay behind a misconfigured proxy returns HTML or a binary blob. None,
    never an exception: one bad frame must not take the sweep down."""
    assert _parse(raw) == expected


# --------------------------------------------------------------------- resolved_uri


@pytest.mark.parametrize(
    ("scheme", "port", "expected"),
    [
        ("wss", 443, "wss://epicbox.epiccash.com:443/"),
        ("ws", 13420, "ws://epicbox.epiccash.com:13420/"),
    ],
)
def test_resolved_uri_has_no_path_beyond_root(
    scheme: str, port: int, expected: str
) -> None:
    """The relay binds the root and the wallet builds its URL with no path either.
    Anything appended here is a path the server does not serve."""
    resolved = Resolved(
        hostname="epicbox.epiccash.com",
        port=port,
        addresses=("144.202.75.237",),
        scheme=scheme,
    )
    uri = resolved_uri(resolved)
    assert uri == expected
    assert uri.endswith(":%d/" % port)
    assert uri.count("/") == 3


# ------------------------------------------------------------------- integration


@pytest.fixture
async def relay() -> AsyncIterator[int]:
    """A stand-in relay: pushes the Challenge frame unprompted on connect, then
    answers one `getversion`. Port 0 so concurrent runs cannot collide."""

    async def handler(ws: Any) -> None:
        await ws.send(json.dumps({"type": "Challenge", "str": STATIC_CHALLENGE}))
        try:
            raw = await ws.recv()
        except Exception:  # noqa: BLE001 - the probe closing first is normal
            return
        frame = _parse(raw)
        if frame is not None and frame.get("type") == "getversion":
            await ws.send(json.dumps({"type": "Version", "str": "2.0.0"}))

    async with serve(handler, "127.0.0.1", 0) as server:
        yield server.sockets[0].getsockname()[1]


async def test_probe_relay_reads_the_unprompted_challenge(
    relay: int, settings: Settings
) -> None:
    """The complete health check: connect, read one frame, assert Challenge. That
    frame proves TLS, the proxy's upgrade path, the relay process and a responsive
    event loop — strictly more than a TCP or TLS check can.

    Reached through `resolve_endpoint`, not a hand-built `Resolved`, so the guard is
    exercised on the one path that is allowed to reach loopback.
    """
    resolved = await resolve_endpoint(
        f"ws://127.0.0.1:{relay}/", allow_private=settings.allow_private_targets
    )

    probe = await probe_relay(resolved, timeout=5.0)

    assert probe.ok is True
    assert probe.challenge_seen is True
    assert probe.reason is Reason.OK
    assert probe.latency_ms is not None
    assert probe.protocol_version == "2.0.0"


async def test_probe_relay_sends_nothing_before_reading(
    relay: int, settings: Settings
) -> None:
    """With `want_version=False` the probe must complete without writing a single
    byte. That is what makes the 30-second cadence defensible on somebody else's
    server."""
    resolved = await resolve_endpoint(
        f"ws://127.0.0.1:{relay}/", allow_private=settings.allow_private_targets
    )

    probe = await probe_relay(resolved, timeout=5.0, want_version=False)

    assert probe.ok is True
    assert probe.challenge_seen is True
    assert probe.protocol_version is None


async def test_probe_relay_rejects_a_non_challenge_first_frame() -> None:
    """A socket that opens and says something else is not a working relay, however
    healthy the TCP and TLS layers look."""

    async def handler(ws: Any) -> None:
        await ws.send(json.dumps({"type": "Hello"}))
        await asyncio.sleep(0.2)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        resolved = await resolve_endpoint(
            f"ws://127.0.0.1:{port}/", allow_private=True
        )
        probe = await probe_relay(resolved, timeout=5.0)

    assert probe.ok is False
    assert probe.reason is Reason.BAD_RESPONSE
    assert probe.error is not None
    assert "Challenge" in probe.error


async def test_probe_relay_rejects_a_non_json_first_frame() -> None:
    async def handler(ws: Any) -> None:
        await ws.send("<html>holding page</html>")
        await asyncio.sleep(0.2)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        resolved = await resolve_endpoint(
            f"ws://127.0.0.1:{port}/", allow_private=True
        )
        probe = await probe_relay(resolved, timeout=5.0)

    assert probe.ok is False
    assert probe.reason is Reason.BAD_RESPONSE
    assert probe.error == "first frame was not JSON"


async def test_probe_relay_times_out_on_a_silent_server(relay: int) -> None:
    """A relay fronted by nginx with the relay process dead accepts the upgrade and
    then says nothing. TIMEOUT, not ok."""

    async def handler(ws: Any) -> None:
        await asyncio.sleep(1.0)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        resolved = await resolve_endpoint(
            f"ws://127.0.0.1:{port}/", allow_private=True
        )
        probe = await probe_relay(resolved, timeout=0.3)

    assert probe.ok is False
    assert probe.reason is Reason.TIMEOUT


async def test_probe_relay_reports_a_closed_port_as_refused() -> None:
    """Nothing listening at all. REFUSED, and it must not raise."""
    # Bind and immediately release, so the port is almost certainly free.
    server = await asyncio.get_running_loop().create_server(
        asyncio.Protocol, "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    resolved = await resolve_endpoint(f"ws://127.0.0.1:{port}/", allow_private=True)
    probe = await probe_relay(resolved, timeout=2.0)

    assert probe.ok is False
    assert probe.reason is Reason.REFUSED
