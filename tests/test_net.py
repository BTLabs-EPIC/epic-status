"""The SSRF guard.

This is the highest-stakes module in the project and therefore the most important
file in the suite. The submit form lets a stranger name a host that this process
will then connect to, on a machine that also runs a live mainnet node on 3413 and
a wallet on 3420. A hole here is a port scanner with our source address.

Every address used below is a literal, so `getaddrinfo` answers from the resolver's
numeric fast path or /etc/hosts. Nothing here touches the network, which matters:
a suite that reaches the internet cannot distinguish a working guard from a
firewall.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from epic_status.models import Reason
from epic_status.net import (
    TargetRejected,
    _expiry_days_from_der,
    _is_public,
    classify_http_error,
    default_port,
    resolve_endpoint,
)

# --------------------------------------------------------------------------- deny

BLOCKED = [
    pytest.param("http://127.0.0.1/", id="ipv4-loopback"),
    pytest.param("http://localhost/", id="localhost-by-name"),
    pytest.param("http://[::1]/", id="ipv6-loopback-bracketed"),
    pytest.param("http://10.0.0.1/", id="rfc1918-10"),
    pytest.param("http://172.16.0.1/", id="rfc1918-172.16"),
    pytest.param("http://192.168.1.1/", id="rfc1918-192.168"),
    # The canonical cloud metadata address. Link-local, and the single most
    # valuable thing an SSRF can reach on a hosted box.
    pytest.param("http://169.254.169.254/", id="cloud-metadata"),
    # Carrier-grade NAT, and also where this machine's own tailnet lives — the
    # visual-channel service sits on one of these addresses with no auth at all.
    pytest.param("http://100.100.100.100/", id="cgnat-tailnet"),
    pytest.param("http://0.0.0.0/", id="unspecified"),
    # An IPv4 loopback smuggled through an IPv6 literal. Checking only the address
    # family and not the mapped value is the classic miss here.
    pytest.param("http://[::ffff:127.0.0.1]/", id="ipv4-mapped-loopback"),
    pytest.param("http://[fd00::1]/", id="ipv6-unique-local"),
]


@pytest.mark.parametrize("endpoint", BLOCKED)
async def test_resolve_endpoint_rejects_non_public(endpoint: str) -> None:
    with pytest.raises(TargetRejected):
        await resolve_endpoint(endpoint)


@pytest.mark.parametrize("endpoint", ["file:///etc/passwd", "gopher://host:70/"])
async def test_resolve_endpoint_rejects_unsupported_scheme(endpoint: str) -> None:
    """Rejected before any resolution, so a scheme that could read local files
    never reaches getaddrinfo."""
    with pytest.raises(TargetRejected) as exc:
        await resolve_endpoint(endpoint)
    assert "unsupported scheme" in exc.value.message


@pytest.mark.parametrize(
    "endpoint",
    [
        # Port 0 is falsy. `parts.port or default_port(scheme)` silently rewrote
        # this to 443 instead of rejecting it.
        pytest.param("http://1.1.1.1:0/", id="port-zero"),
        # urlsplit().port raises ValueError here, which must surface as a
        # TargetRejected the submit form can render, not as a 500.
        pytest.param("http://1.1.1.1:99999/", id="port-too-large"),
    ],
)
async def test_resolve_endpoint_rejects_bad_port(endpoint: str) -> None:
    with pytest.raises(TargetRejected):
        await resolve_endpoint(endpoint)


async def test_allow_private_is_the_dev_escape_hatch() -> None:
    """The one way to probe a loopback listener. False everywhere but development
    and this suite."""
    resolved = await resolve_endpoint("http://127.0.0.1:13431/", allow_private=True)
    assert resolved.addresses == ("127.0.0.1",)
    assert resolved.port == 13431
    assert resolved.is_tls is False


async def test_resolve_endpoint_accepts_public_address() -> None:
    resolved = await resolve_endpoint("https://1.1.1.1:3413")
    assert resolved.hostname == "1.1.1.1"
    assert resolved.port == 3413
    assert resolved.is_tls is True


async def test_rejection_names_the_offending_address() -> None:
    """An operator who mis-pointed a DNS record has to be able to fix it from the
    message alone, without asking us."""
    with pytest.raises(TargetRejected) as exc:
        await resolve_endpoint("http://10.11.12.13/")
    assert "10.11.12.13" in exc.value.message
    assert exc.value.reason is Reason.BAD_RESPONSE


# --------------------------------------------------------------------- _is_public

PUBLIC_TABLE = [
    ("1.1.1.1", True),
    ("8.8.8.8", True),
    ("144.202.75.237", True),  # node.epiccash.com, Vultr
    ("95.217.197.180", True),  # a documented mainnet seed, Hetzner
    ("2606:4700::1111", True),
    ("172.32.0.1", True),  # one address past the end of RFC1918's 172.16/12
    ("100.63.255.255", True),  # one address below the CGNAT block
    ("127.0.0.1", False),
    ("127.99.99.99", False),  # the whole /8, not just .0.1
    ("10.0.0.1", False),
    ("172.16.0.1", False),
    ("172.31.255.255", False),
    ("192.168.1.1", False),
    ("169.254.169.254", False),
    ("100.64.0.0", False),
    ("100.127.255.254", False),
    ("192.0.0.1", False),  # IETF protocol assignments
    ("224.0.0.1", False),  # multicast
    ("240.0.0.1", False),  # reserved
    ("0.0.0.0", False),
    ("::1", False),
    ("::", False),
    ("::ffff:127.0.0.1", False),
    ("::ffff:10.0.0.1", False),
    ("fd00::1", False),
    ("fe80::1", False),
    ("ff02::1", False),
]


@pytest.mark.parametrize(("address", "expected"), PUBLIC_TABLE)
def test_is_public(address: str, expected: bool) -> None:
    assert _is_public(ipaddress.ip_address(address)) is expected


# ----------------------------------------------------------------- default_port


@pytest.mark.parametrize(
    ("scheme", "port"),
    [("http", 80), ("https", 443), ("ws", 80), ("wss", 443)],
)
def test_default_port(scheme: str, port: int) -> None:
    assert default_port(scheme) == port


# ------------------------------------------------------------ certificate expiry


def _utctime(dt: datetime) -> bytes:
    body = dt.strftime("%y%m%d%H%M%SZ").encode("ascii")
    return bytes([0x17, len(body)]) + body


def _generalizedtime(dt: datetime) -> bytes:
    body = dt.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    return bytes([0x18, len(body)]) + body


def test_expiry_days_reads_the_second_time_field() -> None:
    """The Validity SEQUENCE is notBefore then notAfter, so the answer is the
    SECOND time in the blob. Returning the first would report every certificate as
    long expired.
    """
    now = datetime.now(UTC)
    der = (
        b"\x30\x1e"  # a SEQUENCE header, so the blob looks like real DER
        + _utctime(now - timedelta(days=400))
        + _utctime(now + timedelta(days=30, hours=12))
    )
    assert _expiry_days_from_der(der, 0.0) == 30


def test_expiry_days_handles_generalizedtime() -> None:
    """Certificates valid past 2049 use GeneralizedTime (tag 0x18) rather than
    UTCTime, and Let's Encrypt is not the only issuer in the wild."""
    now = datetime.now(UTC)
    der = (
        _generalizedtime(now - timedelta(days=10))
        + _generalizedtime(now + timedelta(days=7, hours=12))
    )
    assert _expiry_days_from_der(der, 0.0) == 7


def test_expiry_days_reports_an_already_expired_certificate() -> None:
    """Negative, not None. An expired certificate is the case the operator most
    needs to see, and it is why this is read from a raw handshake rather than from
    a verified httpx response.

    `timedelta.days` floors, so 5.5 days past notAfter is -6 rather than -5. Only
    the sign is load-bearing for display, but pin the exact value so a change in
    the arithmetic is visible.
    """
    now = datetime.now(UTC)
    der = _utctime(now - timedelta(days=500)) + _utctime(
        now - timedelta(days=5, hours=12)
    )
    assert _expiry_days_from_der(der, 0.0) == -6


@pytest.mark.parametrize(
    "der",
    [
        pytest.param(b"garbage, not a certificate at all", id="garbage"),
        pytest.param(b"", id="empty"),
        pytest.param(
            b"\x30\x0f" + _utctime(datetime(2030, 1, 1, tzinfo=UTC)), id="one-time-only"
        ),
    ],
)
def test_expiry_days_returns_none_when_it_cannot_tell(der: bytes) -> None:
    """None, never a guess. A wrong expiry date on a status page is worse than no
    expiry date."""
    assert _expiry_days_from_der(der, 0.0) is None


# ------------------------------------------------------- classify_http_error


@pytest.mark.parametrize(
    ("exc", "reason", "message"),
    [
        (httpx.ConnectTimeout("timed out"), Reason.TIMEOUT, "connection timed out"),
        (httpx.ReadTimeout("timed out"), Reason.TIMEOUT, "connection timed out"),
        (httpx.ConnectError("refused"), Reason.REFUSED, "connection refused"),
        (httpx.ConnectError("no route to host"), Reason.REFUSED, "could not connect"),
        (
            httpx.ConnectError("certificate verify failed"),
            Reason.TLS,
            "TLS handshake failed",
        ),
        (
            ssl.SSLCertVerificationError("hostname mismatch"),
            Reason.TLS,
            "TLS certificate not valid",
        ),
        (socket.gaierror(-2, "Name or service not known"), Reason.DNS, "does not resolve"),
        (httpx.TooManyRedirects("too many"), Reason.BAD_RESPONSE, "endpoint redirects"),
    ],
)
def test_classify_http_error(
    exc: BaseException, reason: Reason, message: str
) -> None:
    """The message is published per endpoint, so an operator sees why their host is
    red without contacting anyone. It has to read as English, not as a class name.
    """
    assert classify_http_error(exc) == (reason, message)
