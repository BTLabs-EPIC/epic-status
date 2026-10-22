"""Network primitives, and the guard that makes it safe to probe a host a stranger
typed into a form.

This is the highest-risk module in the project. Everything else reads data; this
makes the server open connections to addresses chosen by the public. Without the
checks below, the submit form is a port scanner with our source address — and the
machine this was written on runs a live mainnet node on 3413 and Postgres on 5432.

Three separate protections, because any one of them alone has a hole:

1. Resolve the name ourselves and reject the target if *any* returned address is
   non-public. Rejecting only the first address is defeated by a name that
   resolves to a public address and a private one.
2. Connect to the address we validated, not to the name, passing the hostname
   only as the Host header and the TLS SNI value. Re-resolving at connect time
   reopens a DNS-rebinding window between the check and the request.
3. Never follow redirects. A 302 to http://169.254.169.254/ is the oldest trick
   in this category, and a liveness probe has no legitimate use for one.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from .models import Reason


class TargetRejected(Exception):
    """The endpoint must not be contacted. Carries a reason fit to show a
    submitter, because "invalid" with no explanation generates support requests."""

    def __init__(self, reason: Reason, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class Resolved:
    hostname: str
    port: int
    addresses: tuple[str, ...]
    scheme: str

    @property
    def primary(self) -> str:
        return self.addresses[0]

    @property
    def is_tls(self) -> bool:
        return self.scheme in {"https", "wss"}


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Deliberately broader than `ip.is_private`.

    `is_global` already covers loopback, link-local, multicast and the RFC1918 and
    RFC4193 ranges, but not every reserved block, and the carve-outs below are the
    ones that have actually been used to reach cloud metadata and local services.
    """
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        # 169.254.169.254 is link-local and already excluded; 100.64.0.0/10 is
        # carrier-grade NAT and is also where this machine's own tailnet lives.
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            return False
        if ip in ipaddress.ip_network("192.0.0.0/24"):
            return False
        # The deprecated 6to4 relay anycast block (RFC 7526). Nothing legitimate is
        # addressed there any more, and what answers is whichever relay is nearest.
        if ip in _SIXTOFOUR_RELAY:
            return False
    else:
        if ip.ipv4_mapped is not None:
            return _is_public(ip.ipv4_mapped)
        if ip.is_site_local:
            return False
        # Translation prefixes carry an IPv4 address inside an IPv6 one, and a
        # gateway on the path unwraps it: 64:ff9b::7f00:1 is 127.0.0.1 to a NAT64
        # box, 2002:7f00:1:: is 127.0.0.1 to a 6to4 relay. Checked explicitly
        # rather than left to `is_global`, whose treatment of these prefixes has
        # changed between Python releases — the embedded address is the one that
        # gets reached, so it is the one that has to be public.
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not _is_public(embedded):
            return False
    return ip.is_global


_SIXTOFOUR_RELAY = ipaddress.ip_network("192.88.99.0/24")
_NAT64_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),  # RFC 6052 well-known prefix
    ipaddress.ip_network("64:ff9b:1::/48"),  # RFC 8215 local-use prefix
)


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address a translator would deliver this IPv6 address to, if any."""
    if ip.sixtofour is not None:
        return ip.sixtofour
    for prefix in _NAT64_PREFIXES:
        if ip in prefix:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.teredo is not None:
        # (server, client): the client is the host traffic ends up at.
        return ip.teredo[1]
    return None


def default_port(scheme: str) -> int:
    return {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scheme, 443)


Resolver = Callable[[str, int], Awaitable[list[Any]]]
"""`getaddrinfo(host, port)` returning the same tuples as `socket.getaddrinfo`."""


async def resolve_endpoint(
    endpoint: str, *, allow_private: bool = False, getaddrinfo: Resolver | None = None
) -> Resolved:
    """Resolve and vet an endpoint URL.

    `allow_private` exists only so the test suite and local development can point
    at 127.0.0.1. Enabling it on a public instance is the single worst thing you
    can do to this service, which is why the setting says so.

    `getaddrinfo` replaces the event loop's resolver. The quick check passes its own,
    backed by a private thread pool: the loop's default pool is shared with the poller
    and with every httpx connect, and a lookup that never answers keeps its thread long
    after the caller's timeout — so a visitor typing names under a dead nameserver could
    otherwise starve the board's own probes.
    """
    parts = urlsplit(endpoint)
    scheme = (parts.scheme or "https").lower()
    if scheme not in {"http", "https", "ws", "wss"}:
        raise TargetRejected(Reason.BAD_RESPONSE, f"unsupported scheme {scheme!r}")

    hostname = parts.hostname
    if not hostname:
        raise TargetRejected(Reason.DNS, "no hostname in endpoint")

    # urlsplit().port raises ValueError for anything outside 0-65535 or
    # non-numeric, so it has to be read inside a try: an out-of-range port in a
    # submitted URL would otherwise escape this function as a bare ValueError
    # rather than a TargetRejected the submit form can render.
    try:
        raw_port = parts.port
    except ValueError as exc:
        raise TargetRejected(Reason.BAD_RESPONSE, f"invalid port ({exc})") from exc
    # `is None`, not truthiness: port 0 is falsy, and `parts.port or default_port`
    # silently rewrote ":0" to 443 instead of rejecting it.
    port = default_port(scheme) if raw_port is None else raw_port
    if not 1 <= port <= 65535:
        raise TargetRejected(Reason.BAD_RESPONSE, f"port {port} out of range")

    loop = asyncio.get_running_loop()
    try:
        if getaddrinfo is not None:
            infos = await getaddrinfo(hostname, port)
        else:
            infos = await loop.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
    except socket.gaierror as exc:
        raise TargetRejected(Reason.DNS, f"does not resolve ({exc.strerror})") from exc

    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise TargetRejected(Reason.DNS, "resolved to no addresses")

    if not allow_private:
        for addr in addresses:
            ip = ipaddress.ip_address(addr)
            if not _is_public(ip):
                # Names the offending address on purpose: an operator who
                # mis-pointed a DNS record can fix it from this message alone.
                raise TargetRejected(
                    Reason.BAD_RESPONSE,
                    f"{hostname} resolves to the non-public address {addr}",
                )

    return Resolved(
        hostname=hostname, port=port, addresses=tuple(addresses), scheme=scheme
    )


def pinned_url(resolved: Resolved, path: str) -> str:
    """The request URL, addressed to the validated IP rather than the name."""
    host = resolved.primary
    if ":" in host:
        host = f"[{host}]"
    return f"{resolved.scheme}://{host}:{resolved.port}{path}"


def build_client(*, timeout: float, verify: bool = True) -> httpx.AsyncClient:
    """One client, reused. A fresh client per probe would mean a fresh TLS
    handshake per probe, which is the expensive part and the rude part.

    `follow_redirects` is off and must stay off: see the module docstring.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=verify,
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        headers={"user-agent": "epic-status/0.1 (+https://github.com/BTLabs-EPIC/epic-status)"},
    )


def classify_http_error(exc: BaseException) -> tuple[Reason, str]:
    """Turn a transport exception into something an operator can act on.

    The error string ends up in the JSON API and on the page. cosmos.directory is
    the only comparable service that publishes per-endpoint error text, and it is
    the single most useful thing it does: an operator sees why their endpoint is
    red without having to ask anyone.
    """
    if isinstance(exc, httpx.ConnectTimeout | httpx.ReadTimeout | asyncio.TimeoutError):
        return Reason.TIMEOUT, "connection timed out"
    if isinstance(exc, httpx.ConnectError):
        text = str(exc)
        if "certificate" in text.lower() or "ssl" in text.lower():
            return Reason.TLS, "TLS handshake failed"
        if "refused" in text.lower():
            return Reason.REFUSED, "connection refused"
        return Reason.REFUSED, "could not connect"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return Reason.TLS, "TLS certificate not valid"
    if isinstance(exc, ssl.SSLError):
        return Reason.TLS, "TLS error"
    if isinstance(exc, httpx.TooManyRedirects):
        return Reason.BAD_RESPONSE, "endpoint redirects"
    if isinstance(exc, socket.gaierror):
        return Reason.DNS, "does not resolve"
    if isinstance(exc, httpx.HTTPError):
        return Reason.BAD_RESPONSE, type(exc).__name__
    return Reason.BAD_RESPONSE, type(exc).__name__


async def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, int | None]:
    """A bare TCP connect, used as the fallback for a node whose HTTP API is
    closed. It proves only that something is listening — which is exactly why it
    produces amber rather than green."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass
        return True, int((loop.time() - start) * 1000)
    except (OSError, asyncio.TimeoutError):
        return False, None


async def peer_certificate_expiry(resolved: Resolved, timeout: float) -> int | None:
    """Days until the certificate expires, or None if it cannot be determined.

    Done with a bare TLS handshake against the pinned address rather than by
    reading it out of an httpx response, because the most useful case is a host
    whose certificate is *already* invalid — where the HTTP request fails but the
    expiry date is still exactly what the operator needs to see.
    """
    if not resolved.is_tls:
        return None

    ctx = ssl.create_default_context()
    # The point of this handshake is to read the certificate, including when it is
    # expired or issued for the wrong name. Verifying would throw away the answer.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(
                resolved.primary,
                resolved.port,
                ssl=ctx,
                server_hostname=resolved.hostname,
            )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None

    try:
        sock = writer.get_extra_info("ssl_object")
        if sock is None:
            return None
        der = sock.getpeercert(binary_form=True)
        if not der:
            return None
        return _expiry_days_from_der(der, loop.time())
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


def _expiry_days_from_der(der: bytes, _now_monotonic: float) -> int | None:
    """Extract notAfter without adding a dependency.

    `ssl.CERT_NONE` means `getpeercert()` returns an empty dict, so the parsed
    form is unavailable and only the DER is. `ssl.DER_cert_to_PEM_cert` plus
    `ssl._ssl._test_decode_cert` would need a temp file; decoding the two ASN.1
    UTCTime/GeneralizedTime fields directly is less code and no I/O.
    """
    from datetime import UTC, datetime

    # Walk the DER for the Validity SEQUENCE: it is the only SEQUENCE containing
    # exactly two time values (tag 0x17 UTCTime or 0x18 GeneralizedTime).
    times: list[datetime] = []
    i = 0
    while i < len(der) - 2 and len(times) < 2:
        tag = der[i]
        if tag in (0x17, 0x18):
            length = der[i + 1]
            raw = der[i + 2 : i + 2 + length]
            try:
                text = raw.decode("ascii")
            except UnicodeDecodeError:
                i += 1
                continue
            try:
                if tag == 0x17:
                    dt = datetime.strptime(text, "%y%m%d%H%M%SZ")
                else:
                    dt = datetime.strptime(text, "%Y%m%d%H%M%SZ")
            except ValueError:
                i += 1
                continue
            times.append(dt.replace(tzinfo=UTC))
            i += 2 + length
            continue
        i += 1

    if len(times) < 2:
        return None
    not_after = times[1]
    return (not_after - datetime.now(UTC)).days
