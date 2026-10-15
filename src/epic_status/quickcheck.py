"""Quick node check: a visitor types a node address, this server probes it once.

This is the only place in the project where a page visit makes the server connect
somewhere synchronously, to a host a stranger chose. Everything else either reads the
snapshot or probes a committed list. The guards are therefore stacked, and each one
covers a hole in the others:

1. **A fixed request.** Only `POST /v2/foreign` on the API port and a TCP connect on
   the peer port are ever made. No path, method or body comes from the input, so the
   check cannot be steered into talking to anything but an Epic node's public API.
2. **A fixed port set.** 3413 and 3414 by default; a typed port must be above 1024,
   so 22, 25, 80, 443 and the rest of the privileged range are never reached.
3. **`net.resolve_endpoint`.** Resolved once; refused if *any* address is non-public
   (`net._is_public`). The connection goes to the validated IP, the name travels only
   as Host and SNI, and the socket's connected peer is compared to that IP afterwards.
4. **Not ourselves.** This machine's own public addresses are refused on every port
   but 3413/3414. Without that, `<our IP>:5432` reaches a service the firewall exists
   to hide, from the one source address the firewall trusts.
5. **Bounded everything.** 3 s per step, 9 s overall, a 64 KiB body cap, no redirects,
   no compression, and rate limits per visitor, per target and in total.

Peer counts are not here and cannot be: they are owner-API data behind `api_secret`.

The P2P handshake is implemented but off by default (`quickcheck_p2p_handshake`).
From the node source (`p2p/src/types.rs` `PeerAddr::as_key`, `peers.rs`
`add_connected`/`clean_peers`, `serv.rs` `listen`): Epic keys peer records and bans
by IP alone, ignoring the port. On a host that also runs an Epic node — as the
reference instance does — a successful handshake overwrites the remote's record of
*our* node with this probe's capabilities and marks it `Defunct` when we hang up, and
any failed handshake bans the address for `BAN_WINDOW` (three hours). A visitor could
trigger either at will. So by default the peer port gets a TCP connect only.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import fcntl
import functools
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel

from .config import Settings
from .models import Chain, Reason, Target
from .net import (
    Resolved,
    TargetRejected,
    _embedded_ipv4,
    _is_public,
    classify_http_error,
    resolve_endpoint,
)
from .probes.node import BodyTooLarge, CappedResponse, EncodedBody, _rpc, _unwrap, post_capped

# --------------------------------------------------------------------- constants

API_PORT = 3413
P2P_PORT = 3414
DEFAULT_PORTS = frozenset({API_PORT, P2P_PORT})

QUICKCHECK_TIMEOUT_S = 3.0
"""Per step: one connect, one request, one read."""
QUICKCHECK_DEADLINE_S = 9.0
"""The whole check, whatever the fallbacks."""
MAX_BODY_BYTES = 64 * 1024
"""A `get_tip` answer is 468 bytes and a header about 1.5 KB. 64 KiB is generous."""
MAX_INPUT_CHARS = 253

# Rate limits. In memory, per process: losing them on restart costs nothing, and a
# database write per keystroke-triggered check would cost a lot.
CLIENT_PER_MINUTE = 5
CLIENT_PER_HOUR = 30
TARGET_PER_MINUTE = 10
"""Across all visitors, so this server cannot be used to hammer one node."""
MAX_CONCURRENT = 4
DNS_THREADS = 2
"""Lookups the quick check may have in flight, each on a thread of its own private pool.

Counted until the thread returns, not until the caller gives up: a name under a dead
nameserver holds its thread for the resolver's full retry cycle, ten seconds or more,
whatever timeout the check applied. When both are held the check answers busy."""
BUSY_RETRY_S = 5
MAX_TRACKED_KEYS = 10_000
"""Bound on limiter memory. A flood of distinct addresses evicts the oldest keys."""

LOCAL_ADDRESS_TTL_S = 300.0

# Genesis block hashes, as `get_header` at height 0 reports them. Source: the
# assertions in EpicCash/epic core/src/genesis.rs (`mainnet_genesis_hash`,
# `floonet_genesis_hash`, Epic 4.0.4). Mainnet's was also read back from
# node.epiccash.com's `get_header [0]` on 2026-10-13 and matches.
MAINNET_GENESIS = "454018a56d86e37611bdcabc7de670305c3f3dc9675e314b437f1adc29430851"
FLOONET_GENESIS = "95d457c669f65ee27b0c90b6b11c53d9b51eb0610b6ea8d5c2a45f96d8200c67"
GENESIS = {MAINNET_GENESIS: Chain.MAINNET, FLOONET_GENESIS: Chain.FLOONET}

# P2P wire constants, from EpicCash/epic p2p/src/msg.rs and core/src/global.rs.
MAGIC = {Chain.MAINNET: bytes([97, 61]), Chain.FLOONET: bytes([83, 59])}
MSG_HAND = 1
MSG_SHAKE = 2
MSG_HEADER_LEN = 2 + 1 + 8
P2P_PROTOCOL_VERSION = 2
"""`global::PROTOCOL_VERSION`. The node answers with min(ours, its own)."""
SHAKE_MAX_LEN = 4 * 88
"""`max_msg_size(Shake) * 4`, the node's own read limit for this message."""
P2P_READ_CAP = 4096
P2P_USER_AGENT = "epic-status-quickcheck/1"
MAX_DIFFICULTY_ENTRIES = 16
MAX_USER_AGENT_BYTES = 256

PEERS_NOTE = (
    "Peer counts come only from a node's owner API, which needs that node's "
    "api_secret, so no outside check can see them."
)
HANDSHAKE_OFF_NOTE = (
    "No P2P handshake is attempted: Epic records peers by IP, and a handshake from "
    "here would change how that node records this server's own node."
)

ApiOutcome = Literal[
    "answered",
    "api_secret",
    "rate_limited",
    "http_error",
    "not_epic",
    "refused",
    "timeout",
    "tls",
    "unreachable",
]
ErrorKind = Literal["input", "blocked", "dns", "rate_limited", "busy"]
Network = Literal["mainnet", "floonet"]
Sync = Literal["synced", "behind", "ahead", "unknown"]
Tone = Literal["ok", "warn", "bad", "info"]


class QuickCheckInputError(Exception):
    """The address cannot be checked as typed. `message` is shown to the visitor."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# ------------------------------------------------------------------------ result


class ApiCheck(BaseModel):
    port: int
    scheme: Literal["http", "https"] | None = None
    attempted: bool = True
    ok: bool = False
    outcome: ApiOutcome | None = None
    http_status: int | None = None
    latency_ms: int | None = None
    error: str | None = None
    tls_warning: str | None = None
    height: int | None = None
    tip_hash: str | None = None
    node_version: str | None = None
    block_header_version: int | None = None
    genesis_hash: str | None = None
    network: Network | None = None
    network_inferred: bool = False


class P2PCheck(BaseModel):
    port: int
    attempted: bool = True
    tcp_open: bool = False
    latency_ms: int | None = None
    handshake_attempted: bool = False
    handshake_ok: bool = False
    handshake_note: str | None = None
    user_agent: str | None = None
    protocol_version: int | None = None
    capabilities: int | None = None
    network: Network | None = None
    error: str | None = None


class QuickCheckResult(BaseModel):
    input: str
    host: str | None = None
    address: str | None = None
    port_given: int | None = None
    checked_at: datetime
    duration_ms: int = 0
    error_kind: ErrorKind | None = None
    error: str | None = None
    retry_after_s: int | None = None
    api: ApiCheck | None = None
    p2p: P2PCheck | None = None
    network: Network | None = None
    network_inferred: bool = False
    network_tip: int | None = None
    lag: int | None = None
    sync: Sync = "unknown"
    answered_port: int | None = None
    offer_default_retry: bool = False
    peers_available: Literal[False] = False
    peers_note: str = PEERS_NOTE
    listed_slug: str | None = None
    tone: Tone = "info"
    headline: str = ""


# ------------------------------------------------------------------------ parser


@dataclass(frozen=True)
class ParsedAddress:
    host: str
    """Lower-case, no brackets, no trailing dot."""
    port: int | None
    scheme: Literal["http", "https"] | None

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def url_host(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")
_DOTTED_RE = re.compile(r"^[0-9.]+$")
_ALLOWED_PATHS = frozenset({"", "/", "/v2/foreign", "/v2/foreign/"})


def port_allowed(port: int) -> bool:
    """3413 and 3414, or any unprivileged port. Nothing at or below 1024: that range
    is where SSH, SMTP, HTTP and the other services a probe must never reach live."""
    return port in DEFAULT_PORTS or 1025 <= port <= 65535


def _parse_port(text: str) -> int:
    if not text.isascii() or not text.isdigit():
        raise QuickCheckInputError("The port must be a number, such as 3413.")
    port = int(text)
    if not 1 <= port <= 65535:
        raise QuickCheckInputError(
            f"Port {port} is out of range; Epic nodes use 3413 for the API and 3414 for peers."
        )
    if not port_allowed(port):
        raise QuickCheckInputError(
            f"Port {port} is not checked here; use the node's API port (usually 3413) "
            "or its peer port (3414)."
        )
    return port


def _valid_host(host: str) -> str:
    """Return the canonical host or raise."""
    bad = QuickCheckInputError(f"“{host[:64]}” is not a valid hostname or IP address.")
    if not host or not host.isascii() or "%" in host:
        raise bad
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            raise bad from None
    if _DOTTED_RE.match(host):
        try:
            return str(ipaddress.IPv4Address(host))
        except ValueError:
            raise bad from None
    if len(host) > 253 or not _HOSTNAME_RE.match(host):
        raise bad
    if host.rsplit(".", 1)[-1].isdigit():
        raise bad
    return host


def parse_address(raw: str) -> ParsedAddress:
    """Read what a node operator would paste: `host`, `host:port`, an IPv4 or IPv6
    literal (bracketed when it carries a port), optionally as an http(s) URL ending
    in `/` or `/v2/foreign`.

    A bare IPv6 literal is never split at its last colon: `2001:db8::1:3413` is an
    address, and wanting port 3413 on it means `[2001:db8::1]:3413`.
    """
    text = raw.strip()
    if not text:
        raise QuickCheckInputError(
            "Enter a node address, such as node.example.org or node.example.org:3413."
        )
    if len(text) > MAX_INPUT_CHARS:
        raise QuickCheckInputError("That address is longer than any hostname can be.")
    if any(c.isspace() for c in text):
        raise QuickCheckInputError("An address cannot contain spaces.")

    scheme: Literal["http", "https"] | None = None
    rest = text
    if "://" in text:
        given, rest = text.split("://", 1)
        given = given.lower()
        if given in ("ws", "wss"):
            raise QuickCheckInputError(
                "That looks like an Epicbox relay address; this check is for nodes."
            )
        if given == "http":
            scheme = "http"
        elif given == "https":
            scheme = "https"
        else:
            raise QuickCheckInputError("Only http:// and https:// addresses can be checked.")

    if "?" in rest or "#" in rest:
        raise QuickCheckInputError(
            "Remove the ?… or #… part; only a host and an optional port are needed."
        )
    authority, slash, path = rest.partition("/")
    path = slash + path
    if "@" in authority or "@" in path:
        raise QuickCheckInputError(
            "Remove the user name and password; this check never sends credentials."
        )
    if path.lower() not in _ALLOWED_PATHS:
        raise QuickCheckInputError(
            "Remove the path after the host; only /v2/foreign is ever requested."
        )

    authority = authority.lower()
    port: int | None = None
    if authority.startswith("["):
        inside, close, after = authority[1:].partition("]")
        if not close or ":" not in inside:
            raise QuickCheckInputError("A bracketed address must be an IPv6 literal, like [2001:db8::1].")
        host = inside
        if after:
            if not after.startswith(":"):
                raise QuickCheckInputError(f"“{authority[:64]}” is not a valid address.")
            port = _parse_port(after[1:])
    elif authority.count(":") >= 2:
        host = authority
    elif ":" in authority:
        host, _, port_text = authority.partition(":")
        port = _parse_port(port_text)
    else:
        host = authority

    if host.endswith(".") and not host.endswith(".."):
        host = host[:-1]  # the fully-qualified form of the same name
    return ParsedAddress(host=_valid_host(host), port=port, scheme=scheme)


# ---------------------------------------------------------- local addresses


def _canonical(addr: str) -> str:
    return str(ipaddress.ip_address(addr.split("%", 1)[0]))


def _ipv6_from_proc(path: Path) -> set[str]:
    found: set[str] = set()
    for line in path.read_text().splitlines():
        fields = line.split()
        if fields and len(fields[0]) == 32:
            found.add(str(ipaddress.IPv6Address(int(fields[0], 16))))
    return found


def _ipv4_from_fib_trie(path: Path) -> set[str]:
    """Every local IPv4 address, secondaries included: `/32 host LOCAL` leaves in
    the kernel's routing trie. `SIOCGIFADDR` only reports one per interface."""
    found: set[str] = set()
    last: str | None = None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("|--"):
            last = stripped[3:].strip()
        elif "/32 host LOCAL" in stripped and last is not None:
            try:
                found.add(str(ipaddress.IPv4Address(last)))
            except ValueError:
                pass
    return found


def _ipv4_from_ioctl() -> set[str]:
    found: set[str] = set()
    siocgifaddr = 0x8915
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in socket.if_nameindex():
            try:
                packed = fcntl.ioctl(
                    sock.fileno(), siocgifaddr, struct.pack("256s", name[:15].encode())
                )
            except OSError:
                continue
            found.add(socket.inet_ntoa(packed[20:24]))
    return found


def read_local_addresses(proc: Path = Path("/proc/net")) -> frozenset[str]:
    """This machine's interface addresses. Raises OSError if neither family could
    be read, so the caller can fail closed rather than conclude "none"."""
    found: set[str] = set()
    readable = False
    try:
        found |= _ipv6_from_proc(proc / "if_inet6")
        readable = True
    except OSError:
        pass
    v4: set[str] = set()
    try:
        v4 = _ipv4_from_fib_trie(proc / "fib_trie")
        readable = readable or bool(v4)
    except OSError:
        pass
    if not v4:
        try:
            v4 = _ipv4_from_ioctl()
            readable = True
        except OSError:
            pass
    found |= v4
    if not readable:
        raise OSError("no local address source was readable")
    return frozenset(found)


class LocalAddresses:
    """Cached view of this host's own addresses, plus any declared in settings."""

    def __init__(
        self,
        extra: Iterable[str] = (),
        *,
        reader: Callable[[], frozenset[str]] = read_local_addresses,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._extra = frozenset(_canonical(a.strip()) for a in extra if a.strip())
        self._reader = reader
        self._clock = clock
        self._cached: frozenset[str] | None = None
        self._at = 0.0

    def get(self) -> frozenset[str] | None:
        """None when detection failed: the caller must refuse rather than assume."""
        now = self._clock()
        if self._cached is None or now - self._at > LOCAL_ADDRESS_TTL_S:
            try:
                self._cached = frozenset(_canonical(a) for a in self._reader()) | self._extra
            except (OSError, ValueError):
                return None
            self._at = now
        return self._cached


# ------------------------------------------------------------------ rate limits


class _Window:
    """Timestamps per key within one sliding window."""

    def __init__(self, limit: int, seconds: float) -> None:
        self.limit = limit
        self.seconds = seconds
        self.hits: dict[str, deque[float]] = {}

    def _trim(self, key: str, now: float) -> deque[float]:
        hits = self.hits.get(key)
        if hits is None:
            return deque()
        while hits and now - hits[0] >= self.seconds:
            hits.popleft()
        if not hits:
            del self.hits[key]
        return hits

    def retry_after(self, key: str, now: float) -> int | None:
        hits = self._trim(key, now)
        if len(hits) < self.limit:
            return None
        return max(1, int(hits[0] + self.seconds - now + 0.999))

    def record(self, key: str, now: float) -> None:
        if key not in self.hits and len(self.hits) >= MAX_TRACKED_KEYS:
            for key_ in list(self.hits):
                self._trim(key_, now)
            while len(self.hits) >= MAX_TRACKED_KEYS:
                self.hits.pop(next(iter(self.hits)))
        self.hits.setdefault(key, deque()).append(now)


class QuickCheckLimiter:
    """Per visitor (salted hash, never the address), per target IP, and in total."""

    def __init__(self, salt: str, clock: Callable[[], float] = time.monotonic) -> None:
        self._salt = salt
        self._clock = clock
        self._minute = _Window(CLIENT_PER_MINUTE, 60.0)
        self._hour = _Window(CLIENT_PER_HOUR, 3600.0)
        self._target = _Window(TARGET_PER_MINUTE, 60.0)
        self.active = 0

    def _key(self, client_ip: str) -> str:
        """One key per IPv4 address and per IPv6 /64.

        A /64 is what one subscriber line is given, and every address in it is theirs to
        use: keyed by full address, one visitor would have 2^64 separate allowances."""
        try:
            ip = ipaddress.ip_address(client_ip.split("%", 1)[0])
        except ValueError:
            who = client_ip
        else:
            mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
            if mapped is not None:
                who = str(mapped)
            elif isinstance(ip, ipaddress.IPv6Address):
                who = str(ipaddress.ip_network(f"{ip}/64", strict=False))
            else:
                who = str(ip)
        return hashlib.sha256(f"{self._salt}:{who}".encode()).hexdigest()[:32]

    def take_client(self, client_ip: str) -> int | None:
        """Count one check for this visitor; the retry delay if over the limit."""
        key, now = self._key(client_ip), self._clock()
        waits = [w for w in (self._minute.retry_after(key, now), self._hour.retry_after(key, now)) if w]
        if waits:
            return max(waits)
        self._minute.record(key, now)
        self._hour.record(key, now)
        return None

    def take_target(self, address: str) -> int | None:
        now = self._clock()
        wait = self._target.retry_after(address, now)
        if wait:
            return wait
        self._target.record(address, now)
        return None

    def acquire(self) -> bool:
        if self.active >= MAX_CONCURRENT:
            return False
        self.active += 1
        return True

    def release(self) -> None:
        self.active = max(0, self.active - 1)


# ------------------------------------------------------------------ P2P codec


class P2PError(Exception):
    pass


@dataclass(frozen=True)
class Shake:
    version: int
    capabilities: int
    user_agent: str
    genesis: str
    difficulty: dict[int, int] = field(default_factory=dict)


def encode_peer_addr(ip: str, port: int) -> bytes:
    """`PeerAddr::write`: tag 0 + 4 octets + u16 port, or tag 1 + 8 u16 segments +
    u16 port. Big-endian throughout."""
    addr = ipaddress.ip_address(ip)
    tag = b"\x00" if addr.version == 4 else b"\x01"
    return tag + addr.packed + struct.pack(">H", port)


def encode_hand(*, chain: Chain, nonce: int, receiver_ip: str, receiver_port: int) -> bytes:
    """A `Hand` message, header included, laid out as `impl Writeable for Hand`:

    version u32 | capabilities u32 | nonce u64 | total_difficulty (u64 count, then
    u8 algo + u64 per entry) | sender_addr | receiver_addr | user_agent (u64 length
    + bytes) | genesis 32 bytes.

    Capabilities 0 (UNKNOWN) and an empty difficulty: this probe offers nothing, so
    the node never asks it for blocks or peers. Sender 0.0.0.0:0, so the record the
    node keeps is not a dialable address.
    """
    ua = P2P_USER_AGENT.encode()
    genesis = bytes.fromhex(MAINNET_GENESIS if chain is Chain.MAINNET else FLOONET_GENESIS)
    body = (
        struct.pack(">IIQ", P2P_PROTOCOL_VERSION, 0, nonce)
        + struct.pack(">Q", 0)
        + encode_peer_addr("0.0.0.0", 0)
        + encode_peer_addr(receiver_ip, receiver_port)
        + struct.pack(">Q", len(ua))
        + ua
        + genesis
    )
    return MAGIC[chain] + struct.pack(">BQ", MSG_HAND, len(body)) + body


def parse_msg_header(head: bytes, chain: Chain) -> int:
    """Validate a message header as a `Shake`; return its body length."""
    if len(head) != MSG_HEADER_LEN:
        raise P2PError("short message header")
    if head[:2] != MAGIC[chain]:
        raise P2PError("wrong network magic")
    msg_type, msg_len = struct.unpack(">BQ", head[2:])
    if msg_type != MSG_SHAKE:
        raise P2PError(f"expected Shake, got message type {msg_type}")
    if msg_len > SHAKE_MAX_LEN:
        raise P2PError(f"Shake of {msg_len} bytes exceeds {SHAKE_MAX_LEN}")
    return int(msg_len)


def parse_shake(body: bytes) -> Shake:
    """`impl Readable for Shake`: version u32 | capabilities u32 | difficulty |
    user_agent (u64 length + bytes) | genesis 32 bytes."""
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if n < 0 or pos + n > len(body):
            raise P2PError("truncated Shake")
        chunk = body[pos : pos + n]
        pos += n
        return chunk

    version, capabilities = struct.unpack(">II", take(8))
    (count,) = struct.unpack(">Q", take(8))
    if count > MAX_DIFFICULTY_ENTRIES:
        raise P2PError("implausible difficulty entry count")
    difficulty: dict[int, int] = {}
    for _ in range(count):
        algo, value = struct.unpack(">BQ", take(9))
        difficulty[algo] = value
    (ua_len,) = struct.unpack(">Q", take(8))
    if ua_len > MAX_USER_AGENT_BYTES:
        raise P2PError("implausible user agent length")
    user_agent = take(ua_len).decode("utf-8", errors="replace")
    genesis = take(32).hex()
    return Shake(
        version=version,
        capabilities=capabilities,
        user_agent=user_agent,
        genesis=genesis,
        difficulty=difficulty,
    )


async def handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    chain: Chain,
    receiver_ip: str,
    receiver_port: int,
    timeout: float,
) -> Shake:
    """Send one `Hand`, read one `Shake`, nothing else. At most 11 + 352 bytes read."""
    nonce = secrets.randbits(64)
    async with asyncio.timeout(timeout):
        writer.write(
            encode_hand(chain=chain, nonce=nonce, receiver_ip=receiver_ip, receiver_port=receiver_port)
        )
        await writer.drain()
        try:
            head = await reader.readexactly(MSG_HEADER_LEN)
            msg_len = parse_msg_header(head, chain)
            body = await reader.readexactly(msg_len)
        except asyncio.IncompleteReadError:
            raise P2PError("peer closed the connection without a handshake") from None
    if len(head) + len(body) > P2P_READ_CAP:
        raise P2PError("handshake larger than the read cap")
    return parse_shake(body)


# ------------------------------------------------------------------ probes


class _Deadline:
    def __init__(self, seconds: float) -> None:
        self._loop = asyncio.get_running_loop()
        self.at = self._loop.time() + seconds

    def budget(self) -> float:
        return max(0.0, min(QUICKCHECK_TIMEOUT_S, self.at - self._loop.time()))

    def now(self) -> float:
        return self._loop.time()


class PeerMismatch(Exception):
    """The socket connected somewhere other than the address that was vetted."""


def _same_ip(a: str, b: str) -> bool:
    try:
        return _canonical(a) == _canonical(b)
    except ValueError:
        return False


async def _call(
    client: httpx.AsyncClient,
    resolved: Resolved,
    method: str,
    params: Any,
    deadline: _Deadline,
) -> CappedResponse:
    budget = deadline.budget()
    if budget <= 0:
        raise TimeoutError
    async with asyncio.timeout(budget):
        response = await post_capped(client, resolved, _rpc(method, params), max_bytes=MAX_BODY_BYTES)
    if response.peer is not None and not _same_ip(response.peer, resolved.primary):
        raise PeerMismatch(response.peer)
    return response


def _failure(exc: BaseException) -> tuple[ApiOutcome, str]:
    if isinstance(exc, PeerMismatch):
        return "unreachable", "connected to a different address than the one checked"
    if isinstance(exc, BodyTooLarge):
        return "not_epic", "response larger than 64 KiB; not an Epic node"
    if isinstance(exc, EncodedBody):
        return "http_error", "compressed response refused"
    if isinstance(exc, httpx.RemoteProtocolError | httpx.DecodingError):
        return "not_epic", "something answered, but not with HTTP"
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        return "timeout", "connection timed out"
    reason, message = classify_http_error(exc)
    if reason is Reason.TLS:
        return "tls", message
    if reason is Reason.TIMEOUT:
        return "timeout", message
    if reason is Reason.REFUSED:
        if "refused" in message:
            return "refused", message
        return "unreachable", message
    return "unreachable", message


def _is_cert_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "certificate" in text or "verify failed" in text


def _json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


async def probe_api(
    clients: tuple[httpx.AsyncClient, httpx.AsyncClient],
    *,
    hostname: str,
    address: str,
    port: int,
    scheme: Literal["http", "https"] | None,
    deadline: _Deadline,
) -> ApiCheck:
    """`get_tip`, then `get_version` and `get_header [0]` if it answered.

    Without a typed scheme https is tried first and plain http only after a TLS
    protocol failure — Epic's own listener speaks plain HTTP on 3413, many public
    ones are TLS. A certificate that does not verify is retried once without
    verification, as `probe_tip` does: such a node is up, and says so with a warning.
    """
    verified, insecure = clients
    result = ApiCheck(port=port)
    schemes: list[Literal["http", "https"]] = [scheme] if scheme else ["https", "http"]
    response: CappedResponse | None = None
    resolved: Resolved | None = None
    client = verified
    loop = asyncio.get_running_loop()
    started = loop.time()

    for attempt in schemes:
        resolved = Resolved(hostname=hostname, port=port, addresses=(address,), scheme=attempt)
        result.scheme = attempt
        started = loop.time()
        try:
            response = await _call(verified, resolved, "get_tip", [], deadline)
            client = verified
            break
        except Exception as exc:  # noqa: BLE001 - every failure becomes an outcome
            outcome, message = _failure(exc)
            if outcome == "tls" and attempt == "https" and _is_cert_error(exc):
                try:
                    started = loop.time()
                    response = await _call(insecure, resolved, "get_tip", [], deadline)
                    client = insecure
                    result.tls_warning = "certificate not valid"
                    break
                except Exception as retry_exc:  # noqa: BLE001
                    outcome, message = _failure(retry_exc)
            result.outcome, result.error = outcome, message
            if outcome == "tls" and attempt == "https" and len(schemes) > 1:
                continue
            return result

    if response is None or resolved is None:
        return result
    result.latency_ms = int((loop.time() - started) * 1000)
    result.http_status = response.status_code
    result.error = None

    status = response.status_code
    if status == 401:
        result.outcome, result.error = "api_secret", "the API requires an api_secret"
        return result
    if status == 429:
        result.outcome, result.error = "rate_limited", "the node is rate-limiting requests"
        return result
    if 300 <= status < 400:
        result.outcome, result.error = "http_error", f"HTTP {status} redirect, not followed"
        return result
    if status >= 400:
        result.outcome, result.error = "http_error", f"HTTP {status}"
        return result

    payload, error = _unwrap(_json(response.body))
    height = payload.get("height") if payload else None
    if payload is None or not isinstance(height, int) or isinstance(height, bool):
        result.outcome = "not_epic"
        result.error = error if payload is None else "no height in the tip"
        if _json(response.body) is None:
            result.error = "answered, but not with JSON"
        return result

    result.ok, result.outcome = True, "answered"
    result.height = height
    tip_hash = payload.get("last_block_pushed")
    result.tip_hash = tip_hash if isinstance(tip_hash, str) else None

    version, header = await asyncio.gather(
        _call(client, resolved, "get_version", [], deadline),
        _call(client, resolved, "get_header", [0, None, None], deadline),
        return_exceptions=True,
    )
    if isinstance(version, CappedResponse) and version.status_code == 200:
        data, _ = _unwrap(_json(version.body))
        if data:
            nv, bhv = data.get("node_version"), data.get("block_header_version")
            result.node_version = nv[:64] if isinstance(nv, str) else None
            result.block_header_version = bhv if isinstance(bhv, int) else None
    if isinstance(header, CappedResponse) and header.status_code == 200:
        data, _ = _unwrap(_json(header.body))
        if data and data.get("height") == 0 and isinstance(data.get("hash"), str):
            genesis = str(data["hash"]).lower()
            result.genesis_hash = genesis[:64]
            result.network = _net(GENESIS.get(genesis))
    return result


async def probe_p2p(
    *,
    address: str,
    port: int,
    deadline: _Deadline,
    do_handshake: bool,
    chain: Chain | None,
) -> P2PCheck:
    """TCP connect to the peer port; optionally one Hand/Shake, then hang up."""
    result = P2PCheck(port=port)
    loop = asyncio.get_running_loop()
    start = loop.time()
    budget = deadline.budget()
    try:
        if budget <= 0:
            raise TimeoutError
        async with asyncio.timeout(budget):
            reader, writer = await asyncio.open_connection(address, port)
    except TimeoutError:
        result.error = "connection timed out"
        return result
    except ConnectionRefusedError:
        result.error = "connection refused"
        return result
    except OSError:
        result.error = "could not connect"
        return result

    try:
        peer = writer.get_extra_info("peername")
        if not (isinstance(peer, tuple) and peer and _same_ip(str(peer[0]), address)):
            result.error = "connected to a different address than the one checked"
            return result
        result.tcp_open = True
        result.latency_ms = int((loop.time() - start) * 1000)
        if not do_handshake:
            result.handshake_note = HANDSHAKE_OFF_NOTE
            return result
        # 3414 is mainnet's default peer port (floonet's is 13414), so mainnet is the
        # assumption when the API did not say. There is no retry with floonet magic:
        # a failed Hand gets this address banned, and a banned address is refused
        # before its second Hand is read.
        net = chain or Chain.MAINNET
        result.handshake_attempted = True
        try:
            shake = await handshake(
                reader,
                writer,
                chain=net,
                receiver_ip=address,
                receiver_port=port,
                timeout=max(0.1, deadline.budget()),
            )
        except P2PError as exc:
            result.error = str(exc)
            return result
        except TimeoutError:
            result.error = "no handshake reply"
            return result
        except OSError:
            result.error = "connection dropped during the handshake"
            return result
        result.handshake_ok = True
        result.user_agent = shake.user_agent[:128]
        result.protocol_version = shake.version
        result.capabilities = shake.capabilities
        result.network = _net(GENESIS.get(shake.genesis))
        return result
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


# --------------------------------------------------------- network comparison


def infer_network(height: int, tips: Mapping[Chain, int | None]) -> Chain | None:
    """The chain whose tip is closest to `height`. A guess, and labelled as one."""
    known = [(abs(tip - height), chain) for chain, tip in tips.items() if tip is not None]
    if not known:
        return None
    return min(known, key=lambda pair: pair[0])[1]


def compare(
    height: int | None, chain: Chain | None, tips: Mapping[Chain, int | None], healthy_lag: int
) -> tuple[int | None, int | None, Sync]:
    """(network_tip, lag, sync) for a node at `height` on `chain`."""
    if height is None or chain is None:
        return None, None, "unknown"
    tip = tips.get(chain)
    if tip is None:
        return None, None, "unknown"
    lag = tip - height
    if abs(lag) <= healthy_lag:
        return tip, lag, "synced"
    return tip, lag, "behind" if lag > 0 else "ahead"


def listed_slug(host: str, targets: Iterable[Target]) -> str | None:
    """The board slug for this hostname, if the board lists it."""
    wanted = host.lower()
    for target in targets:
        names = {target.slug.lower()}
        display = target.display_host.lower()
        names.add(display)
        names.add(display.rsplit(":", 1)[0] if display.count(":") == 1 else display)
        endpoint_host = urlsplit(target.endpoint).hostname
        if endpoint_host:
            names.add(endpoint_host.lower())
        if wanted in names:
            return target.slug
    return None


_CLOSED_WORDS: dict[str, str] = {
    "refused": "closed",
    "timeout": "not answering",
    "tls": "failing TLS",
    "unreachable": "unreachable",
    "not_epic": "not answering as an Epic node",
    "http_error": "returning an HTTP error",
}


def _summarise(result: QuickCheckResult) -> tuple[Tone, str]:
    api, p2p = result.api, result.p2p
    p2p_open = p2p is not None and p2p.tcp_open
    if api is not None and api.ok:
        where = f"Answering on {api.port}"
        sync_text = {
            "synced": "in sync",
            "behind": f"{result.lag or 0:,} blocks behind",
            "ahead": f"{-(result.lag or 0):,} blocks ahead of the network",
            "unknown": "network tip unknown here",
        }[result.sync]
        if result.network == "mainnet":
            return ("ok" if result.sync == "synced" else "warn"), f"{where}, {sync_text}."
        if result.network == "floonet":
            return "warn", f"{where}: a floonet node, not mainnet ({sync_text})."
        return "warn", f"{where}, but on neither mainnet nor floonet."
    if api is not None and api.outcome == "api_secret":
        extra = f"; peer port {p2p.port} open" if p2p is not None and p2p_open else ""
        return "warn", f"Node on {api.port} requires an api_secret{extra}."
    if api is not None and api.outcome == "rate_limited":
        return "warn", f"Node on {api.port} is rate-limiting requests."
    if p2p is not None and p2p_open:
        if api is not None and api.attempted and api.outcome:
            word = _CLOSED_WORDS.get(api.outcome, "not answering")
            return "warn", f"Peer port {p2p.port} open; API on {api.port} {word}."
        return "warn", f"Peer port {p2p.port} open."
    if api is not None and api.outcome in ("not_epic", "http_error"):
        return "bad", f"Something answered on {api.port}, but not as an Epic node."
    ports = [str(c.port) for c in (api, p2p) if c is not None and c.attempted]
    return "bad", f"No answer on {' or '.join(ports) or 'any port'}."


_REFUSAL_HEADLINES: dict[str, str] = {
    "input": "Check the address.",
    "blocked": "That address cannot be checked from here.",
    "dns": "That name does not resolve.",
    "rate_limited": "Too many checks; try again shortly.",
    "busy": "The checker is busy; try again in a few seconds.",
}


# ------------------------------------------------------------------ entry point


class QuickChecker:
    """Long-lived state: rate limits, the local-address cache and two HTTP clients.

    Its own clients rather than the poller's, for the reason the submit validator has
    its own: an unvetted host must not occupy connection slots the board depends on.
    No keep-alive either, so one visitor's TLS session is never reused under another
    hostname that resolved to the same IP.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        salt: str | None = None,
        local: LocalAddresses | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.limiter = QuickCheckLimiter(salt or secrets.token_hex(16), clock)
        self.local = local or LocalAddresses(
            settings.quickcheck_extra_self_addresses.split(",")
        )
        self._clients: tuple[httpx.AsyncClient, httpx.AsyncClient] | None = None
        self._dns_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=DNS_THREADS, thread_name_prefix="quickcheck-dns"
        )
        # Released from the worker thread when the lookup really ends, so it is a
        # threading primitive rather than an asyncio one.
        self._dns_slots = threading.BoundedSemaphore(DNS_THREADS)

    async def getaddrinfo(self, host: str, port: int) -> list[Any]:
        """Resolve on this checker's own threads, never the event loop's shared pool.

        Raises `DnsBusy` rather than queueing when every thread is still occupied, which
        bounds what a run of unanswerable names can hold to `DNS_THREADS` threads that
        nothing else on the server uses.
        """
        if not self._dns_slots.acquire(blocking=False):
            raise DnsBusy
        try:
            future = self._dns_pool.submit(
                functools.partial(
                    socket.getaddrinfo,
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            )
        except RuntimeError:  # pool shut down
            self._dns_slots.release()
            raise DnsBusy from None
        future.add_done_callback(lambda _f: self._dns_slots.release())
        result: list[Any] = await asyncio.wrap_future(future)
        return result

    def clients(self) -> tuple[httpx.AsyncClient, httpx.AsyncClient]:
        if self._clients is None:
            self._clients = (_client(verify=True), _client(verify=False))
        return self._clients

    async def aclose(self) -> None:
        if self._clients is not None:
            for client in self._clients:
                await client.aclose()
            self._clients = None
        # A stuck lookup must not hold up a restart.
        self._dns_pool.shutdown(wait=False, cancel_futures=True)


class DnsBusy(Exception):
    """Every quick-check resolver thread is still occupied."""


def _client(*, verify: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(QUICKCHECK_TIMEOUT_S),
        # Must stay off: a 302 to 169.254.169.254 is the oldest SSRF trick there is.
        follow_redirects=False,
        verify=verify,
        trust_env=False,
        limits=httpx.Limits(max_connections=2 * MAX_CONCURRENT, max_keepalive_connections=0),
        headers={"user-agent": "epic-status-quickcheck/1"},
    )


async def run_check(
    checker: QuickChecker,
    raw: str,
    *,
    client_ip: str,
    use_defaults: bool,
    tips: Mapping[Chain, int | None],
    listed: Iterable[Target] = (),
) -> QuickCheckResult:
    """Check one typed address. Never raises for anything the visitor typed.

    `tips` are the current network heights from the poller's snapshots; `listed` the
    targets on the board, for `listed_slug`. `api.Service.quick_check` supplies both.
    """
    loop = asyncio.get_running_loop()
    started = loop.time()
    result = QuickCheckResult(input=raw.strip()[:MAX_INPUT_CHARS], checked_at=datetime.now(UTC))

    def refuse(kind: ErrorKind, message: str, retry: int | None = None) -> QuickCheckResult:
        result.error_kind, result.error, result.retry_after_s = kind, message, retry
        result.tone, result.headline = "info", _REFUSAL_HEADLINES[kind]
        result.duration_ms = int((loop.time() - started) * 1000)
        return result

    try:
        parsed = parse_address(raw)
    except QuickCheckInputError as exc:
        return refuse("input", exc.message)
    result.host, result.port_given = parsed.host, parsed.port
    result.listed_slug = listed_slug(parsed.host, listed)

    wait = checker.limiter.take_client(client_ip)
    if wait:
        return refuse("rate_limited", f"You have run several checks; try again in {wait} s.", wait)
    if not checker.limiter.acquire():
        return refuse("busy", "Several checks are running already; try again in a few seconds.", BUSY_RETRY_S)
    try:
        return await _checked(checker, parsed, result, use_defaults, tips, refuse, started)
    finally:
        checker.limiter.release()


async def _checked(
    checker: QuickChecker,
    parsed: ParsedAddress,
    result: QuickCheckResult,
    use_defaults: bool,
    tips: Mapping[Chain, int | None],
    refuse: Callable[..., QuickCheckResult],
    started: float,
) -> QuickCheckResult:
    settings = checker.settings
    loop = asyncio.get_running_loop()
    deadline = _Deadline(QUICKCHECK_DEADLINE_S)

    api_port: int | None
    p2p_port: int | None
    if use_defaults or parsed.port is None:
        api_port, p2p_port = API_PORT, P2P_PORT
    elif parsed.port == P2P_PORT:
        api_port, p2p_port = None, P2P_PORT
    else:
        api_port, p2p_port = parsed.port, None
    custom_port = not use_defaults and parsed.port is not None and parsed.port not in DEFAULT_PORTS

    probe_port = api_port or p2p_port or API_PORT
    try:
        async with asyncio.timeout(deadline.budget()):
            resolved = await resolve_endpoint(
                f"{parsed.scheme or 'https'}://{parsed.url_host}:{probe_port}",
                allow_private=settings.allow_private_targets,
                getaddrinfo=checker.getaddrinfo,
            )
    except DnsBusy:
        return refuse("busy", "Several lookups are still running; try again in a few seconds.", BUSY_RETRY_S)
    except TimeoutError:
        return refuse("dns", f"Looking up {parsed.host} timed out.")
    except TargetRejected as exc:
        if exc.reason is Reason.DNS:
            return refuse("dns", f"{parsed.host} does not resolve; check the spelling.")
        return refuse("blocked", f"{exc.message[:1].upper()}{exc.message[1:]}, which is never checked.")
    result.address = resolved.primary

    if custom_port:
        own = checker.local.get()
        if own is None:
            return refuse("blocked", "Custom ports cannot be checked right now; try the default ports.")
        for addr in resolved.addresses:
            # Unwrapped first: [::ffff:<our IPv4>] and the NAT64 form reach the same
            # IPv4 service on Linux, and whether `_is_public` refuses them outright
            # depends on the Python release's `ipaddress` rules.
            ip = ipaddress.ip_address(_canonical(addr))
            forms = {str(ip)}
            if isinstance(ip, ipaddress.IPv6Address):
                inner = ip.ipv4_mapped or _embedded_ipv4(ip)
                if inner is not None:
                    forms.add(str(inner))
            if forms & own:
                return refuse(
                    "blocked",
                    "That address belongs to this server; only ports 3413 and 3414 are checked on it.",
                )

    wait = checker.limiter.take_target(_canonical(resolved.primary))
    if wait:
        return refuse("rate_limited", f"That node was checked several times just now; try again in {wait} s.", wait)

    api_task = (
        probe_api(
            checker.clients(),
            hostname=parsed.host,
            address=resolved.primary,
            port=api_port,
            scheme=parsed.scheme,
            deadline=deadline,
        )
        if api_port is not None
        else None
    )

    async def p2p(chain: Chain | None) -> P2PCheck | None:
        if p2p_port is None:
            return None
        return await probe_p2p(
            address=resolved.primary,
            port=p2p_port,
            deadline=deadline,
            do_handshake=settings.quickcheck_p2p_handshake,
            chain=chain,
        )

    if settings.quickcheck_p2p_handshake:
        # The handshake needs the network, which the API names: run in order.
        result.api = await api_task if api_task is not None else None
        api_chain = _chain_of(result.api.network) if result.api is not None else None
        result.p2p = await p2p(api_chain)
    else:
        api_result, p2p_result = await asyncio.gather(
            api_task if api_task is not None else _none(), p2p(None)
        )
        result.api, result.p2p = api_result, p2p_result

    if result.api is None and api_port is None:
        result.api = ApiCheck(port=API_PORT, attempted=False)
    if result.p2p is None and p2p_port is None:
        result.p2p = P2PCheck(port=P2P_PORT, attempted=False)

    _finish(result, tips, settings.thresholds.tip_lag_healthy, custom_port)
    result.duration_ms = int((loop.time() - started) * 1000)
    return result


async def _none() -> None:
    return None


def _net(chain: Chain | None) -> Network | None:
    if chain is Chain.MAINNET:
        return "mainnet"
    if chain is Chain.FLOONET:
        return "floonet"
    return None


def _chain_of(network: str | None) -> Chain | None:
    return Chain(network) if network else None


def _finish(
    result: QuickCheckResult, tips: Mapping[Chain, int | None], healthy_lag: int, custom_port: bool
) -> None:
    api, p2p = result.api, result.p2p
    chain: Chain | None = None
    if api is not None and api.ok:
        if api.network is not None:
            chain = Chain(api.network)
        elif api.genesis_hash is None and api.height is not None:
            chain = infer_network(api.height, tips)
            if chain is not None:
                api.network = _net(chain)
                api.network_inferred = True
    elif p2p is not None and p2p.network is not None:
        chain = Chain(p2p.network)
    result.network = _net(chain)
    result.network_inferred = bool(api is not None and api.network_inferred)
    height = api.height if api is not None and api.ok else None
    result.network_tip, result.lag, result.sync = compare(height, chain, tips, healthy_lag)
    if api is not None and api.ok:
        result.answered_port = api.port
    elif p2p is not None and p2p.tcp_open:
        result.answered_port = p2p.port
    result.offer_default_retry = bool(custom_port and api is not None and not api.ok)
    result.tone, result.headline = _summarise(result)
