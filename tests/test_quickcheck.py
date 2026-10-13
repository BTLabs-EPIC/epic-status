"""Quick node check: the one route where a visitor makes this server connect somewhere.

Nothing here touches the network. DNS is faked on the running loop, HTTP is mocked
with respx, and the P2P tests run a real TCP server on loopback — the same reasoning
as the Epicbox test: what the wire carries is the contract, and only a socket shows it.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastapi import FastAPI

from epic_status import quickcheck as qc
from epic_status.api import create_app
from epic_status.config import Settings
from epic_status.models import Chain, Kind, NetworkSummary, Snapshot, Source, Target, TargetStatus
from epic_status.quickcheck import (
    FLOONET_GENESIS,
    MAINNET_GENESIS,
    ApiCheck,
    LocalAddresses,
    P2PCheck,
    QuickChecker,
    QuickCheckInputError,
    QuickCheckLimiter,
    compare,
    encode_hand,
    infer_network,
    listed_slug,
    parse_address,
    parse_msg_header,
    parse_shake,
    port_allowed,
    probe_api,
    probe_p2p,
    run_check,
)

PUBLIC = "8.8.8.8"
OURS = "8.8.4.4"  # stands in for this server's own public address


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "db": tmp_path / "status.db",
        "prober_id": "test",
        "targets_file": tmp_path / "targets.toml",
        "allow_private_targets": False,
    }
    values.update(overrides)
    return Settings(**values)


def checker_for(
    tmp_path: Path,
    *,
    local: frozenset[str] | None = frozenset({"127.0.0.1", OURS}),
    clock: Callable[[], float] | None = None,
    **overrides: Any,
) -> QuickChecker:
    def reader() -> frozenset[str]:
        if local is None:
            raise OSError("no /proc")
        return local

    kwargs: dict[str, Any] = {"salt": "s", "local": LocalAddresses(reader=reader)}
    if clock is not None:
        kwargs["clock"] = clock
    return QuickChecker(make_settings(tmp_path, **overrides), **kwargs)


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> Callable[[dict[str, list[str]]], None]:
    """Answer getaddrinfo from a table. Literals resolve to themselves."""

    def install(table: dict[str, list[str]]) -> None:
        loop = asyncio.get_running_loop()

        async def getaddrinfo(host: str, port: int, **_: Any) -> list[Any]:
            addrs = table.get(host, [host])
            if not addrs:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            out = []
            for addr in addrs:
                family = socket.AF_INET6 if ":" in addr else socket.AF_INET
                out.append((family, socket.SOCK_STREAM, 6, "", (addr, port)))
            return out

        monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)

    return install


@pytest.fixture
def fake_probes(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, int]]:
    """Replace both probes; record (kind, address, port) of every call."""
    calls: list[tuple[str, str, int]] = []

    async def api(_clients: Any, *, hostname: str, address: str, port: int, **_: Any) -> ApiCheck:
        calls.append(("api", address, port))
        return ApiCheck(port=port, ok=True, outcome="answered", height=1000,
                        network="mainnet", scheme="https")

    async def p2p(*, address: str, port: int, **_: Any) -> P2PCheck:
        calls.append(("p2p", address, port))
        return P2PCheck(port=port, tcp_open=True, latency_ms=5)

    monkeypatch.setattr(qc, "probe_api", api)
    monkeypatch.setattr(qc, "probe_p2p", p2p)
    return calls


TIPS = {Chain.MAINNET: 1000, Chain.FLOONET: 400}


# ----------------------------------------------------------------------- parser

PARSED = [
    ("node.example.org", "node.example.org", None, None),
    ("node.example.org:3413", "node.example.org", 3413, None),
    ("  NODE.Example.ORG:3414  ", "node.example.org", 3414, None),
    ("node.example.org.", "node.example.org", None, None),
    ("8.8.8.8", "8.8.8.8", None, None),
    ("8.8.8.8:3413", "8.8.8.8", 3413, None),
    ("[2001:db8::1]:3413", "2001:db8::1", 3413, None),
    ("[2001:DB8::1]", "2001:db8::1", None, None),
    ("2001:db8::1", "2001:db8::1", None, None),
    ("2001:db8::1:3413", "2001:db8::1:3413", None, None),  # a bare v6 is never split
    ("http://node.example.org", "node.example.org", None, "http"),
    ("https://node.example.org:13413", "node.example.org", 13413, "https"),
    ("HTTPS://node.example.org:3413/", "node.example.org", 3413, "https"),
    ("https://node.example.org/v2/foreign", "node.example.org", None, "https"),
    ("http://[2001:db8::1]:3413/v2/foreign", "2001:db8::1", 3413, "http"),
    ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com", None, None),
]


@pytest.mark.parametrize(("raw", "host", "port", "scheme"), PARSED)
def test_parse_accepts(raw: str, host: str, port: int | None, scheme: str | None) -> None:
    parsed = parse_address(raw)
    assert (parsed.host, parsed.port, parsed.scheme) == (host, port, scheme)


REJECTED = [
    ("", "Enter a node address"),
    ("   ", "Enter a node address"),
    ("a" * 254, "longer"),
    ("user:pass@node.example.org", "user name"),
    ("https://user@node.example.org:3413", "user name"),
    ("node.example.org/?x=1", "?"),
    ("node.example.org#frag", "?"),
    ("ws://epicbox.example.org", "Epicbox"),
    ("wss://epicbox.example.org", "Epicbox"),
    ("ftp://node.example.org", "http://"),
    ("node.example.org:22", "not checked"),
    ("node.example.org:443", "not checked"),
    ("node.example.org:80", "not checked"),
    ("node.example.org:1024", "not checked"),
    ("node.example.org:0", "out of range"),
    ("node.example.org:70000", "out of range"),
    ("node.example.org:abc", "number"),
    ("node.example.org:", "number"),
    ("node.example.org/admin", "path"),
    ("node.example.org/v2/owner", "path"),
    ("localhost", "valid hostname"),
    ("-bad.example.org", "valid hostname"),
    ("bad_host.example.org", "valid hostname"),
    ("999.1.1.1", "valid hostname"),
    ("1.2.3", "valid hostname"),
    ("[not-v6]:3413", "IPv6"),
    ("fe80::1%eth0", "valid hostname"),
    ("node .example.org", "spaces"),
]


@pytest.mark.parametrize(("raw", "fragment"), REJECTED)
def test_parse_rejects(raw: str, fragment: str) -> None:
    with pytest.raises(QuickCheckInputError) as exc:
        parse_address(raw)
    assert fragment in exc.value.message
    # One actionable sentence, not a stack of them.
    assert exc.value.message.count(". ") == 0


@pytest.mark.parametrize(
    ("port", "allowed"),
    [(3413, True), (3414, True), (1025, True), (13413, True), (65535, True),
     (1024, False), (443, False), (80, False), (22, False), (0, False), (65536, False)],
)
def test_port_policy(port: int, allowed: bool) -> None:
    assert port_allowed(port) is allowed


# ------------------------------------------------------------------------ guard

BLOCKED = [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "100.100.100.200", "0.0.0.0", "224.0.0.1", "240.0.0.1",
    "::1", "fe80::1", "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1", "2002:7f00:1::",
]


@pytest.mark.parametrize("address", BLOCKED)
async def test_guard_refuses_non_public(
    tmp_path: Path, address: str, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"evil.example.org": [address]})
    result = await run_check(
        checker_for(tmp_path), "evil.example.org", client_ip="1.1.1.1",
        use_defaults=False, tips=TIPS,
    )
    assert result.error_kind == "blocked"
    assert result.tone == "info"
    assert fake_probes == []  # nothing was contacted


async def test_guard_refuses_one_private_among_public(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"mixed.example.org": [PUBLIC, "10.0.0.5"]})
    result = await run_check(
        checker_for(tmp_path), "mixed.example.org", client_ip="1.1.1.1",
        use_defaults=False, tips=TIPS,
    )
    assert result.error_kind == "blocked"
    assert "10.0.0.5" in (result.error or "")
    assert fake_probes == []


async def test_guard_allows_public_and_pins_the_address(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    result = await run_check(
        checker_for(tmp_path), "node.example.org", client_ip="1.1.1.1",
        use_defaults=False, tips=TIPS,
    )
    assert result.error_kind is None
    assert result.address == PUBLIC
    # Defaults: API on 3413 and P2P on 3414, both at the validated address.
    assert sorted(fake_probes) == [("api", PUBLIC, 3413), ("p2p", PUBLIC, 3414)]
    assert result.tone == "ok"
    assert result.headline == "Answering on 3413, in sync."


async def test_dns_failure(tmp_path: Path, fake_dns: Any, fake_probes: list[Any]) -> None:
    fake_dns({"nope.example.org": []})
    result = await run_check(
        checker_for(tmp_path), "nope.example.org", client_ip="1.1.1.1",
        use_defaults=False, tips=TIPS,
    )
    assert result.error_kind == "dns"
    assert fake_probes == []


async def test_own_address_refused_on_a_user_port(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    """Hairpin SSRF: our own public IP on 5432 would reach what the firewall hides."""
    fake_dns({"self.example.org": [OURS]})
    result = await run_check(
        checker_for(tmp_path), "self.example.org:5432", client_ip="1.1.1.1",
        use_defaults=False, tips=TIPS,
    )
    assert result.error_kind == "blocked"
    assert "this server" in (result.error or "")
    assert fake_probes == []


@pytest.mark.parametrize("raw", ["self.example.org", "self.example.org:3413", "self.example.org:3414"])
async def test_own_address_allowed_on_default_ports(
    tmp_path: Path, raw: str, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"self.example.org": [OURS]})
    result = await run_check(
        checker_for(tmp_path), raw, client_ip="1.1.1.1", use_defaults=False, tips=TIPS
    )
    assert result.error_kind is None
    assert fake_probes


async def test_local_detection_failure_fails_closed_for_user_ports(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    checker = checker_for(tmp_path, local=None)
    custom = await run_check(
        checker, "node.example.org:13413", client_ip="1.1.1.1", use_defaults=False, tips=TIPS
    )
    assert custom.error_kind == "blocked"
    default = await run_check(
        checker, "node.example.org", client_ip="1.1.1.2", use_defaults=False, tips=TIPS
    )
    assert default.error_kind is None


def test_local_address_readers(tmp_path: Path) -> None:
    (tmp_path / "if_inet6").write_text(
        "00000000000000000000000000000001 01 80 10 80       lo\n"
        "20010db8000000000000000000000001 02 30 00 80     eth0\n"
    )
    (tmp_path / "fib_trie").write_text(
        "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n"
        "Local:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 127.0.0.1\n        /32 host LOCAL\n"
        "     |-- 203.0.113.10\n        /32 host LOCAL\n"
        "     |-- 203.0.113.255\n        /32 link BROADCAST\n"
    )
    found = qc.read_local_addresses(tmp_path)
    assert found == {"::1", "2001:db8::1", "127.0.0.1", "203.0.113.10"}


# ------------------------------------------------------------------ port strategy


async def test_typed_3414_is_probed_as_p2p_only(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    result = await run_check(
        checker_for(tmp_path), "node.example.org:3414", client_ip="1.1.1.1",
        use_defaults=False, tips=TIPS,
    )
    assert fake_probes == [("p2p", PUBLIC, 3414)]
    assert result.api is not None and result.api.attempted is False
    assert result.answered_port == 3414


async def test_typed_custom_port_failing_offers_defaults(
    tmp_path: Path, fake_dns: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    calls: list[int] = []

    async def api(_c: Any, *, port: int, **_: Any) -> ApiCheck:
        calls.append(port)
        return ApiCheck(port=port, outcome="refused", error="connection refused")

    monkeypatch.setattr(qc, "probe_api", api)
    checker = checker_for(tmp_path)
    result = await run_check(
        checker, "node.example.org:13413", client_ip="1.1.1.1", use_defaults=False, tips=TIPS
    )
    assert calls == [13413]
    assert result.offer_default_retry is True
    assert result.tone == "bad"
    assert result.headline == "No answer on 13413."


async def test_defaults_flag_ignores_the_typed_port(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    result = await run_check(
        checker_for(tmp_path), "node.example.org:13413", client_ip="1.1.1.1",
        use_defaults=True, tips=TIPS,
    )
    assert sorted(fake_probes) == [("api", PUBLIC, 3413), ("p2p", PUBLIC, 3414)]
    assert result.offer_default_retry is False


async def test_p2p_only_headline(tmp_path: Path, fake_dns: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_dns({"node.example.org": [PUBLIC]})

    async def api(_c: Any, *, port: int, **_: Any) -> ApiCheck:
        return ApiCheck(port=port, outcome="refused")

    async def p2p(*, port: int, **_: Any) -> P2PCheck:
        return P2PCheck(port=port, tcp_open=True)

    monkeypatch.setattr(qc, "probe_api", api)
    monkeypatch.setattr(qc, "probe_p2p", p2p)
    result = await run_check(
        checker_for(tmp_path), "node.example.org", client_ip="1.1.1.1", use_defaults=False, tips=TIPS
    )
    assert result.headline == "Peer port 3414 open; API on 3413 closed."
    assert result.tone == "warn"
    assert result.answered_port == 3414
    assert result.peers_available is False


# ------------------------------------------------------------------- rate limits


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_limiter_per_client_minute_and_hour() -> None:
    clock = Clock()
    limiter = QuickCheckLimiter("salt", clock)
    for _ in range(qc.CLIENT_PER_MINUTE):
        assert limiter.take_client("1.1.1.1") is None
    wait = limiter.take_client("1.1.1.1")
    assert wait is not None and 1 <= wait <= 60
    assert limiter.take_client("2.2.2.2") is None  # someone else is unaffected
    # Over an hour of steady use, the hourly cap is what stops it.
    allowed = qc.CLIENT_PER_MINUTE
    for _ in range(50):  # 50 x 61 s stays inside the first hour
        clock.now += 61
        while limiter.take_client("1.1.1.1") is None:
            allowed += 1
    assert allowed == qc.CLIENT_PER_HOUR
    # And the client's address is never stored, only a salted hash of it.
    assert all("1.1.1.1" not in key for key in limiter._minute.hits)


def test_limiter_per_target() -> None:
    limiter = QuickCheckLimiter("salt", Clock())
    for _ in range(qc.TARGET_PER_MINUTE):
        assert limiter.take_target(PUBLIC) is None
    assert limiter.take_target(PUBLIC) is not None
    assert limiter.take_target("9.9.9.9") is None


def test_limiter_concurrency() -> None:
    limiter = QuickCheckLimiter("salt", Clock())
    assert all(limiter.acquire() for _ in range(qc.MAX_CONCURRENT))
    assert limiter.acquire() is False
    limiter.release()
    assert limiter.acquire() is True


def test_limiter_memory_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qc, "MAX_TRACKED_KEYS", 50)
    limiter = QuickCheckLimiter("salt", Clock())
    for i in range(500):
        limiter.take_client(f"10.0.{i // 256}.{i % 256}")
    assert len(limiter._minute.hits) <= 50


async def test_run_check_rate_limited_and_busy(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    checker = checker_for(tmp_path)
    for _ in range(qc.CLIENT_PER_MINUTE):
        ok = await run_check(checker, "node.example.org", client_ip="1.1.1.1",
                             use_defaults=False, tips=TIPS)
        assert ok.error_kind is None
    limited = await run_check(checker, "node.example.org", client_ip="1.1.1.1",
                              use_defaults=False, tips=TIPS)
    assert limited.error_kind == "rate_limited" and limited.retry_after_s
    # Input errors cost nothing, so a typo does not burn the visitor's quota.
    bad = await run_check(checker, "node.example.org:22", client_ip="3.3.3.3",
                          use_defaults=False, tips=TIPS)
    assert bad.error_kind == "input"
    checker.limiter.active = qc.MAX_CONCURRENT
    busy = await run_check(checker, "node.example.org", client_ip="4.4.4.4",
                           use_defaults=False, tips=TIPS)
    assert busy.error_kind == "busy" and busy.retry_after_s


async def test_run_check_per_target_limit(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    checker = checker_for(tmp_path)
    kinds = [
        (await run_check(checker, "node.example.org", client_ip=f"5.5.5.{i}",
                         use_defaults=False, tips=TIPS)).error_kind
        for i in range(qc.TARGET_PER_MINUTE + 1)
    ]
    assert kinds[:-1] == [None] * qc.TARGET_PER_MINUTE
    assert kinds[-1] == "rate_limited"


# --------------------------------------------------------------------- API probe

RPC = f"https://{PUBLIC}:3413/v2/foreign"
RPC_HTTP = f"http://{PUBLIC}:3413/v2/foreign"


def _ok(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"id": 1, "jsonrpc": "2.0", "result": {"Ok": payload}})


def node_handler(genesis: str | None = MAINNET_GENESIS, height: int = 995) -> Callable[[httpx.Request], httpx.Response]:
    import json as _json

    def handle(request: httpx.Request) -> httpx.Response:
        method = _json.loads(request.content)["method"]
        if method == "get_tip":
            return _ok({"height": height, "last_block_pushed": "ab" * 32,
                        "total_difficulty": {"randomx": 1}})
        if method == "get_version":
            return _ok({"node_version": "4.1.0", "block_header_version": 6})
        if genesis is None:
            return httpx.Response(200, json={"result": {"Err": "NotFound"}})
        return _ok({"height": 0, "hash": genesis, "previous": "00" * 32})

    return handle


@pytest.fixture
async def clients() -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    a, b = qc._client(verify=True), qc._client(verify=False)
    try:
        yield a, b
    finally:
        await a.aclose()
        await b.aclose()


async def _api(clients: Any, scheme: Any = None, port: int = 3413) -> ApiCheck:
    return await probe_api(
        clients, hostname="node.example.org", address=PUBLIC, port=port,
        scheme=scheme, deadline=qc._Deadline(qc.QUICKCHECK_DEADLINE_S),
    )


async def test_api_answered_reads_tip_version_and_genesis(clients: Any) -> None:
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(RPC).mock(side_effect=node_handler())
        result = await _api(clients)
    assert result.ok and result.outcome == "answered"
    assert (result.height, result.node_version, result.block_header_version) == (995, "4.1.0", 6)
    assert result.network == "mainnet" and result.network_inferred is False
    assert result.scheme == "https"
    # Every request carried the name only as Host, and asked for no compression.
    for call in route.calls:
        assert call.request.headers["host"] == "node.example.org"
        assert call.request.headers["accept-encoding"] == "identity"
        assert call.request.url.path == "/v2/foreign"


async def test_api_floonet_genesis(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).mock(side_effect=node_handler(genesis=FLOONET_GENESIS))
        result = await _api(clients)
    assert result.network == "floonet"


async def test_api_unknown_genesis_is_no_network(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).mock(side_effect=node_handler(genesis="cd" * 32))
        result = await _api(clients)
    assert result.ok and result.network is None and result.genesis_hash == "cd" * 32


async def test_api_401_is_api_secret(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).respond(401)
        result = await _api(clients)
    assert (result.ok, result.outcome, result.http_status) == (False, "api_secret", 401)


async def test_api_429(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).respond(429)
        result = await _api(clients)
    assert result.outcome == "rate_limited"


async def test_api_timeout(clients: Any) -> None:
    with respx.mock(assert_all_called=False) as mock:
        https = mock.post(RPC).mock(side_effect=httpx.ConnectTimeout("timed out"))
        http = mock.post(RPC_HTTP).respond(200)
        result = await _api(clients)
    assert result.outcome == "timeout"
    assert https.called and not http.called  # a timeout is not a reason to try http


async def test_api_refused(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).mock(side_effect=httpx.ConnectError("[Errno 111] Connection refused"))
        result = await _api(clients)
    assert result.outcome == "refused"


async def test_api_not_json(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).respond(200, text="<html>hello</html>")
        result = await _api(clients)
    assert result.outcome == "not_epic" and "JSON" in (result.error or "")


async def test_api_json_but_not_epic(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).respond(200, json={"hello": "world"})
        result = await _api(clients)
    assert result.outcome == "not_epic"


async def test_api_oversized_body_aborted(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).respond(200, content=b"x" * (qc.MAX_BODY_BYTES + 1))
        result = await _api(clients)
    assert result.outcome == "not_epic" and "64 KiB" in (result.error or "")


async def test_api_oversized_stream_without_length_aborted(clients: Any) -> None:
    sent = 0

    async def endless() -> AsyncIterator[bytes]:
        nonlocal sent
        for _ in range(1000):
            sent += 8192
            yield b"x" * 8192

    with respx.mock() as mock:
        mock.post(RPC).mock(return_value=httpx.Response(200, content=endless()))
        result = await _api(clients)
    assert result.outcome == "not_epic"
    assert sent < 2 * qc.MAX_BODY_BYTES  # stopped reading, not buffered to the end


async def test_api_compressed_body_refused(clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).respond(200, content=b"\x1f\x8b", headers={"content-encoding": "gzip"})
        result = await _api(clients)
    assert result.outcome == "http_error"


async def test_api_redirect_not_followed(clients: Any) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.post(RPC).respond(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        metadata = mock.route(host="169.254.169.254").respond(200)
        result = await _api(clients)
    assert result.outcome == "http_error" and "redirect" in (result.error or "")
    assert not metadata.called


async def test_api_tls_protocol_error_falls_back_to_http(clients: Any) -> None:
    """Epic's own listener speaks plain HTTP on 3413; a TLS hello to it fails."""
    with respx.mock() as mock:
        mock.post(RPC).mock(side_effect=httpx.ConnectError("[SSL] record layer failure (_ssl.c:1000)"))
        mock.post(RPC_HTTP).mock(side_effect=node_handler())
        result = await _api(clients)
    assert result.ok and result.scheme == "http" and result.tls_warning is None


async def test_api_typed_https_does_not_fall_back(clients: Any) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.post(RPC).mock(side_effect=httpx.ConnectError("[SSL] record layer failure"))
        http = mock.post(RPC_HTTP).mock(side_effect=node_handler())
        result = await _api(clients, scheme="https")
    assert result.outcome == "tls" and not http.called


async def test_api_bad_certificate_retried_without_verification(clients: Any) -> None:
    calls = {"n": 0}
    handler = node_handler()

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        return handler(request)

    with respx.mock() as mock:
        mock.post(RPC).mock(side_effect=flaky)
        result = await _api(clients)
    assert result.ok and result.tls_warning == "certificate not valid"


async def test_api_header_failure_leaves_network_to_inference(tmp_path: Path, clients: Any) -> None:
    with respx.mock() as mock:
        mock.post(RPC).mock(side_effect=node_handler(genesis=None, height=390))
        api = await _api(clients)
    assert api.ok and api.network is None and api.genesis_hash is None
    result = qc.QuickCheckResult(input="x", checked_at=datetime.now(UTC), api=api)
    qc._finish(result, TIPS, 10, custom_port=False)
    assert result.network == "floonet" and result.network_inferred is True
    assert result.sync == "synced" and result.tone == "warn"
    assert "floonet" in result.headline


async def test_api_peer_mismatch_is_refused(clients: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """If the socket ever lands somewhere other than the vetted IP, nothing is read."""

    async def wrong_peer(*_: Any, **__: Any) -> qc.CappedResponse:
        return qc.CappedResponse(status_code=200, headers=httpx.Headers(), body=b"{}", peer="10.0.0.1")

    monkeypatch.setattr(qc, "post_capped", wrong_peer)
    result = await _api(clients, scheme="http")
    assert not result.ok and result.outcome == "unreachable"


# --------------------------------------------------------------------- P2P codec


def test_hand_encoding_is_byte_exact() -> None:
    """Spelled out field by field from `impl Writeable for Hand` (p2p/src/msg.rs),
    `PeerAddr::write` (p2p/src/types.rs) and `Difficulty::write`
    (core/src/pow/types.rs). Big-endian everywhere, u64 length prefixes."""
    ua = b"epic-status-quickcheck/1"
    body = (
        bytes.fromhex("00000002")  # ProtocolVersion u32
        + bytes.fromhex("00000000")  # capabilities u32: UNKNOWN
        + bytes.fromhex("0102030405060708")  # nonce u64
        + bytes.fromhex("0000000000000000")  # total_difficulty: zero entries
        + bytes.fromhex("00" "00000000" "0000")  # sender_addr: v4 0.0.0.0:0
        + bytes.fromhex("00" "08080808" "0d56")  # receiver_addr: v4 8.8.8.8:3414
        + len(ua).to_bytes(8, "big") + ua  # user_agent
        + bytes.fromhex(MAINNET_GENESIS)  # genesis hash
    )
    header = bytes([97, 61]) + b"\x01" + len(body).to_bytes(8, "big")
    assert encode_hand(chain=Chain.MAINNET, nonce=0x0102030405060708,
                       receiver_ip="8.8.8.8", receiver_port=3414) == header + body
    assert len(body) <= 4 * 128  # under the node's own Hand limit


def test_hand_ipv6_receiver_and_floonet() -> None:
    wire = encode_hand(chain=Chain.FLOONET, nonce=1, receiver_ip="2001:db8::1", receiver_port=13414)
    assert wire[:3] == bytes([83, 59, 1])
    receiver = wire[11 + 24 + 7:][:19]
    assert receiver == b"\x01" + bytes.fromhex("20010db8000000000000000000000001") + bytes.fromhex("3466")
    assert wire.endswith(bytes.fromhex(FLOONET_GENESIS))


def shake_bytes(*, genesis: str = MAINNET_GENESIS, ua: bytes = b"MW/Epic 4.1.0",
                chain: Chain = Chain.MAINNET, msg_len: int | None = None) -> bytes:
    """A Shake as `impl Writeable for Shake` writes it."""
    body = (
        struct.pack(">II", 2, 0b1111)
        + struct.pack(">Q", 4)
        + b"".join(struct.pack(">BQ", algo, 10 + algo) for algo in range(4))
        + struct.pack(">Q", len(ua)) + ua
        + bytes.fromhex(genesis)
    )
    length = len(body) if msg_len is None else msg_len
    return qc.MAGIC[chain] + struct.pack(">BQ", 2, length) + body


def test_parse_shake() -> None:
    wire = shake_bytes()
    msg_len = parse_msg_header(wire[:11], Chain.MAINNET)
    shake = parse_shake(wire[11 : 11 + msg_len])
    assert (shake.version, shake.capabilities, shake.user_agent) == (2, 15, "MW/Epic 4.1.0")
    assert shake.genesis == MAINNET_GENESIS
    assert shake.difficulty == {0: 10, 1: 11, 2: 12, 3: 13}


@pytest.mark.parametrize(
    ("head", "fragment"),
    [
        (bytes([83, 59, 2]) + struct.pack(">Q", 50), "magic"),
        (bytes([97, 61, 3]) + struct.pack(">Q", 16), "type 3"),
        (bytes([97, 61, 2]) + struct.pack(">Q", 4 * 88 + 1), "exceeds"),
        (bytes([97, 61, 2]) + struct.pack(">Q", 2**63), "exceeds"),
    ],
)
def test_shake_header_rejections(head: bytes, fragment: str) -> None:
    with pytest.raises(qc.P2PError) as exc:
        parse_msg_header(head, Chain.MAINNET)
    assert fragment in str(exc.value)


def test_shake_body_rejections() -> None:
    with pytest.raises(qc.P2PError):
        parse_shake(b"\x00" * 10)  # truncated
    huge_count = struct.pack(">II", 2, 0) + struct.pack(">Q", 10**9)
    with pytest.raises(qc.P2PError):
        parse_shake(huge_count)
    huge_ua = struct.pack(">II", 2, 0) + struct.pack(">Q", 0) + struct.pack(">Q", 10**6)
    with pytest.raises(qc.P2PError):
        parse_shake(huge_ua)


# --------------------------------------------------------- P2P over a real socket


class FakePeer:
    """A loopback TCP server that records what it was sent and answers with `reply`."""

    def __init__(self, reply: bytes | None) -> None:
        self.reply = reply
        self.received = b""
        self.port = 0
        self.server: asyncio.Server | None = None
        self.done = asyncio.Event()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if self.reply is not None:
                head = await reader.readexactly(11)
                (length,) = struct.unpack(">Q", head[3:])
                self.received = head + await reader.readexactly(length)
                if not self.reply:
                    return  # hang up after reading the Hand, as a refusing node does
                writer.write(self.reply)
                await writer.drain()
            # Whatever else arrives before the client hangs up.
            self.received += await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            self.done.set()

    async def __aenter__(self) -> FakePeer:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_: object) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


async def _p2p(port: int, *, handshake: bool, chain: Chain | None = Chain.MAINNET) -> P2PCheck:
    return await probe_p2p(address="127.0.0.1", port=port, deadline=qc._Deadline(5.0),
                           do_handshake=handshake, chain=chain)


async def test_p2p_tcp_only_sends_nothing() -> None:
    """The default. Connect, measure, hang up — not one byte written."""
    async with FakePeer(reply=None) as peer:
        result = await _p2p(peer.port, handshake=False)
        await asyncio.wait_for(peer.done.wait(), 2)
    assert result.tcp_open and result.latency_ms is not None
    assert result.handshake_attempted is False and result.handshake_ok is False
    assert result.handshake_note == qc.HANDSHAKE_OFF_NOTE
    assert peer.received == b""


async def test_p2p_handshake_against_a_real_socket() -> None:
    async with FakePeer(reply=shake_bytes()) as peer:
        result = await _p2p(peer.port, handshake=True)
        await asyncio.wait_for(peer.done.wait(), 2)
    assert result.handshake_ok
    assert (result.user_agent, result.protocol_version, result.capabilities) == ("MW/Epic 4.1.0", 2, 15)
    assert result.network == "mainnet"
    # Exactly one Hand went out, and nothing after it.
    assert peer.received[:3] == bytes([97, 61, 1])
    (length,) = struct.unpack(">Q", peer.received[3:11])
    assert len(peer.received) == 11 + length
    assert b"epic-status-quickcheck/1" in peer.received


async def test_p2p_handshake_oversized_shake_rejected() -> None:
    async with FakePeer(reply=shake_bytes(msg_len=4 * 88 + 1)) as peer:
        result = await _p2p(peer.port, handshake=True)
    assert result.tcp_open and not result.handshake_ok
    assert "exceeds" in (result.error or "")


async def test_p2p_handshake_peer_closes() -> None:
    async with FakePeer(reply=b"") as peer:
        result = await _p2p(peer.port, handshake=True)
    assert result.tcp_open and not result.handshake_ok
    assert "without a handshake" in (result.error or "")


async def test_p2p_handshake_floonet_genesis_reported() -> None:
    async with FakePeer(reply=shake_bytes(genesis=FLOONET_GENESIS, chain=Chain.FLOONET)) as peer:
        result = await _p2p(peer.port, handshake=True, chain=Chain.FLOONET)
    assert result.handshake_ok and result.network == "floonet"
    assert peer.received[:2] == bytes([83, 59])


async def test_p2p_closed_port() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    result = await _p2p(port, handshake=False)
    assert result.tcp_open is False and result.error == "connection refused"


# -------------------------------------------------------------- network and sync


@pytest.mark.parametrize(
    ("height", "chain", "expected"),
    [
        (1000, Chain.MAINNET, (1000, 0, "synced")),
        (990, Chain.MAINNET, (1000, 10, "synced")),
        (989, Chain.MAINNET, (1000, 11, "behind")),
        (1011, Chain.MAINNET, (1000, -11, "ahead")),
        (400, Chain.FLOONET, (400, 0, "synced")),
        (None, Chain.MAINNET, (None, None, "unknown")),
        (1000, None, (None, None, "unknown")),
    ],
)
def test_compare(height: int | None, chain: Chain | None, expected: tuple[Any, ...]) -> None:
    assert compare(height, chain, TIPS, 10) == expected


def test_compare_without_a_tip() -> None:
    assert compare(5, Chain.MAINNET, {Chain.MAINNET: None}, 10) == (None, None, "unknown")


def test_infer_network() -> None:
    assert infer_network(999, TIPS) is Chain.MAINNET
    assert infer_network(380, TIPS) is Chain.FLOONET
    assert infer_network(5, {Chain.MAINNET: None, Chain.FLOONET: None}) is None


@pytest.mark.parametrize(
    ("api", "p2p", "tone", "headline"),
    [
        (ApiCheck(port=3413, ok=True, outcome="answered", height=900, network="mainnet"),
         None, "warn", "Answering on 3413, 100 blocks behind."),
        (ApiCheck(port=3413, ok=True, outcome="answered", height=400, network="floonet"),
         None, "warn", "Answering on 3413: a floonet node, not mainnet (in sync)."),
        (ApiCheck(port=3413, outcome="api_secret"), P2PCheck(port=3414, tcp_open=True),
         "warn", "Node on 3413 requires an api_secret; peer port 3414 open."),
        (ApiCheck(port=3413, outcome="timeout"), P2PCheck(port=3414),
         "bad", "No answer on 3413 or 3414."),
        (ApiCheck(port=3413, outcome="not_epic"), P2PCheck(port=3414),
         "bad", "Something answered on 3413, but not as an Epic node."),
    ],
)
def test_summary(api: ApiCheck, p2p: P2PCheck | None, tone: str, headline: str) -> None:
    result = qc.QuickCheckResult(input="x", checked_at=datetime.now(UTC), api=api, p2p=p2p)
    qc._finish(result, TIPS, 10, custom_port=False)
    assert (result.tone, result.headline) == (tone, headline)


def test_listed_slug() -> None:
    targets = [
        Target(kind=Kind.NODE, slug="node.epiccash.com", endpoint="https://node.epiccash.com:3413",
               display_host="node.epiccash.com:3413", source=Source.SEED),
        Target(kind=Kind.NODE, slug="btlabs", endpoint="https://node.btlabs.uk",
               display_host="node.btlabs.uk", source=Source.SEED),
    ]
    assert listed_slug("node.epiccash.com", targets) == "node.epiccash.com"
    assert listed_slug("node.btlabs.uk", targets) == "btlabs"
    assert listed_slug("other.example.org", targets) is None


# --------------------------------------------------------------------- JSON route


def app_for(tmp_path: Path, **overrides: Any) -> FastAPI:
    app = create_app(make_settings(tmp_path, **overrides))
    service = app.state.service
    service.quickcheck = checker_for(tmp_path)
    target = Target(kind=Kind.NODE, slug="node.example.org", endpoint="https://node.example.org:3413",
                    display_host="node.example.org:3413", source=Source.SEED)
    service.poller.snapshots[Chain.MAINNET] = Snapshot(
        generated_at=datetime.now(UTC), prober_id="test",
        network=NetworkSummary(chain=Chain.MAINNET, tip_height=1000),
        nodes=[TargetStatus(target=target)],
    )
    return app


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def test_route_runs_a_check(tmp_path: Path, fake_dns: Any, fake_probes: list[Any]) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/api/v1/check", json={"address": "node.example.org"})
    assert response.status_code == 200
    body = response.json()
    assert body["tone"] == "ok" and body["network_tip"] == 1000 and body["sync"] == "synced"
    assert body["listed_slug"] == "node.example.org"
    assert body["peers_available"] is False
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers


async def test_route_requires_json(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        form = await client.post("/api/v1/check", data={"address": "node.example.org"})
        plain = await client.post("/api/v1/check", content=b'{"address":"x"}',
                                  headers={"content-type": "text/plain"})
    assert form.status_code == 415 and plain.status_code == 415
    assert "access-control-allow-origin" not in form.headers


async def test_route_refuses_cross_site(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/api/v1/check", json={"address": "node.example.org"},
                                     headers={"sec-fetch-site": "cross-site"})
    assert response.status_code == 403


async def test_route_no_cors_preflight(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        response = await client.options(
            "/api/v1/check",
            headers={"origin": "https://evil.example", "access-control-request-method": "POST"},
        )
    assert response.status_code >= 400
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"address": 5}', b'{"address":"x","defaults":"yes"}'])
async def test_route_bad_body(tmp_path: Path, payload: bytes) -> None:
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/api/v1/check", content=payload,
                                     headers={"content-type": "application/json"})
    assert response.status_code == 400


async def test_route_body_too_large(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/api/v1/check", content=b"{" + b" " * 5000 + b"}",
                                     headers={"content-type": "application/json"})
    assert response.status_code == 413


async def test_route_input_refusal_is_200(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/api/v1/check", json={"address": "node.example.org:22"})
    assert response.status_code == 200
    assert response.json()["error_kind"] == "input"
    assert response.json()["tone"] == "info"


async def test_route_rate_limited_is_429(tmp_path: Path, fake_dns: Any, fake_probes: list[Any]) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        statuses = [
            (await client.post("/api/v1/check", json={"address": "node.example.org"})).status_code
            for _ in range(qc.CLIENT_PER_MINUTE + 1)
        ]
        last = await client.post("/api/v1/check", json={"address": "node.example.org"})
    assert statuses[:-1] == [200] * qc.CLIENT_PER_MINUTE
    assert statuses[-1] == 429
    assert int(last.headers["retry-after"]) >= 1
    assert last.json()["error_kind"] == "rate_limited"


async def test_route_defaults_flag(tmp_path: Path, fake_dns: Any, fake_probes: list[Any]) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        await client.post("/api/v1/check", json={"address": "node.example.org:13413", "defaults": True})
    assert sorted(fake_probes) == [("api", PUBLIC, 3413), ("p2p", PUBLIC, 3414)]


async def test_route_disabled_is_404(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path, quickcheck_enabled=False)) as client:
        response = await client.post("/api/v1/check", json={"address": "node.example.org"})
    assert response.status_code == 404


def test_result_model_fields() -> None:
    """The contract the board's UI is built against. Fields may be added, never renamed."""
    expected = {
        "input", "host", "address", "port_given", "checked_at", "duration_ms", "error_kind",
        "error", "retry_after_s", "api", "p2p", "network", "network_tip", "lag", "sync",
        "answered_port", "offer_default_retry", "peers_available", "peers_note",
        "listed_slug", "tone", "headline",
    }
    assert expected <= set(qc.QuickCheckResult.model_fields)
    assert {"port", "scheme", "attempted", "ok", "outcome", "http_status", "latency_ms", "error",
            "tls_warning", "height", "tip_hash", "node_version", "block_header_version",
            "network", "network_inferred"} <= set(ApiCheck.model_fields)
    assert {"port", "attempted", "tcp_open", "latency_ms", "handshake_ok", "user_agent",
            "protocol_version", "capabilities", "network", "error"} <= set(P2PCheck.model_fields)


# ----------------------------------------------------- API over a real socket


async def test_api_over_a_real_socket_reports_the_connected_peer(
    clients: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No respx: a loopback HTTP server, so the socket's peer address is real and
    the post-connect re-check runs against what the kernel actually connected to."""
    import json as _json

    seen: list[str | None] = []
    real = qc.post_capped

    async def spy(*args: Any, **kwargs: Any) -> qc.CappedResponse:
        response = await real(*args, **kwargs)
        seen.append(response.peer)
        return response

    monkeypatch.setattr(qc, "post_capped", spy)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        length = next(
            int(line.split(b":", 1)[1])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length:")
        )
        method = _json.loads(await reader.readexactly(length))["method"]
        result = {"get_tip": {"height": 7, "last_block_pushed": "aa" * 32},
                  "get_version": {"node_version": "4.1.0", "block_header_version": 6},
                  "get_header": {"height": 0, "hash": MAINNET_GENESIS}}[method]
        body = _json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"Ok": result}}).encode()
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                     b"content-length: " + str(len(body)).encode() + b"\r\nconnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await probe_api(clients, hostname="node.example.org", address="127.0.0.1",
                                 port=port, scheme="http", deadline=qc._Deadline(5.0))
    finally:
        server.close()
        await server.wait_closed()
    assert result.ok and result.height == 7 and result.network == "mainnet"
    assert seen and all(peer == "127.0.0.1" for peer in seen)
