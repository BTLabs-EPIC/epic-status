"""Node status (peers): `GET /v1/status`, falling back to owner `get_status`.

The bodies are recorded mainnet answers from 2026-10-18, trimmed of the
network-wide figures the board does not show.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from epic_status.config import Settings
from epic_status.db import Database
from epic_status.models import Chain, Kind, NodeProbe, StatusProbe, StatusSource, Target
from epic_status.net import Resolved, build_client
from epic_status.poller import Poller
from epic_status.probes.node import probe_status

RESOLVED = Resolved(
    hostname="node.epiccash.com",
    port=3413,
    addresses=("144.202.75.237",),
    scheme="https",
)
V1_URL = "https://144.202.75.237:3413/v1/status"
OWNER_URL = "https://144.202.75.237:3413/v2/owner"

STATUS: dict[str, Any] = {
    "protocol_version": 2,
    "user_agent": "MW/Epic 4.1.0",
    "connections": 43,
    "tip": {
        "height": 3759223,
        "last_block_pushed": "f829" + "0" * 60,
        "prev_block_to_last": "e820" + "0" * 60,
        "total_difficulty": {
            "cuckatoo": 140102462055541,
            "cuckaroo": 928385089855,
            "progpow": 8151982727395403865,
            "randomx": 4597731608633519,
        },
    },
    "sync_status": "no_sync",
    "supply": 19459543,
    "max_supply": 21000000,
    "blocks_to_next_halving": 883337,
}

# Stock 4.1.0's answer on /v1/status, verbatim apart from whitespace.
UNAUTHORIZED = {
    "jsonrpc": "2.0",
    "error": {"code": -32600, "message": "Unauthorized"},
    "id": None,
}


@pytest.fixture
async def clients() -> Any:
    client = build_client(timeout=2.0)
    insecure = build_client(timeout=2.0, verify=False)
    try:
        yield client, insecure
    finally:
        await client.aclose()
        await insecure.aclose()


async def _status(clients: Any, **kwargs: Any) -> StatusProbe:
    client, insecure = clients
    return await probe_status(client, insecure, RESOLVED, timeout=2.0, **kwargs)


@respx.mock
async def test_v1_status_parses(clients: Any) -> None:
    v1 = respx.get(V1_URL).mock(return_value=httpx.Response(200, json=STATUS))
    owner = respx.post(OWNER_URL)

    probe = await _status(clients)

    assert probe.ok is True
    assert probe.source is StatusSource.V1
    assert probe.connections == 43
    assert probe.user_agent == "MW/Epic 4.1.0"
    assert probe.protocol_version == 2
    assert probe.sync_status == "no_sync"
    assert probe.height == 3759223
    assert probe.tip_hash == STATUS["tip"]["last_block_pushed"]
    # One request, carrying the hostname only as Host.
    assert v1.call_count == 1
    assert v1.calls[0].request.headers["host"] == "node.epiccash.com"
    assert owner.call_count == 0


@respx.mock
async def test_401_falls_back_to_owner_get_status(clients: Any) -> None:
    respx.get(V1_URL).mock(return_value=httpx.Response(401, json=UNAUTHORIZED))
    owner = respx.post(OWNER_URL).mock(
        return_value=httpx.Response(
            200, json={"id": 1, "jsonrpc": "2.0", "result": {"Ok": STATUS}}
        )
    )

    probe = await _status(clients)

    assert probe.ok is True
    assert probe.source is StatusSource.OWNER
    assert probe.connections == 43
    sent = owner.calls[0].request
    assert b'"method":"get_status"' in sent.content.replace(b" ", b"")


@respx.mock
async def test_skip_v1_goes_straight_to_the_fallback(clients: Any) -> None:
    v1 = respx.get(V1_URL)
    respx.post(OWNER_URL).mock(
        return_value=httpx.Response(200, json={"result": {"Ok": STATUS}})
    )

    probe = await _status(clients, skip_v1=True)

    assert probe.source is StatusSource.OWNER
    assert v1.call_count == 0


@respx.mock
async def test_both_failing_is_unavailable_with_both_reasons(clients: Any) -> None:
    respx.get(V1_URL).mock(return_value=httpx.Response(401, json=UNAUTHORIZED))
    respx.post(OWNER_URL).mock(
        return_value=httpx.Response(403, text="Node administration is not publicly available.")
    )

    probe = await _status(clients)

    assert probe.ok is False
    assert probe.connections is None
    assert probe.error == "/v1/status: HTTP 401; owner get_status: HTTP 403"


@respx.mock
async def test_owner_err_envelope_is_unavailable(clients: Any) -> None:
    respx.get(V1_URL).mock(return_value=httpx.Response(404))
    respx.post(OWNER_URL).mock(
        return_value=httpx.Response(200, json={"result": {"Err": "Internal"}})
    )

    probe = await _status(clients)

    assert probe.ok is False
    assert "owner get_status: node returned Err" in (probe.error or "")


@respx.mock
async def test_no_answer_does_not_try_the_fallback(clients: Any) -> None:
    """A host that timed out once will time out twice; the second call would only
    double what a dead node costs the sweep."""
    respx.get(V1_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))
    owner = respx.post(OWNER_URL)

    probe = await _status(clients)

    assert probe.ok is False
    assert owner.call_count == 0


@respx.mock
async def test_status_without_connections_is_not_ok(clients: Any) -> None:
    respx.get(V1_URL).mock(return_value=httpx.Response(200, json={"tip": {}}))
    respx.post(OWNER_URL).mock(return_value=httpx.Response(403))

    probe = await _status(clients)

    assert probe.ok is False
    assert "no connections" in (probe.error or "")


# ------------------------------------------------------------- tip agreement


def _poller(db: Database, settings: Settings) -> Poller:
    return Poller(db, settings)


def _node(i: int) -> Target:
    return Target(
        id=i,
        kind=Kind.NODE,
        slug=f"n{i}",
        display_host=f"n{i}",
        endpoint=f"https://n{i}.example",
        chain=Chain.MAINNET,
    )


def test_tip_agreement_flags_the_odd_one_out(db: Database, settings: Settings) -> None:
    poller = _poller(db, settings)
    nodes = [_node(i) for i in (1, 2, 3, 4)]
    poller._status = {
        1: StatusProbe(ok=True, connections=1, height=10, tip_hash="aa"),
        2: StatusProbe(ok=True, connections=1, height=10, tip_hash="aa"),
        3: StatusProbe(ok=True, connections=1, height=10, tip_hash="bb"),
    }
    # n4 has no status call answering; its get_tip is at another height.
    probes = {
        "n1": NodeProbe(ok=True, height=10, tip_hash="aa"),
        "n2": NodeProbe(ok=True, height=10, tip_hash="aa"),
        "n3": NodeProbe(ok=True, height=10, tip_hash="bb"),
        "n4": NodeProbe(ok=True, height=9, tip_hash="zz"),
    }

    agreement = poller._tip_agreement(nodes, probes)

    assert agreement == {"n1": True, "n2": True, "n3": False}


def test_tip_agreement_falls_back_to_get_tip(db: Database, settings: Settings) -> None:
    poller = _poller(db, settings)
    nodes = [_node(1), _node(2)]
    poller._status = {1: StatusProbe(ok=False, error="unavailable")}
    probes = {
        "n1": NodeProbe(ok=True, height=10, tip_hash="aa"),
        "n2": NodeProbe(ok=True, height=10, tip_hash="aa"),
    }

    assert poller._tip_agreement(nodes, probes) == {"n1": True, "n2": True}


@respx.mock
async def test_rate_limited_does_not_try_the_fallback(clients: Any) -> None:
    respx.get(V1_URL).mock(return_value=httpx.Response(429))
    owner = respx.post(OWNER_URL)

    probe = await _status(clients)

    assert probe.ok is False
    assert "rate limited" in (probe.error or "")
    assert owner.call_count == 0
