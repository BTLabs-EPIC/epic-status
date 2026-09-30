"""Node probes, against mocked HTTP only.

The response body in `MAINNET_TIP` is a genuine recorded mainnet answer. It is
here verbatim because the two field-level facts it demonstrates are the most
likely way this module regresses:

* `total_difficulty` is an OBJECT keyed by algorithm, not an integer. Epic is
  multi-algorithm; every Grin-derived example treats it as a scalar and raises on
  the first real response.
* the payload sits inside an `Ok`/`Err` envelope inside the JSON-RPC `result`.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from epic_status.models import Reason
from epic_status.net import Resolved, build_client
from epic_status.probes.node import probe_cors, probe_header, probe_tip, probe_version

RESOLVED = Resolved(
    hostname="node.epiccash.com",
    port=3413,
    addresses=("144.202.75.237",),
    scheme="https",
)

# The URL the probe actually requests: the validated IP, never the name. If this
# constant ever has to become a hostname, address pinning has been lost.
RPC_URL = "https://144.202.75.237:3413/v2/foreign"

MAINNET_TIP: dict[str, Any] = {
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
        "Ok": {
            "height": 3721166,
            "last_block_pushed": "902031772af68dda0000000000000000000000000000000000000000000000000",
            "prev_block_to_last": "96f1804fe248b082088104fbf96596dfa4d5de66d74c1512fefeee40f8a10c04",
            "total_difficulty": {
                "cuckaroo": 25151785933,
                "cuckatoo": 123808651914255,
                "progpow": 8122621836969345041,
                "randomx": 4573849396699194,
            },
        }
    },
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


async def _tip(clients: Any) -> Any:
    client, insecure = clients
    return await probe_tip(client, insecure, RESOLVED)


# ------------------------------------------------------------------ the happy path


@respx.mock
async def test_recorded_mainnet_tip_parses(clients: Any) -> None:
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=MAINNET_TIP))

    probe = await _tip(clients)

    assert probe.ok is True
    assert probe.reason is Reason.OK
    assert probe.height == 3721166
    assert probe.tip_hash == MAINNET_TIP["result"]["Ok"]["last_block_pushed"]
    assert probe.prev_hash == MAINNET_TIP["result"]["Ok"]["prev_block_to_last"]
    assert probe.latency_ms is not None
    assert probe.http_status == 200


@respx.mock
async def test_total_difficulty_is_an_object_with_four_algorithms(clients: Any) -> None:
    """The regression that matters. Epic mines four algorithms and reports a
    difficulty per algorithm; a scalar-shaped parser raises here."""
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=MAINNET_TIP))

    probe = await _tip(clients)

    assert probe.difficulty is not None
    assert probe.difficulty.cuckaroo == 25151785933
    assert probe.difficulty.cuckatoo == 123808651914255
    assert probe.difficulty.progpow == 8122621836969345041
    assert probe.difficulty.randomx == 4573849396699194
    assert None not in probe.difficulty.fingerprint()


@respx.mock
async def test_legacy_scalar_total_difficulty_still_parses(clients: Any) -> None:
    """Not seen on mainnet, but a modified or much older node could serve the
    Grin-shaped scalar. It must degrade to a partial difficulty rather than fail
    the probe — the height is what the traffic light needs."""
    body = {
        "id": 1,
        "jsonrpc": "2.0",
        "result": {"Ok": {"height": 42, "total_difficulty": 99}},
    }
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await _tip(clients)

    assert probe.ok is True
    assert probe.height == 42
    assert probe.difficulty is not None
    assert probe.difficulty.cuckatoo == 99


@respx.mock
async def test_unknown_difficulty_algorithm_is_kept(clients: Any) -> None:
    """Difficulty allows extra keys, so a future fifth algorithm does not turn
    every node on the board red."""
    body = {
        "id": 1,
        "jsonrpc": "2.0",
        "result": {
            "Ok": {"height": 7, "total_difficulty": {"randomx": 1, "newalgo": 2}}
        },
    }
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await _tip(clients)

    assert probe.ok is True
    assert probe.difficulty is not None
    assert probe.difficulty.randomx == 1


# --------------------------------------------------------------- HTTP-level cases


@respx.mock
async def test_http_401_is_api_restricted_not_down(clients: Any) -> None:
    """The most common non-success by far. The node is running and in consensus;
    its operator simply has not made the foreign API public. Reporting it as down
    is factually wrong and generates complaints from the operators this page
    exists to help.
    """
    respx.post(RPC_URL).mock(return_value=httpx.Response(401, text="Unauthorized"))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is Reason.API_RESTRICTED
    assert probe.reason is not Reason.REFUSED
    assert probe.http_status == 401
    assert probe.latency_ms is not None


@respx.mock
@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (429, Reason.RATE_LIMITED),
        (500, Reason.BAD_RESPONSE),
        (502, Reason.BAD_RESPONSE),
        (404, Reason.BAD_RESPONSE),
    ],
)
async def test_http_status_maps_to_reason(
    clients: Any, status: int, reason: Reason
) -> None:
    respx.post(RPC_URL).mock(return_value=httpx.Response(status, text="no"))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is reason
    assert probe.http_status == status


@respx.mock
async def test_non_json_body_is_bad_response(clients: Any) -> None:
    """A 200 of HTML is an nginx holding page or a captive portal, not a node."""
    respx.post(RPC_URL).mock(
        return_value=httpx.Response(200, text="<html>hello</html>")
    )

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is Reason.BAD_RESPONSE
    assert probe.error == "response was not JSON"


# ------------------------------------------------------------- envelope failures


@respx.mock
async def test_jsonrpc_error_is_not_ok(clients: Any) -> None:
    body = {
        "id": 1,
        "jsonrpc": "2.0",
        "error": {"code": -32601, "message": "Method not found"},
    }
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is Reason.BAD_RESPONSE
    assert probe.error is not None
    assert "Method not found" in probe.error


@respx.mock
async def test_result_err_envelope_is_not_ok(clients: Any) -> None:
    """A node can answer HTTP 200 with an `Err` inside the result. Treating that as
    success is exactly how a broken node shows green."""
    body = {"id": 1, "jsonrpc": "2.0", "result": {"Err": "Internal error"}}
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.error is not None
    assert "Err" in probe.error


@respx.mock
@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"id": 1, "result": {"Ok": {}}}, id="no-height"),
        pytest.param(
            {"id": 1, "result": {"Ok": {"height": "3721166"}}}, id="height-as-string"
        ),
        pytest.param({"id": 1, "result": {"Ok": None}}, id="null-ok"),
        pytest.param({"id": 1, "result": []}, id="result-not-an-object"),
        pytest.param([1, 2, 3], id="body-not-an-object"),
    ],
)
async def test_malformed_tip_payloads_are_not_ok(clients: Any, body: Any) -> None:
    """A height that is not an int is not a height. Coercing it would let a node
    that reports `"unknown"` sit at the top of the fleet tip calculation."""
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is Reason.BAD_RESPONSE


# ---------------------------------------------------------------------- version


@respx.mock
async def test_probe_version_parses(clients: Any) -> None:
    client, _ = clients
    body = {
        "id": 1,
        "jsonrpc": "2.0",
        "result": {"Ok": {"node_version": "4.0.2", "block_header_version": 6}},
    }
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    version = await probe_version(client, RESOLVED)

    assert version.ok is True
    assert version.node_version == "4.0.2"
    assert version.block_header_version == 6


@respx.mock
async def test_probe_version_failure_is_not_fatal(clients: Any) -> None:
    """Version is decoration on a slow cadence. A node that will not answer it is
    still a healthy node, so this must report not-ok without a reason code that
    could colour the row."""
    client, _ = clients
    respx.post(RPC_URL).mock(return_value=httpx.Response(401))

    version = await probe_version(client, RESOLVED)

    assert version.ok is False
    assert version.node_version is None
    assert version.error == "HTTP 401"


# ---------------------------------------------------------------------- tip age


#: Recorded from mainnet, with the proof and the Merkle roots trimmed.
HEADER_OK = {
    "height": 3721166,
    "hash": "9db990acbdaebc0defb42a3aeb0ea62e6ec10cf8937bc9e9baf934586c2d26fd",
    "previous": "cc2c48191cec1b09f39937d0a3d75ace077765c98d50614997cbfd93d6c0c22c",
    "proof": "Cuckoo",
    "timestamp": "2026-09-22T05:41:12+00:00",
    "total_difficulty": {
        "cuckaroo": 231941927570,
        "cuckatoo": 128410260130803,
        "progpow": 8130861338913581012,
        "randomx": 4581163557466978,
    },
}


@respx.mock
async def test_probe_header_parses_a_mainnet_header(clients: Any) -> None:
    """Height alone cannot distinguish "this node is answering" from "the chain is
    moving". The header's own timestamp can, and its hash and parent are what make a
    replaced block visible."""
    client, _ = clients
    body = {"id": 1, "jsonrpc": "2.0", "result": {"Ok": HEADER_OK}}
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await probe_header(client, RESOLVED, 3721166)

    assert probe.ok is True
    header = probe.header
    assert header is not None
    assert header.mined_at.year == 2026
    assert header.mined_at.utcoffset() is not None
    assert header.mined_at.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    assert header.hash.startswith("9db990")
    assert header.previous.startswith("cc2c48")
    assert header.proof == "Cuckoo"
    assert header.total_difficulty.randomx == 4581163557466978


@respx.mock
async def test_probe_header_rejects_a_missing_timestamp(clients: Any) -> None:
    client, _ = clients
    body = {"id": 1, "jsonrpc": "2.0", "result": {"Ok": {"height": 3721166}}}
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await probe_header(client, RESOLVED, 3721166)

    assert probe.ok is False
    assert probe.error == "no timestamp in header"


@respx.mock
async def test_probe_header_rejects_the_wrong_height(clients: Any) -> None:
    """Filing a header under a height it does not belong to would corrupt the record
    that reorg detection compares against."""
    client, _ = clients
    body = {"id": 1, "jsonrpc": "2.0", "result": {"Ok": {**HEADER_OK, "height": 5}}}
    respx.post(RPC_URL).mock(return_value=httpx.Response(200, json=body))

    probe = await probe_header(client, RESOLVED, 3721166)

    assert probe.ok is False


# ------------------------------------------------------------------ transport


@respx.mock
async def test_connect_error_becomes_refused(clients: Any) -> None:
    respx.post(RPC_URL).mock(side_effect=httpx.ConnectError("Connection refused"))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is Reason.REFUSED
    assert probe.latency_ms is None


@respx.mock
async def test_timeout_becomes_timeout(clients: Any) -> None:
    respx.post(RPC_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))

    probe = await _tip(clients)

    assert probe.ok is False
    assert probe.reason is Reason.TIMEOUT


@respx.mock
async def test_probe_posts_to_the_pinned_address_with_the_host_header(
    clients: Any,
) -> None:
    """Address pinning is protection #2 in the net module: connect to the address
    that was validated, carry the name only as Host and SNI. Re-resolving at
    connect time reopens the DNS-rebinding window between check and request.
    """
    route = respx.post(RPC_URL).mock(
        return_value=httpx.Response(200, json=MAINNET_TIP)
    )

    await _tip(clients)

    request = route.calls.last.request
    assert request.url.host == "144.202.75.237"
    assert request.headers["host"] == "node.epiccash.com"
    assert request.extensions["sni_hostname"] == "node.epiccash.com"


# ----------------------------------------------------------------- browser access

ORIGIN = "https://status.example.org"


@respx.mock
async def test_probe_cors_accepts_the_mainnet_preflight_answer(clients: Any) -> None:
    """Recorded from node.epiccash.com: the node's own listener answers the preflight."""
    client, _ = clients
    route = respx.options(RPC_URL).mock(
        return_value=httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-headers": "Content-Type, Authorization",
            },
        )
    )

    assert await probe_cors(client, RESOLVED, ORIGIN) is True
    sent = route.calls.last.request.headers
    assert sent["access-control-request-method"] == "POST"
    assert sent["origin"] == ORIGIN


@respx.mock
async def test_probe_cors_needs_the_content_type_header_allowed(clients: Any) -> None:
    """An allowed origin is not enough: a JSON POST also needs `content-type`."""
    client, _ = clients
    respx.options(RPC_URL).mock(
        return_value=httpx.Response(200, headers={"access-control-allow-origin": "*"})
    )
    assert await probe_cors(client, RESOLVED, ORIGIN) is False


@respx.mock
async def test_probe_cors_is_unknown_when_the_request_fails(clients: Any) -> None:
    client, _ = clients
    respx.options(RPC_URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    assert await probe_cors(client, RESOLVED, ORIGIN) is None
