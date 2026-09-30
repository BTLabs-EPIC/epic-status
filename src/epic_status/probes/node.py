"""Node probes.

The whole traffic light rests on one unauthenticated call:

    POST {endpoint}/v2/foreign
    {"jsonrpc":"2.0","method":"get_tip","params":[],"id":1}

Verified against mainnet: 468 bytes of response, no credentials, and
`access-control-allow-origin: *`. At a five-second cadence that is 0.2 requests
per second per host, orders of magnitude below any rate limit an operator deploys.

Two field-level facts that break naive implementations, both confirmed against
live mainnet rather than inferred from Grin:

* `total_difficulty` is an **object**, not an integer. Epic is multi-algorithm and
  the keys are cuckaroo, cuckatoo, progpow and randomx. Every Grin-derived example
  treats it as a scalar and raises on the first real response.
* `result` is wrapped in an `Ok`/`Err` envelope inside the JSON-RPC `result`, so
  the height lives at `result.Ok.height`.

What is *not* available without credentials, and must not be promised per row:
peer counts and sync status. Those are the owner API on the same port, which
requires an `api_secret`. A remote observer gets tip, difficulty, block hash,
version and latency, and nothing else.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import httpx

from ..models import (
    BlockHeader,
    Difficulty,
    HeaderProbe,
    NodeProbe,
    Reason,
    VersionProbe,
)
from ..net import Resolved, classify_http_error, pinned_url

_RPC_PATH = "/v2/foreign"


def _rpc(method: str, params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}


async def _post(
    client: httpx.AsyncClient, resolved: Resolved, payload: dict[str, Any]
) -> httpx.Response:
    """Post to the pinned address, with the hostname carried only as Host and SNI.

    The `sni_hostname` extension is what makes certificate verification work
    against an IP-addressed URL: without it the handshake is validated against the
    literal address and every correctly-configured host fails.
    """
    return await client.post(
        pinned_url(resolved, _RPC_PATH),
        json=payload,
        headers={"host": resolved.hostname},
        extensions={"sni_hostname": resolved.hostname},
    )


def _unwrap(body: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Pull the payload out of the JSON-RPC and Ok/Err envelopes.

    Returns (payload, error_text). A node can answer 200 with an `Err`, and
    treating that as success is how a broken node shows green.
    """
    if not isinstance(body, dict):
        return None, "response was not a JSON object"
    if "error" in body and body["error"]:
        err = body["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        return None, f"JSON-RPC error: {msg}"
    result = body.get("result")
    if not isinstance(result, dict):
        return None, "no result object"
    if "Err" in result:
        return None, f"node returned Err: {str(result['Err'])[:120]}"
    ok = result.get("Ok")
    if isinstance(ok, dict):
        return ok, None
    if ok is not None:
        return {"value": ok}, None
    return None, "no Ok payload"


async def probe_tip(
    client: httpx.AsyncClient,
    insecure_client: httpx.AsyncClient,
    resolved: Resolved,
) -> NodeProbe:
    """The five-second probe. Everything the board needs, in one request.

    The TLS retry deserves its comment: a node with a self-signed or expired
    certificate is *up and serving the chain*, and reporting it as down would be
    wrong. So a verification failure is retried once without verification, and if
    that succeeds the node is reported reachable with an explicit certificate
    complaint rather than as an outage.
    """
    loop = asyncio.get_running_loop()
    start = loop.time()
    tls_warning: str | None = None

    try:
        response = await _post(client, resolved, _rpc("get_tip", []))
    except Exception as exc:  # noqa: BLE001 - every failure mode becomes a Reason
        reason, message = classify_http_error(exc)
        if reason is not Reason.TLS:
            return NodeProbe(ok=False, reason=reason, error=message)
        try:
            start = loop.time()
            response = await _post(insecure_client, resolved, _rpc("get_tip", []))
            tls_warning = "certificate not valid"
        except Exception as retry_exc:  # noqa: BLE001
            reason, message = classify_http_error(retry_exc)
            return NodeProbe(ok=False, reason=reason, error=message)

    latency_ms = int((loop.time() - start) * 1000)

    if response.status_code == 401:
        # By far the most common non-success. The node is running and in
        # consensus; its operator simply has not made the foreign API public.
        # Rendering this as offline is factually wrong.
        return NodeProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=401,
            reason=Reason.API_RESTRICTED,
            error="public API requires credentials",
        )
    if response.status_code == 429:
        return NodeProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=429,
            reason=Reason.RATE_LIMITED,
            error="rate limited by the endpoint",
        )
    if response.status_code >= 400:
        return NodeProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=response.status_code,
            reason=Reason.BAD_RESPONSE,
            error=f"HTTP {response.status_code}",
        )

    try:
        body = response.json()
    except ValueError:
        return NodeProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=response.status_code,
            reason=Reason.BAD_RESPONSE,
            error="response was not JSON",
        )

    payload, error = _unwrap(body)
    if payload is None:
        return NodeProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=response.status_code,
            reason=Reason.BAD_RESPONSE,
            error=error,
        )

    height = payload.get("height")
    if not isinstance(height, int):
        return NodeProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=response.status_code,
            reason=Reason.BAD_RESPONSE,
            error="no height in tip",
        )

    difficulty: Difficulty | None = None
    raw_difficulty = payload.get("total_difficulty")
    if isinstance(raw_difficulty, dict):
        difficulty = Difficulty.model_validate(raw_difficulty)
    elif isinstance(raw_difficulty, int):
        # Not seen on mainnet, but a modified or much older node could still
        # serve the Grin-shaped scalar. Accept it rather than fail the probe.
        difficulty = Difficulty(cuckatoo=raw_difficulty)

    return NodeProbe(
        ok=True,
        latency_ms=latency_ms,
        height=height,
        tip_hash=_as_str(payload.get("last_block_pushed")),
        prev_hash=_as_str(payload.get("prev_block_to_last")),
        difficulty=difficulty,
        http_status=response.status_code,
        reason=Reason.TLS if tls_warning else Reason.OK,
        error=tls_warning,
    )


async def probe_version(
    client: httpx.AsyncClient, resolved: Resolved
) -> VersionProbe:
    """`get_version`, on a five-minute cadence. 133 bytes, and it only changes
    when the node restarts.

    Worth collecting because version spread is a security metric on a
    MimbleWimble chain, not trivia: after Litecoin's 2026 MWEB peg-out exploit
    roughly 70% of nodes were still unpatched weeks later.
    """
    try:
        response = await _post(client, resolved, _rpc("get_version", []))
        if response.status_code >= 400:
            return VersionProbe(ok=False, error=f"HTTP {response.status_code}")
        payload, error = _unwrap(response.json())
        if payload is None:
            return VersionProbe(ok=False, error=error)
        header_version = payload.get("block_header_version")
        return VersionProbe(
            ok=True,
            node_version=_as_str(payload.get("node_version")),
            block_header_version=(
                header_version if isinstance(header_version, int) else None
            ),
        )
    except Exception as exc:  # noqa: BLE001
        _, message = classify_http_error(exc)
        return VersionProbe(ok=False, error=message)


async def probe_header(
    client: httpx.AsyncClient, resolved: Resolved, height: int
) -> HeaderProbe:
    """`get_header` at one height: hash, parent, timestamp, algorithm, difficulty.

    This is the difference between "this node is answering" and "the chain is
    moving". A node can serve `get_tip` perfectly while the whole network has
    stalled, and height alone cannot tell you which. Kept per height, the same
    header is also how a replaced block — a reorg — becomes visible from outside:
    the parent a new header names either is, or is not, the block that was seen
    at that height before.

    About 1.5 KB with the proof. Fetched once per new block, not once per sweep.
    """
    try:
        response = await _post(
            client, resolved, _rpc("get_header", [height, None, None])
        )
        if response.status_code >= 400:
            return HeaderProbe(ok=False, error=f"HTTP {response.status_code}")
        payload, error = _unwrap(response.json())
        if payload is None:
            return HeaderProbe(ok=False, error=error)
        raw_time = payload.get("timestamp")
        block_hash = payload.get("hash")
        previous = payload.get("previous")
        found = payload.get("height")
        if not isinstance(raw_time, str):
            return HeaderProbe(ok=False, error="no timestamp in header")
        if not (isinstance(block_hash, str) and isinstance(previous, str)):
            return HeaderProbe(ok=False, error="no hash in header")
        if found != height:
            # A node answering for a different height than was asked is not a header
            # this service can file under the height it asked about.
            return HeaderProbe(ok=False, error=f"asked for {height}, got {found}")
        raw_difficulty = payload.get("total_difficulty")
        return HeaderProbe(
            ok=True,
            header=BlockHeader(
                height=height,
                hash=block_hash,
                previous=previous,
                mined_at=datetime.fromisoformat(raw_time),
                proof=_as_str(payload.get("proof")),
                total_difficulty=(
                    Difficulty.model_validate(raw_difficulty)
                    if isinstance(raw_difficulty, dict)
                    else Difficulty()
                ),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        _, message = classify_http_error(exc)
        return HeaderProbe(ok=False, error=message)


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None
