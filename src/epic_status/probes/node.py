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

Peer counts and sync status are not on the foreign API. Epic 4.1.0-1 serves them
at `GET /v1/status` without auth, and a stock 4.x serves the same struct through
the owner API's `get_status`; see `probe_status`. A node that answers neither
still gets tip, difficulty, block hash, version and latency.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from ..models import (
    BlockHeader,
    Difficulty,
    HeaderProbe,
    NodeProbe,
    Reason,
    StatusProbe,
    StatusSource,
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


class BodyTooLarge(Exception):
    """The response grew past the cap and the read was abandoned."""


class EncodedBody(Exception):
    """The response is compressed even though identity was asked for. Refused rather
    than decoded: a small gzip body can inflate a thousandfold."""


@dataclass(frozen=True)
class CappedResponse:
    status_code: int
    headers: httpx.Headers
    body: bytes
    peer: str | None
    """The address the socket is actually connected to, when the transport reports
    it. None under a mocked transport."""


async def post_capped(
    client: httpx.AsyncClient,
    resolved: Resolved,
    payload: dict[str, Any],
    *,
    max_bytes: int,
) -> CappedResponse:
    """`_post`, for a host nobody vetted: the body is streamed and abandoned past
    `max_bytes`, and the connected peer address is reported back for re-checking.

    The poller can afford `client.post`, which buffers whatever arrives, because its
    targets are a committed list. A host a visitor typed could answer with a
    gigabyte, so the read is bounded here rather than trusted.
    """
    # An IPv6 literal must be bracketed in a Host header, and must not be in SNI.
    host_header = f"[{resolved.hostname}]" if ":" in resolved.hostname else resolved.hostname
    async with client.stream(
        "POST",
        pinned_url(resolved, _RPC_PATH),
        json=payload,
        headers={"host": host_header, "accept-encoding": "identity"},
        extensions={"sni_hostname": resolved.hostname},
    ) as response:
        peer: str | None = None
        stream = response.extensions.get("network_stream")
        if stream is not None:
            server_addr = stream.get_extra_info("server_addr")
            if isinstance(server_addr, tuple) and server_addr:
                peer = str(server_addr[0])
        encoding = response.headers.get("content-encoding", "identity").lower()
        if encoding not in ("", "identity"):
            raise EncodedBody(encoding)
        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise BodyTooLarge(declared)
        buf = bytearray()
        async for chunk in response.aiter_raw():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise BodyTooLarge(str(len(buf)))
        return CappedResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=bytes(buf),
            peer=peer,
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


async def probe_cors(
    client: httpx.AsyncClient, resolved: Resolved, origin: str
) -> bool | None:
    """Would a browser on another site be allowed to call this node?

    The CORS preflight a wallet running in a web page sends before its first
    `get_tip`: an OPTIONS naming POST and a JSON content type. A node that returns
    `access-control-allow-origin` on the POST but fails the preflight is unusable from
    a browser, so the POST's own headers are not the test — this is.

    None when the request itself failed: that is "unknown", not "no".
    """
    try:
        response = await client.request(
            "OPTIONS",
            pinned_url(resolved, _RPC_PATH),
            headers={
                "host": resolved.hostname,
                "origin": origin,
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type",
            },
            extensions={"sni_hostname": resolved.hostname},
        )
    except Exception:  # noqa: BLE001 - unknown, not a verdict
        return None
    if response.status_code >= 400:
        return False
    allowed_origin = response.headers.get("access-control-allow-origin", "")
    allowed_headers = response.headers.get("access-control-allow-headers", "").lower()
    origin_ok = allowed_origin in ("*", origin)
    headers_ok = "*" in allowed_headers or "content-type" in allowed_headers
    return origin_ok and headers_ok


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


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class _NoAnswer(Exception):
    """The host gave no HTTP answer at all. Not worth a second endpoint."""


async def _status_request(
    client: httpx.AsyncClient,
    insecure_client: httpx.AsyncClient,
    resolved: Resolved,
    source: StatusSource,
    timeout: float,
) -> httpx.Response:
    """One status request, with the same one-shot TLS retry as `probe_tip`: a
    self-signed node is serving, and its peers are as real as anyone's."""
    if source is StatusSource.V1:
        method, path, body = "GET", "/v1/status", None
    else:
        method, path, body = "POST", "/v2/owner", _rpc("get_status", [])
    for attempt in (client, insecure_client):
        try:
            return await attempt.request(
                method,
                pinned_url(resolved, path),
                json=body,
                headers={"host": resolved.hostname},
                extensions={"sni_hostname": resolved.hostname},
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001 - every failure mode becomes text
            reason, message = classify_http_error(exc)
            if reason is not Reason.TLS or attempt is insecure_client:
                raise _NoAnswer(message) from exc
    raise AssertionError("unreachable")  # pragma: no cover


def _parse_status(payload: Any, source: StatusSource) -> StatusProbe:
    if not isinstance(payload, dict):
        return StatusProbe(ok=False, error="status was not a JSON object")
    connections = _as_int(payload.get("connections"))
    if connections is None:
        return StatusProbe(ok=False, error="no connections in status")
    tip = payload.get("tip")
    tip = tip if isinstance(tip, dict) else {}
    return StatusProbe(
        ok=True,
        source=source,
        connections=connections,
        user_agent=_as_str(payload.get("user_agent")),
        protocol_version=_as_int(payload.get("protocol_version")),
        sync_status=_as_str(payload.get("sync_status")),
        height=_as_int(tip.get("height")),
        tip_hash=_as_str(tip.get("last_block_pushed")),
    )


async def probe_status(
    client: httpx.AsyncClient,
    insecure_client: httpx.AsyncClient,
    resolved: Resolved,
    *,
    timeout: float,
    skip_v1: bool = False,
) -> StatusProbe:
    """Peers, sync state and agent: `GET /v1/status`, else owner `get_status`.

    4.1.0-1 answers the first without auth. A stock 4.1.0 returns 401 there and
    serves the same struct, wrapped in `result.Ok`, from `POST /v2/owner`. The
    fallback is only tried when the first endpoint gave an HTTP answer: a host
    that timed out once will time out twice, and the poller's budget is per sweep.

    `skip_v1` is the poller remembering that a node only answers the fallback, so
    a steady state costs one request per node per sweep, not two.
    """
    errors: list[str] = []
    sources = [StatusSource.OWNER] if skip_v1 else [StatusSource.V1, StatusSource.OWNER]
    for source in sources:
        try:
            response = await _status_request(
                client, insecure_client, resolved, source, timeout
            )
        except _NoAnswer as exc:
            errors.append(f"{source.label}: {exc}")
            break
        if response.status_code == 429:
            # Rate limited: asking the same host again at once is the wrong answer.
            errors.append(f"{source.label}: rate limited (HTTP 429)")
            break
        if response.status_code >= 400:
            errors.append(f"{source.label}: HTTP {response.status_code}")
            continue
        try:
            body = response.json()
        except ValueError:
            errors.append(f"{source.label}: response was not JSON")
            continue
        if source is StatusSource.OWNER:
            body, error = _unwrap(body)
            if body is None:
                errors.append(f"{source.label}: {error}")
                continue
        result = _parse_status(body, source)
        if result.ok:
            return result
        errors.append(f"{source.label}: {result.error}")
    return StatusProbe(ok=False, error="; ".join(errors) or "no answer")
