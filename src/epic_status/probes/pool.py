"""Mining pool probes.

Pools are the one monitored kind with no protocol. A node speaks Epic's JSON-RPC
and a relay speaks the Epicbox WebSocket handshake, so one probe covers every host
of that kind forever. A pool exposes whatever its author wrote: different path,
different envelope, different units for the same number. So each pool is named in
the registry with an `adapter`, and adding a pool is a code change here plus a
registry entry — deliberately, because the alternative is sniffing a third party's
JSON shape at runtime and silently mis-reporting when it changes.

What is collected is deliberately thin: reachable or not, the pool's own view of
the chain height, how many miners and workers are connected, the fee, and the last
block it found. No hashrate. A pool's hashrate is a large number that moves
constantly, it says nothing about whether the pool is *working*, and putting it on
a status board invites reading it as a ranking.

`poolStats.currentHeight` is NOT the pool's view of the chain tip, and reading it
as one is a trap this code fell into first time round. It is identical to
`poolBlocks.lastFound` and to `latest[0].blockHeight` in both implementations,
every time it has been sampled: it is the height of the last block the pool FOUND.
Measured against a live tip of 3721265, epicmine (118 miners) reported 3721265 and
iniaku (9 miners) reported 3721246 — and iniaku was entirely healthy, having simply
not won a block for eighteen minutes.

So a pool's block height must never be compared to the chain tip: the expected gap
scales inversely with the pool's share, and doing so puts a red light on a pool for
the crime of being small. Neither API exposes its node's actual tip, so that check
is not available at any price. What is honest is the AGE of the last block found,
reported as a fact and not as a verdict.

A note on `epicmine`: its API host answers 200 with an endpoint index for *any*
path, including paths that do not exist. A status code is therefore not evidence
of anything there, and the parser requires the fields it actually needs before
calling a probe good.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from ..models import PoolProbe, Reason
from ..net import Resolved, classify_http_error, pinned_url


@dataclass(frozen=True)
class PoolAdapter:
    """How to read one pool's stats endpoint."""

    path: str
    wrapped: bool
    """True when the payload is `{"status": true, "data": {...}}` rather than the
    bare object. Checked rather than tolerated: silently accepting either shape
    would hide the day a pool changes its envelope."""
    fee_is_fraction: bool
    """The trap. One pool reports its 2% fee as the string `"0.02"` and the other
    reports its 2.5% fee as the number `2.5`. Without this flag one of them renders
    as 0.02% — a plausible-looking number that is wrong by a factor of a hundred,
    and exactly the sort of error nobody notices on a dashboard."""


ADAPTERS: dict[str, PoolAdapter] = {
    "iniaku": PoolAdapter(
        path="/api/pool/stats", wrapped=True, fee_is_fraction=True
    ),
    "epicmine": PoolAdapter(
        path="/pool/getstats", wrapped=False, fee_is_fraction=False
    ),
}


def _as_int(value: Any) -> int | None:
    # Accepts the string forms too: these APIs are not consistent about quoting
    # numbers, and a quoted integer is not a reason to call a pool broken.
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return None
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def parse_pool_stats(payload: Any, adapter: PoolAdapter) -> PoolProbe:
    """Turn one stats response into a probe result.

    Separate from the request so both shapes can be tested against real recorded
    payloads without a network call.
    """
    if not isinstance(payload, dict):
        return PoolProbe(
            ok=False, reason=Reason.BAD_RESPONSE, error="response was not an object"
        )

    if adapter.wrapped:
        if payload.get("status") is not True:
            return PoolProbe(
                ok=False,
                reason=Reason.BAD_RESPONSE,
                error="API reported status false",
            )
        root = payload.get("data")
    else:
        root = payload

    if not isinstance(root, dict):
        return PoolProbe(
            ok=False, reason=Reason.BAD_RESPONSE, error="no stats object in response"
        )

    stats = root.get("poolStats")
    if not isinstance(stats, dict):
        # This is the epicmine-answers-200-for-everything guard. A wrong path there
        # returns the endpoint index, which is a perfectly valid JSON object with
        # none of the fields that matter.
        return PoolProbe(
            ok=False,
            reason=Reason.BAD_RESPONSE,
            error="no poolStats in response (wrong path?)",
        )

    # Presence of currentHeight is the liveness assertion, not a value worth
    # publishing: it is `lastFound` under a misleading name. Requiring it is what
    # distinguishes a real stats payload from epicmine's catch-all endpoint index.
    found_height = _as_int(stats.get("currentHeight"))
    if found_height is None:
        return PoolProbe(
            ok=False,
            reason=Reason.BAD_RESPONSE,
            error="poolStats carried no currentHeight",
        )

    info = root.get("poolInfo") if isinstance(root.get("poolInfo"), dict) else {}
    blocks = root.get("poolBlocks") if isinstance(root.get("poolBlocks"), dict) else {}
    assert isinstance(info, dict) and isinstance(blocks, dict)

    fee = _as_float(info.get("fee"))
    if fee is not None and adapter.fee_is_fraction:
        fee *= 100.0

    # `lastFound` and `currentHeight` are the same number in both implementations;
    # prefer the honestly-named one and fall back to the other.
    last_height = _as_int(blocks.get("lastFound")) or found_height

    # The timestamp of that block, which is the part worth showing: "last block 18m
    # ago" is a fact a miner can act on, where a bare height is not.
    last_at: datetime | None = None
    latest = blocks.get("latest")
    if isinstance(latest, list) and latest and isinstance(latest[0], dict):
        stamp = _as_int(latest[0].get("time"))
        if stamp is not None and stamp > 0:
            try:
                last_at = datetime.fromtimestamp(stamp, UTC)
            except (OverflowError, OSError, ValueError):
                last_at = None

    return PoolProbe(
        ok=True,
        miners=_as_int(stats.get("activeUsers")),
        workers=_as_int(stats.get("activeWorkers")),
        fee_percent=fee,
        last_block_height=last_height,
        last_block_at=last_at,
    )


async def probe_pool(
    client: httpx.AsyncClient,
    resolved: Resolved,
    adapter_name: str | None,
) -> PoolProbe:
    """One GET against the pool's stats endpoint.

    No TLS retry, unlike the node probe. A node with a bad certificate is still
    serving the chain and is worth reporting as reachable; a pool with a bad
    certificate is a pool whose miners cannot reach it either, so there is nothing
    to be generous about.
    """
    adapter = ADAPTERS.get(adapter_name or "")
    if adapter is None:
        # A registry entry naming an adapter that does not exist is a deployment
        # mistake, and it must not read as the pool being down.
        return PoolProbe(
            ok=False,
            reason=Reason.BAD_RESPONSE,
            error=f"no adapter named {adapter_name!r}",
        )

    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        response = await client.get(
            pinned_url(resolved, adapter.path),
            headers={"host": resolved.hostname, "accept": "application/json"},
            extensions={"sni_hostname": resolved.hostname},
        )
    except Exception as exc:  # noqa: BLE001 - every failure mode becomes a Reason
        reason, message = classify_http_error(exc)
        return PoolProbe(ok=False, reason=reason, error=message)

    latency_ms = int((loop.time() - start) * 1000)

    if response.status_code == 429:
        return PoolProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=429,
            reason=Reason.RATE_LIMITED,
            error="rate limited",
        )
    if response.status_code >= 400:
        return PoolProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=response.status_code,
            reason=Reason.BAD_RESPONSE,
            error=f"HTTP {response.status_code}",
        )

    try:
        payload = response.json()
    except ValueError:
        return PoolProbe(
            ok=False,
            latency_ms=latency_ms,
            http_status=response.status_code,
            reason=Reason.BAD_RESPONSE,
            error="response was not JSON",
        )

    probe = parse_pool_stats(payload, adapter)
    return probe.model_copy(
        update={"latency_ms": latency_ms, "http_status": response.status_code}
    )
