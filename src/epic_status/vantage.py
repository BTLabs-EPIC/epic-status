"""A second vantage point: remote probers that push their measurements to this one.

The board has always said its latency and reachability are measured from one place, and
that a failure seen from here proves nothing about the host. This is how that stops being
only a disclaimer. Another machine runs `epic-status push`, probes the same targets with
the same code, and posts signed batches to `POST /api/v1/probes` here. The hub stores them
under the remote's `prober_id` — the column every check has carried since the first
schema for exactly this — and shows them beside each verdict.

**Evidence, not a vote.** Remote checks never change a row's state, its failure count or
its uptime. Those stay this prober's own. Averaging vantage points into one verdict would
hide the only thing a second vantage point is for: "down from London, fine from
Frankfurt" is the answer to "is it them or is it us".

**Authentication is a per-prober shared secret and an HMAC over the request.** Not a
bearer token: a token in a header is replayable by anyone who sees one request, and the
signature covers the prober id, a timestamp and the exact body. The hub refuses a
timestamp more than five minutes off, or not newer than the last one it accepted from that
prober, so a captured request cannot be replayed later.

**The pusher needs no configuration of targets.** It reads the list from the hub's own
public `status.json`, so the registry stays in one place. It applies the same address
checks the hub does before connecting anywhere, because a hub is just another server and
the list it serves must not be able to point the pusher at the pusher's own network.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from .db import Database
from .models import Kind, ProbeBatch, RemoteCheck
from .net import TargetRejected, build_client, resolve_endpoint
from .probes.epicbox import probe_relay
from .probes.node import probe_tip

log = logging.getLogger("epic_status.vantage")

HEADER_PROBER = "x-epic-prober"
HEADER_TIMESTAMP = "x-epic-timestamp"
HEADER_SIGNATURE = "x-epic-signature"

MAX_SKEW_S = 300
"""How far a request's timestamp may be from the hub's clock."""

MAX_CHECK_AGE_S = 600
"""A check older than this is not "recent" enough to show beside a live verdict."""

MAX_BODY_BYTES = 256 * 1024


def new_secret() -> str:
    return secrets.token_hex(32)


def parse_keys(raw: str) -> dict[str, str]:
    """`id:secret,id2:secret2` from the environment. Malformed entries are a startup
    failure: a hub that silently ignores a prober's key looks exactly like a broken
    prober."""
    keys: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in raw.split(","))):
        prober, sep, secret = item.partition(":")
        if not sep or not prober or len(secret) < 32:
            raise ValueError(
                "EPIC_STATUS_PROBER_KEYS entries must be id:secret with a secret of at"
                " least 32 characters (use `epic-status prober-key`)"
            )
        keys[prober] = secret
    return keys


def sign(secret: str, prober_id: str, timestamp: int, body: bytes) -> str:
    message = f"{prober_id}\n{timestamp}\n".encode() + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class Rejected(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Ingest:
    """Hub-side verification and storage of pushed batches."""

    db: Database
    keys: Mapping[str, str]
    _last_ts: dict[str, int] = field(default_factory=dict)

    def accept(
        self, headers: Mapping[str, str], body: bytes, *, now: float | None = None
    ) -> tuple[int, int]:
        """Verify and store one batch. Returns (accepted, skipped)."""
        now = time.time() if now is None else now
        if len(body) > MAX_BODY_BYTES:
            raise Rejected(413, "batch too large")
        prober = headers.get(HEADER_PROBER, "")
        secret = self.keys.get(prober)
        try:
            timestamp = int(headers.get(HEADER_TIMESTAMP, ""))
        except ValueError:
            raise Rejected(401, "bad signature") from None
        signature = headers.get(HEADER_SIGNATURE, "")
        # One message for every authentication failure, so the response does not say
        # which prober ids exist.
        if secret is None or not hmac.compare_digest(
            sign(secret, prober, timestamp, body), signature
        ):
            raise Rejected(401, "bad signature")
        if abs(now - timestamp) > MAX_SKEW_S:
            raise Rejected(401, "timestamp outside the allowed window; check the clock")
        if timestamp <= self._last_ts.get(prober, 0):
            raise Rejected(409, "replayed or out-of-order batch")

        try:
            batch = ProbeBatch.model_validate(json.loads(body))
        except (ValueError, TypeError) as exc:
            raise Rejected(400, f"malformed batch: {str(exc)[:200]}") from None
        if batch.prober_id != prober:
            raise Rejected(400, "prober_id in the body does not match the header")
        self._last_ts[prober] = timestamp

        accepted = skipped = 0
        oldest = datetime.fromtimestamp(now, UTC) - timedelta(seconds=MAX_CHECK_AGE_S)
        newest = datetime.fromtimestamp(now, UTC) + timedelta(seconds=60)
        for check in batch.checks:
            target = self.db.target_by_slug(check.kind, check.target)
            at = check.checked_at.astimezone(UTC)
            if target is None or target.id is None or not oldest <= at <= newest:
                skipped += 1
                continue
            self.db.record_remote_check(
                target_id=target.id,
                prober_id=prober,
                ok=check.ok,
                latency_ms=check.latency_ms,
                height=check.height,
                tip_hash=check.tip_hash,
                error=check.error,
                at=at,
            )
            accepted += 1
        log.info("prober %s pushed %d checks (%d skipped)", prober, accepted, skipped)
        return accepted, skipped


# ------------------------------------------------------------------------ pusher


@dataclass(frozen=True)
class _Target:
    slug: str
    kind: Kind
    endpoint: str


async def _hub_targets(client: httpx.AsyncClient, hub: str) -> list[_Target]:
    """Every node and relay the hub lists, across the chains it monitors."""
    health = (await client.get(f"{hub}/api/v1/health")).json()
    chains = list(health.get("chains", {})) or ["mainnet"]
    found: list[_Target] = []
    for chain in chains:
        response = await client.get(f"{hub}/api/v1/status.json", params={"chain": chain})
        if response.status_code != 200:
            continue
        doc = response.json()
        for row in doc.get("nodes", []):
            found.append(_Target(row["id"], Kind.NODE, row["endpoint"]))
        for row in doc.get("epicbox", []):
            found.append(_Target(row["id"], Kind.EPICBOX, row["endpoint"]))
    return found


async def _probe(
    target: _Target,
    client: httpx.AsyncClient,
    insecure: httpx.AsyncClient,
    ws_timeout: float,
) -> RemoteCheck:
    at = datetime.now(UTC)
    try:
        resolved = await resolve_endpoint(target.endpoint)
    except TargetRejected as exc:
        return RemoteCheck(
            target=target.slug,
            kind=target.kind,
            ok=False,
            error=_clip(exc.message),
            checked_at=at,
        )
    if target.kind is Kind.NODE:
        node = await probe_tip(client, insecure, resolved)
        return RemoteCheck(
            target=target.slug,
            kind=target.kind,
            ok=node.ok,
            latency_ms=node.latency_ms,
            height=node.height,
            tip_hash=node.tip_hash,
            error=_clip(node.error),
            checked_at=at,
        )
    relay = await probe_relay(resolved, timeout=ws_timeout)
    return RemoteCheck(
        target=target.slug,
        kind=target.kind,
        ok=relay.ok,
        latency_ms=relay.latency_ms,
        error=_clip(relay.error),
        checked_at=at,
    )


def _clip(error: str | None) -> str | None:
    return error[:300] if error else None


async def push_forever(
    *,
    hub: str,
    prober_id: str,
    secret: str,
    interval_s: float = 30.0,
    http_timeout_s: float = 4.0,
    ws_timeout_s: float = 8.0,
    once: bool = False,
) -> None:
    """Probe the hub's targets every `interval_s` and push the results.

    Thirty seconds by default, not five: a second vantage point exists to answer "is it
    them or us", which does not need the board's cadence, and every prober added is
    another stream of requests to every operator.
    """
    hub = hub.rstrip("/")
    async with (
        build_client(timeout=http_timeout_s) as client,
        build_client(timeout=http_timeout_s, verify=False) as insecure,
    ):
        targets: list[_Target] = []
        next_refresh = 0.0
        while True:
            started = time.monotonic()
            try:
                if started >= next_refresh or not targets:
                    targets = await _hub_targets(client, hub)
                    next_refresh = started + 300
                checks = await asyncio.gather(
                    *(_probe(t, client, insecure, ws_timeout_s) for t in targets)
                )
                batch = ProbeBatch(prober_id=prober_id, checks=list(checks))
                body = batch.model_dump_json().encode()
                timestamp = int(time.time())
                response = await client.post(
                    f"{hub}/api/v1/probes",
                    content=body,
                    headers={
                        "content-type": "application/json",
                        HEADER_PROBER: prober_id,
                        HEADER_TIMESTAMP: str(timestamp),
                        HEADER_SIGNATURE: sign(secret, prober_id, timestamp, body),
                    },
                )
                if response.status_code >= 400:
                    log.warning(
                        "hub refused batch: %s %s", response.status_code, response.text[:200]
                    )
                else:
                    log.info("pushed %d checks", len(checks))
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("push round failed")
            if once:
                return
            await asyncio.sleep(max(1.0, interval_s - (time.monotonic() - started)))
