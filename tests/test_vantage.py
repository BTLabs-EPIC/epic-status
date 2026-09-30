"""Remote probers: signed pushes accepted, everything else refused, and the board's own
verdict left untouched by what they report."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from epic_status.api import create_app
from epic_status.db import Database
from epic_status.models import Kind, Source, Target
from epic_status.vantage import (
    HEADER_PROBER,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    Ingest,
    Rejected,
    parse_keys,
    sign,
)

from test_app import client_for, make_settings

SECRET = "s" * 64


def _target(db: Database) -> int:
    return db.insert_target(
        Target(
            kind=Kind.NODE,
            slug="node.example.org",
            endpoint="https://node.example.org",
            display_host="node.example.org",
            source=Source.SEED,
        )
    )


def _batch(ok: bool = False, at: datetime | None = None) -> bytes:
    return json.dumps(
        {
            "prober_id": "fra",
            "checks": [
                {
                    "target": "node.example.org",
                    "kind": "node",
                    "ok": ok,
                    "latency_ms": 42,
                    "error": None if ok else "timed out",
                    "checked_at": (at or datetime.now(UTC)).isoformat(),
                }
            ],
        }
    ).encode()


def _headers(body: bytes, ts: int | None = None, secret: str = SECRET) -> dict[str, str]:
    ts = int(time.time()) if ts is None else ts
    return {
        HEADER_PROBER: "fra",
        HEADER_TIMESTAMP: str(ts),
        HEADER_SIGNATURE: sign(secret, "fra", ts, body),
    }


def test_a_signed_batch_is_stored_under_the_remote_id(db: Database) -> None:
    target_id = _target(db)
    ingest = Ingest(db, {"fra": SECRET})
    body = _batch(ok=False)

    assert ingest.accept(_headers(body), body) == (1, 0)

    rows = db.vantages(target_id, datetime.now(UTC) - timedelta(minutes=5))
    assert [(r["prober_id"], r["ok"]) for r in rows] == [("fra", 0)]


def test_a_remote_failure_does_not_touch_the_local_verdict(db: Database) -> None:
    """Evidence, not a vote: failure count, last error and uptime stay local."""
    target_id = _target(db)
    body = _batch(ok=False)
    Ingest(db, {"fra": SECRET}).accept(_headers(body), body)

    row = db.conn.execute(
        "SELECT consecutive_failures, last_error FROM targets WHERE id = ?", (target_id,)
    ).fetchone()
    assert (row["consecutive_failures"], row["last_error"]) == (0, None)
    assert db.uptime(target_id, timedelta(hours=1)) is None
    assert db.history(target_id, 10) == []


@pytest.mark.parametrize(
    "tamper",
    [
        lambda h, b: ({**h, HEADER_SIGNATURE: "0" * 64}, b),
        lambda h, b: (h, b.replace(b"timed out", b"all good!")),
        lambda h, b: ({**h, HEADER_PROBER: "someone"}, b),
    ],
)
def test_tampered_requests_are_refused(db: Database, tamper) -> None:  # type: ignore[no-untyped-def]
    _target(db)
    body = _batch()
    headers, body = tamper(_headers(body), body)
    with pytest.raises(Rejected) as info:
        Ingest(db, {"fra": SECRET}).accept(headers, body)
    assert info.value.status == 401


def test_replay_and_clock_skew_are_refused(db: Database) -> None:
    _target(db)
    ingest = Ingest(db, {"fra": SECRET})
    body = _batch()
    headers = _headers(body)
    ingest.accept(headers, body)
    with pytest.raises(Rejected) as replay:
        ingest.accept(headers, body)
    assert replay.value.status == 409

    old = _headers(body, ts=int(time.time()) - 3600)
    with pytest.raises(Rejected):
        Ingest(db, {"fra": SECRET}).accept(old, body)


def test_unknown_targets_and_stale_checks_are_skipped(db: Database) -> None:
    _target(db)
    stale = _batch(at=datetime.now(UTC) - timedelta(hours=1))
    assert Ingest(db, {"fra": SECRET}).accept(_headers(stale), stale) == (0, 1)


def test_keys_must_be_long_enough() -> None:
    assert parse_keys(f"fra:{SECRET}, lon:{SECRET}") == {"fra": SECRET, "lon": SECRET}
    with pytest.raises(ValueError):
        parse_keys("fra:short")


async def test_the_route_exists_only_with_keys(tmp_path: Path) -> None:
    async with client_for(create_app(make_settings(tmp_path))) as client:
        assert (await client.post("/api/v1/probes", content=b"{}")).status_code in (404, 405)

    app = create_app(make_settings(tmp_path / "b", prober_keys=f"fra:{SECRET}"))
    _target(app.state.service.db)
    body = _batch()
    async with client_for(app) as client:
        response = await client.post("/api/v1/probes", content=body, headers=_headers(body))
        assert response.status_code == 200
        assert response.json()["accepted"] == 1



async def test_push_round_probes_the_hubs_targets_and_signs_the_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One round of the pusher against a mocked hub and node, verified by the real
    `sign` — the two ends of the protocol agree."""
    import httpx
    import respx

    from epic_status import vantage
    from epic_status.net import Resolved

    async def fake_resolve(endpoint: str, **_: object) -> Resolved:
        return Resolved(
            hostname="node.example.org", port=443, addresses=("203.0.113.7",), scheme="https"
        )

    monkeypatch.setattr(vantage, "resolve_endpoint", fake_resolve)
    hub = "https://hub.example.org"
    pushed: list[httpx.Request] = []

    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{hub}/api/v1/health").respond(json={"chains": {"mainnet": {}}})
        mock.get(f"{hub}/api/v1/status.json").respond(
            json={
                "nodes": [{"id": "node.example.org", "endpoint": "https://node.example.org"}],
                "epicbox": [],
            }
        )
        mock.post("https://203.0.113.7:443/v2/foreign").respond(
            json={"jsonrpc": "2.0", "id": 1, "result": {"Ok": {"height": 7, "last_block_pushed": "ab"}}}
        )

        def capture(request: httpx.Request) -> httpx.Response:
            pushed.append(request)
            return httpx.Response(200, json={"ok": True})

        mock.post(f"{hub}/api/v1/probes").mock(side_effect=capture)
        await vantage.push_forever(hub=hub, prober_id="fra", secret=SECRET, once=True)

    request = pushed[0]
    body = request.content
    ts = int(request.headers[HEADER_TIMESTAMP])
    assert request.headers[HEADER_SIGNATURE] == sign(SECRET, "fra", ts, body)
    check = json.loads(body)["checks"][0]
    assert (check["target"], check["ok"], check["height"]) == ("node.example.org", True, 7)
