"""The assembled application, through its HTTP interface.

Everything else in the suite calls modules directly. This file builds the real FastAPI
app and drives it over ASGI, because route registration is where a split module or a
renamed helper breaks without any unit test noticing.

The lifespan is deliberately not entered: it starts the poller, which would reach the
network. Snapshots are placed on the poller by hand instead, which is exactly what a
completed sweep does.

`httpx.ASGITransport` rather than Starlette's `TestClient`, which now raises a
deprecation warning — an error under this suite's `filterwarnings`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from epic_status.admin import hash_password
from epic_status.api import Service, create_app
from epic_status.config import Settings
from epic_status.models import (
    Chain,
    Kind,
    NetworkSummary,
    Snapshot,
    Source,
    State,
    Target,
    TargetStatus,
)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "db": tmp_path / "status.db",
        "prober_id": "test",
        "site_url": "https://status.example.org",
        "admin_cookie_secure": False,
        # An empty registry: nothing here should depend on the committed seeds.
        "targets_file": tmp_path / "targets.toml",
    }
    values.update(overrides)
    return Settings(**values)


def node_target(service: Service, slug: str = "node.example.org") -> Target:
    target = Target(
        kind=Kind.NODE,
        slug=slug,
        endpoint=f"https://{slug}:3413",
        display_host=f"{slug}:3413",
        operator="Example",
        source=Source.SEED,
    )
    target.id = service.db.insert_target(target)
    return target


def install_snapshot(
    service: Service, *, state: State = State.HEALTHY, chain: Chain = Chain.MAINNET
) -> TargetStatus:
    """A one-node snapshot whose target exists in the database."""
    status = TargetStatus(
        target=node_target(service),
        state=state,
        latency_ms=80,
        height=100,
        tip_lag=0,
        uptime_30d=0.9981,
        last_checked_at=datetime.now(UTC),
    )
    service.poller.snapshots[chain] = Snapshot(
        generated_at=datetime.now(UTC),
        prober_id="test",
        network=NetworkSummary(
            chain=chain, tip_height=100, nodes_total=1, nodes_healthy=1
        ),
        nodes=[status],
    )
    return status


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
    application = create_app(make_settings(tmp_path))
    install_snapshot(application.state.service)
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(app) as c:
        yield c


async def test_public_pages_render(client: httpx.AsyncClient) -> None:
    for path in ("/", "/history", "/api", "/add"):
        response = await client.get(path)
        assert response.status_code == 200, path
        assert "content-security-policy" in response.headers


async def test_status_json_serves_the_snapshot(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/status.json")
    assert response.status_code == 200
    assert response.json()["nodes"][0]["id"] == "node.example.org"
    assert response.headers["access-control-allow-origin"] == "*"


async def test_admin_absent_without_a_password(client: httpx.AsyncClient) -> None:
    """No hash, no surface: /admin is a 404, not a login form."""
    assert (await client.get("/admin")).status_code == 404


async def test_admin_login_round_trip(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, admin_password_hash=hash_password("pw")))
    async with client_for(app) as client:
        assert (await client.get("/admin")).status_code == 200
        bad = await client.post("/admin/login", data={"user": "admin", "password": "no"})
        assert bad.status_code == 401
        good = await client.post(
            "/admin/login", data={"user": "admin", "password": "pw"}
        )
        assert good.status_code == 303
        assert "epic_status_admin" in good.cookies
