"""Shared fixtures.

Everything here is hermetic. No test in this suite may touch the network: the
module under test exists to stop this process connecting to addresses a stranger
chose, and a suite that reaches the internet cannot tell a working guard from a
firewall.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from epic_status.config import Settings
from epic_status.db import Database


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "status.db"


@pytest.fixture
def db(db_path: Path) -> Iterator[Database]:
    """A real SQLite file, not :memory:.

    WAL mode is a no-op on an in-memory database, and the schema asks for it, so
    an in-memory fixture would exercise a different engine configuration from
    production.
    """
    database = Database(db_path, prober_id="test")
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointed at a temp tree, with the private-target escape hatch open.

    `allow_private_targets` is the only way to probe a loopback listener, which is
    what the epicbox integration test needs. It is false everywhere else on
    purpose.
    """
    return Settings(
        db=tmp_path / "status.db",
        allow_private_targets=True,
        prober_id="test",
        site_url="http://127.0.0.1:13431",
    )
