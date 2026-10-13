"""Schema migration.

`apply_schema` is `CREATE TABLE IF NOT EXISTS`, which cannot widen a CHECK
constraint or add a column to a table that already exists. That was fine while the
kind set never changed. The day it did, every test passed — because tests build a
fresh database — while the deployed file still refused `kind='pool'` and raised
IntegrityError from inside a write. These tests build the *old* schema explicitly so
that the thing under test is the upgrade path rather than the current schema.

What the rebuild must never do is lose history. `checks` and `rollup_hourly` cannot
be reconstructed from anything — no server reports when it was last up — and they
reference `targets(id)`, so the row identifiers have to survive byte for byte.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from epic_status.db import (
    SCHEMA,
    Database,
    _column_names,
    _column_order,
    _create_table_sql,
    _sql_in,
)
from epic_status.models import Kind, Source

# The schema as it shipped before pools existed: two kinds, no adapter column.
OLD_SCHEMA = """
CREATE TABLE targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT    NOT NULL CHECK (kind IN ('node','epicbox')),
    slug          TEXT    NOT NULL,
    endpoint      TEXT    NOT NULL,
    display_host  TEXT    NOT NULL,
    p2p           TEXT,
    operator      TEXT,
    label         TEXT,
    notes         TEXT,
    ours          INTEGER NOT NULL DEFAULT 0,
    source        TEXT    NOT NULL CHECK (source IN ('seed','submitted')),
    enabled       INTEGER NOT NULL DEFAULT 1,
    last_ok_at    TEXT,
    last_checked_at TEXT,
    last_error    TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    node_version      TEXT,
    protocol_version  TEXT,
    cert_expires_at   TEXT,
    geo_json          TEXT,
    geo_looked_up_at  TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (kind, slug)
);
CREATE TABLE checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    prober_id   TEXT    NOT NULL,
    checked_at  TEXT    NOT NULL,
    ok          INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    latency_ms  INTEGER,
    height      INTEGER,
    tip_hash    TEXT,
    error       TEXT
);
CREATE TABLE rollup_hourly (
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    prober_id   TEXT    NOT NULL,
    hour        TEXT    NOT NULL,
    checks      INTEGER NOT NULL,
    ok_checks   INTEGER NOT NULL,
    p50_latency_ms INTEGER,
    PRIMARY KEY (target_id, prober_id, hour)
);
CREATE TABLE submissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL CHECK (kind IN ('node','epicbox')),
    host        TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL,
    operator    TEXT,
    submitted_at TEXT   NOT NULL,
    submitter_hash TEXT NOT NULL,
    probes_passed INTEGER NOT NULL DEFAULT 0,
    probes_attempted INTEGER NOT NULL DEFAULT 0,
    next_probe_at TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','accepted','rejected')),
    last_error  TEXT,
    UNIQUE (kind, host)
);
"""


@pytest.fixture
def legacy_db(tmp_path: Path) -> Path:
    """A pre-pool database with history in it, at deliberately non-contiguous ids.

    Gaps matter: a rebuild that lets AUTOINCREMENT reassign would renumber these and
    the checks would still be there, still counted, and attached to the wrong host.
    That is worse than losing them, because nothing would look broken.
    """
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    for target_id, kind, slug in (
        (7, "node", "node.example.org"),
        (19, "epicbox", "epicbox.example.org"),
    ):
        conn.execute(
            "INSERT INTO targets (id, kind, slug, endpoint, display_host, source,"
            " last_ok_at, consecutive_failures, node_version)"
            " VALUES (?,?,?,?,?,'seed','2026-09-01T00:00:00Z',0,'4.0.3')",
            (target_id, kind, slug, f"https://{slug}", slug),
        )
        for i in range(25):
            conn.execute(
                "INSERT INTO checks (target_id, prober_id, checked_at, ok, state,"
                " reason, latency_ms) VALUES (?,'test',?,1,'healthy','ok',42)",
                (target_id, f"2026-09-01T00:{i:02d}:00Z"),
            )
        conn.execute(
            "INSERT INTO rollup_hourly (target_id, prober_id, hour, checks, ok_checks)"
            " VALUES (?,'test','2026-09-01T00',25,25)",
            (target_id,),
        )
    conn.execute(
        "INSERT INTO submissions (kind, host, endpoint, submitted_at, submitter_hash)"
        " VALUES ('node','s.example.org','https://s.example.org','2026-09-01T00:00:00Z','h')"
    )
    conn.commit()
    conn.close()
    return path


def _snapshot(path: Path) -> dict[str, object]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return {
            "targets": [
                (r["id"], r["kind"], r["slug"], r["node_version"])
                for r in conn.execute("SELECT * FROM targets ORDER BY id")
            ],
            "checks": [
                (r["target_id"], r["checked_at"], r["ok"], r["latency_ms"])
                for r in conn.execute(
                    "SELECT * FROM checks ORDER BY target_id, checked_at"
                )
            ],
            "rollups": [
                (r["target_id"], r["hour"], r["checks"], r["ok_checks"])
                for r in conn.execute("SELECT * FROM rollup_hourly ORDER BY target_id")
            ],
            "submissions": [
                (r["kind"], r["host"]) for r in conn.execute("SELECT * FROM submissions")
            ],
            "fk_violations": conn.execute("PRAGMA foreign_key_check").fetchall(),
        }
    finally:
        conn.close()


def test_legacy_database_rejects_a_pool_before_migration(legacy_db: Path) -> None:
    """The bug being fixed, demonstrated. Without this the rest proves nothing."""
    conn = sqlite3.connect(legacy_db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO targets (kind, slug, endpoint, display_host, source)"
                " VALUES ('pool','p.example','https://p.example','p.example','seed')"
            )
    finally:
        conn.close()


def test_migration_preserves_all_history(legacy_db: Path) -> None:
    before = _snapshot(legacy_db)
    Database(legacy_db, prober_id="test").close()
    after = _snapshot(legacy_db)

    assert after["checks"] == before["checks"]
    assert after["rollups"] == before["rollups"]
    assert after["submissions"] == before["submissions"]
    assert not after["fk_violations"]


def test_migration_preserves_target_ids_exactly(legacy_db: Path) -> None:
    """The load-bearing assertion. checks.target_id and rollup_hourly.target_id are
    foreign keys into these values, and the ids here are non-contiguous on purpose."""
    before = _snapshot(legacy_db)
    Database(legacy_db, prober_id="test").close()
    after = _snapshot(legacy_db)

    assert after["targets"] == before["targets"]
    assert [row[0] for row in after["targets"]] == [7, 19]


def test_migration_admits_every_kind(legacy_db: Path) -> None:
    db = Database(legacy_db, prober_id="test")
    try:
        for kind in Kind:
            db.conn.execute(
                "INSERT INTO targets (kind, slug, endpoint, display_host, source,"
                " adapter) VALUES (?,?,?,?,?,?)",
                (kind.value, f"x.{kind.value}", "https://x", "x", Source.SEED.value,
                 "iniaku" if kind is Kind.POOL else None),
            )
        db.conn.execute(
            "INSERT INTO submissions (kind, host, endpoint, submitted_at,"
            " submitter_hash) VALUES ('pool','p2.example','https://p2.example','t','h')"
        )
    finally:
        db.close()


def test_migration_adds_the_adapter_column(legacy_db: Path) -> None:
    Database(legacy_db, prober_id="test").close()
    conn = sqlite3.connect(legacy_db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
        assert "adapter" in cols
    finally:
        conn.close()


def test_migration_is_idempotent(legacy_db: Path) -> None:
    Database(legacy_db, prober_id="test").close()
    once = _snapshot(legacy_db)
    for _ in range(3):
        Database(legacy_db, prober_id="test").close()
    assert _snapshot(legacy_db) == once


def test_a_fresh_database_needs_no_rebuild(tmp_path: Path) -> None:
    """A new file is already current, so the rebuild must not run on every boot —
    rewriting two tables at each restart is not free and not risk-free."""
    db = Database(tmp_path / "fresh.db", prober_id="test")
    try:
        assert not db._needs_rebuild("targets")
        assert not db._needs_rebuild("submissions")
    finally:
        db.close()


def test_needs_rebuild_is_false_for_a_table_that_does_not_exist(tmp_path: Path) -> None:
    db = Database(tmp_path / "fresh.db", prober_id="test")
    try:
        assert not db._needs_rebuild("no_such_table")
    finally:
        db.close()


# ------------------------------------------------------------------- the helpers


def test_check_constraints_are_generated_from_the_enums() -> None:
    """The reason this migration was needed at all was three hand-written copies of
    the kind set. There is now one, and these assertions are what keep it that way."""
    assert _sql_in(Kind) == "'node','epicbox','pool'"
    assert _sql_in(Source) == "'seed','submitted'"
    for kind in Kind:
        assert f"'{kind.value}'" in SCHEMA
    # Two kind constraints, targets and submissions, both from the same source.
    assert SCHEMA.count(f"CHECK (kind IN ({_sql_in(Kind)}))") == 2


def test_create_table_sql_extracts_one_statement() -> None:
    sql = _create_table_sql("targets")
    assert sql.startswith("CREATE TABLE IF NOT EXISTS targets (")
    assert sql.rstrip().endswith(");")
    assert "CREATE TABLE IF NOT EXISTS checks" not in sql


def test_column_parsing_finds_columns_and_not_constraints() -> None:
    cols = _column_order(_create_table_sql("targets"))
    # `chain` sits second because it is declared next to `kind`, which is where a
    # reader looks for what a row *is*. The position is incidental; that the parser
    # finds it as a column is not — a column whose declaration carries an inline CHECK
    # is exactly the shape `_column_order` has to keep getting right.
    assert cols[:4] == ["id", "kind", "chain", "slug"]
    assert "adapter" in cols
    # Table-level constraints and comments are not columns.
    assert not {"UNIQUE", "CHECK", "PRIMARY", "--"} & set(cols)
    assert len(cols) == len(set(cols))
    assert _column_names(_create_table_sql("targets")) == set(cols)


def test_parsed_columns_match_what_sqlite_creates(tmp_path: Path) -> None:
    """Ties the DDL parser to SQLite's own view of the same statement, so a future
    schema style the parser mishandles fails here rather than during a rebuild."""
    db = Database(tmp_path / "fresh.db", prober_id="test")
    try:
        for table in ("targets", "submissions", "checks", "rollup_hourly"):
            live = {r[1] for r in db.conn.execute(f"PRAGMA table_info({table})")}
            assert _column_names(_create_table_sql(table)) == live, table
    finally:
        db.close()


# ------------------------------------------------- the incident log, before dedupe

# `events` as it shipped before occurrences were folded: one row per occurrence.
OLD_EVENTS = """
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chain       TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    target_id   INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    subject     TEXT    NOT NULL,
    detail      TEXT,
    depth       INTEGER,
    prober_id   TEXT    NOT NULL,
    started_at  TEXT    NOT NULL,
    ended_at    TEXT
);
"""

#: (id, chain, kind, severity, target_id, subject, depth, started_at, ended_at).
#: Seven outages of one pool in a morning, the shape of the live log that prompted this;
#: a reorg run on floonet with one deeper reorg in it; one outage a day later than the
#: first, which must start a new entry; and an open outage, which must stay open.
LEGACY_EVENTS = [
    (253, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T07:08:26Z", "2026-10-13T07:11:46Z"),
    (254, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T07:13:56Z", "2026-10-13T07:22:52Z"),
    (255, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T07:25:57Z", "2026-10-13T07:27:12Z"),
    (256, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T11:20:31Z", "2026-10-13T11:21:46Z"),
    (257, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T11:48:31Z", "2026-10-13T11:50:16Z"),
    (258, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T12:05:31Z", "2026-10-13T12:08:57Z"),
    (259, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-13T12:13:32Z", "2026-10-13T12:15:27Z"),
    (260, "mainnet", "down", "warn", 7, "pool.example.org", None, "2026-10-14T07:08:27Z", None),
    (100, "floonet", "reorg", "info", None, "Floonet chain", 1, "2026-10-05T21:58:09Z", "2026-10-05T21:58:09Z"),
    (101, "floonet", "reorg", "warn", None, "Floonet chain", 3, "2026-10-06T08:00:00Z", "2026-10-06T08:00:00Z"),
    (102, "floonet", "reorg", "info", None, "Floonet chain", 1, "2026-10-06T21:58:09Z", "2026-10-06T21:58:09Z"),
    (103, "floonet", "reorg", "info", None, "Floonet chain", 1, "2026-10-06T21:58:10Z", "2026-10-06T21:58:10Z"),
    (104, "mainnet", "reorg", "info", None, "Mainnet chain", 1, "2026-10-06T08:00:00Z", "2026-10-06T08:00:00Z"),
]


@pytest.fixture
def legacy_events_db(tmp_path: Path) -> Path:
    path = tmp_path / "legacy-events.db"
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA + OLD_EVENTS)
    conn.execute(
        "INSERT INTO targets (id, kind, slug, endpoint, display_host, source)"
        " VALUES (7,'node','pool.example.org','https://pool.example.org','pool.example.org','seed')"
    )
    for row in LEGACY_EVENTS:
        conn.execute(
            "INSERT INTO events (id, chain, kind, severity, target_id, subject, depth,"
            " prober_id, started_at, ended_at, detail) VALUES (?,?,?,?,?,?,?,'test',?,?,?)",
            (*row, f"detail {row[0]}"),
        )
    conn.commit()
    conn.close()
    return path


def _events(path: Path) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return conn.execute(
            "SELECT id, kind, severity, occurrences, started_at, last_started_at, ended_at,"
            " active_s, depth, detail FROM events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def _occurrences(path: Path) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return conn.execute(
            "SELECT event_id, started_at, ended_at, detail, severity, depth"
            " FROM event_occurrences ORDER BY started_at, id"
        ).fetchall()
    finally:
        conn.close()


def test_compaction_folds_a_day_of_repeats_into_the_earliest_row(
    legacy_events_db: Path,
) -> None:
    Database(legacy_events_db, prober_id="test").close()
    rows = {r[0]: r for r in _events(legacy_events_db)}

    assert sorted(rows) == [100, 103, 104, 253, 260]
    pool = rows[253]
    assert pool[3] == 7
    assert pool[4] == "2026-10-13T07:08:26Z"
    assert pool[5] == "2026-10-13T12:13:32Z"
    assert pool[6] == "2026-10-13T12:15:27Z"
    # 200 + 536 + 75 + 75 + 105 + 206 + 115 seconds.
    assert pool[7] == 1312
    assert pool[9] == "detail 259"
    # A day after the first outage is a new entry, and an open one stays open.
    assert rows[260][3] == 1 and rows[260][6] is None


def test_compaction_takes_the_worst_severity_and_the_deepest_reorg(
    legacy_events_db: Path,
) -> None:
    Database(legacy_events_db, prober_id="test").close()
    rows = {r[0]: r for r in _events(legacy_events_db)}

    # 100 absorbs 101 (the warn, depth 3) and 102, which is exactly 24 h after 100 —
    # the window is inclusive, as it is in `open_event`. 103, one second past it,
    # starts the next entry, and the escalation does not leak into it.
    assert rows[100][1:4] == ("reorg", "warn", 3)
    assert rows[100][8] == 3
    assert rows[103][1:4] == ("reorg", "info", 1)
    # Chains never fold together.
    assert rows[104][3] == 1


def test_compaction_keeps_every_original_timestamp(legacy_events_db: Path) -> None:
    Database(legacy_events_db, prober_id="test").close()
    occurrences = _occurrences(legacy_events_db)

    original = sorted((r[7], r[8], f"detail {r[0]}", r[3], r[6]) for r in LEGACY_EVENTS)
    assert sorted(o[1:] for o in occurrences) == original
    surviving = {r[0] for r in _events(legacy_events_db)}
    assert {o[0] for o in occurrences} == surviving


def test_compaction_is_idempotent(legacy_events_db: Path) -> None:
    db = Database(legacy_events_db, prober_id="test")
    try:
        assert db._compact_events() == 0
    finally:
        db.close()
    events, occurrences = _events(legacy_events_db), _occurrences(legacy_events_db)
    Database(legacy_events_db, prober_id="test").close()
    assert _events(legacy_events_db) == events
    assert _occurrences(legacy_events_db) == occurrences


def test_compaction_reports_what_it_folded(
    legacy_events_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Database._compact_events
    monkeypatch.setattr(Database, "_compact_events", lambda self: 0)
    db = Database(legacy_events_db, prober_id="test")
    try:
        assert len(_events(legacy_events_db)) == 13
        assert real(db) == 13 - 5
        assert real(db) == 0
    finally:
        db.close()


def test_a_compacted_log_resumes_and_keeps_folding(legacy_events_db: Path) -> None:
    from datetime import UTC, datetime

    from epic_status.models import Chain, Event, EventKind, Severity

    db = Database(legacy_events_db, prober_id="test")
    try:
        ongoing = db.ongoing_events()
        assert [(e.id, t) for e, t in ongoing] == [(260, 7)]
        db.close_event(260, datetime(2026, 10, 14, 7, 10, 27, tzinfo=UTC))
        reopened = db.open_event(
            Event(
                chain=Chain.MAINNET,
                kind=EventKind.DOWN,
                severity=Severity.WARN,
                subject="pool.example.org",
                prober_id="test",
                started_at=datetime(2026, 10, 14, 9, 0, tzinfo=UTC),
            ),
            7,
        )
        assert reopened == 260
        event = next(e for e in db.events(Chain.MAINNET) if e.id == 260)
        assert event.occurrences == 2 and event.ongoing and event.active_s == 120
    finally:
        db.close()


def test_events_columns_match_the_schema(tmp_path: Path) -> None:
    """The in-place column list and SCHEMA must agree, or a migrated file and a fresh
    one would differ."""
    from epic_status.db import _EVENTS_ADDED_COLUMNS

    db = Database(tmp_path / "fresh.db", prober_id="test")
    try:
        live = {r[1] for r in db.conn.execute("PRAGMA table_info(events)")}
        assert {name for name, _ in _EVENTS_ADDED_COLUMNS} <= live
        assert _column_names(_create_table_sql("events")) == live
        occ = {r[1] for r in db.conn.execute("PRAGMA table_info(event_occurrences)")}
        assert {"event_id", "started_at", "ended_at", "detail"} <= occ
    finally:
        db.close()
