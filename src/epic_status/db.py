"""SQLite storage.

SQLite rather than Postgres because "anyone can self-host this" is a requirement,
and a single file is the difference between a five-minute setup and a forty-minute
one. The write volume does not argue otherwise: a dozen targets at a five-second
cadence is a few hundred thousand rows a day, pruned.

WAL mode, one writer, many readers. The poller is the only writer and it lives in
the same process as the web layer, so there is no cross-process contention to
manage.

One thing here is irreplaceable and the rest is not. Uptime history and
`last_ok_at` cannot be reconstructed from anything — no node reports when it was
last up — so `checks` and `rollup_hourly` are real state. Everything derived from
them is rebuilt at boot. Any repair script that truncates must name those two
tables explicitly rather than relying on a cascade.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import GeoInfo, Kind, Source, Target

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- Monitored things. Seeds are reconciled from config/targets.toml at every boot;
-- submissions are only ever inserted here by the submission pipeline, after they
-- have passed validation and three spaced probes.
CREATE TABLE IF NOT EXISTS targets (
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

    -- Denormalised so the board is one query rather than one per row.
    last_ok_at    TEXT,
    last_checked_at TEXT,
    last_error    TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,

    -- Slow-changing facts, refreshed on their own cadences.
    node_version      TEXT,
    protocol_version  TEXT,
    cert_expires_at   TEXT,
    geo_json          TEXT,
    geo_looked_up_at  TEXT,

    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (kind, slug)
);

-- REAL STATE. Nothing can rebuild this. Do not add a foreign key from any
-- disposable table into it, and never truncate it as collateral.
--
-- `prober_id` is here from the first migration even though v1 runs one prober,
-- because retrofitting a vantage-point dimension onto accumulated history is not
-- possible: you cannot say after the fact where a measurement was taken from.
CREATE TABLE IF NOT EXISTS checks (
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

CREATE INDEX IF NOT EXISTS idx_checks_target_time
    ON checks (target_id, checked_at DESC);

-- Hourly rollups, merged into the 90-day bar. Kept separate from `checks` so raw
-- successes can be pruned at seven days without losing long-range uptime.
CREATE TABLE IF NOT EXISTS rollup_hourly (
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    prober_id   TEXT    NOT NULL,
    hour        TEXT    NOT NULL,
    checks      INTEGER NOT NULL,
    ok_checks   INTEGER NOT NULL,
    p50_latency_ms INTEGER,
    PRIMARY KEY (target_id, prober_id, hour)
);

CREATE INDEX IF NOT EXISTS idx_rollup_target_hour
    ON rollup_hourly (target_id, hour DESC);

-- Pending public submissions. Separate from `targets` on purpose: nothing here is
-- ever probed on the main sweep, so a submitted host cannot become a poller
-- amplifier before it has been validated.
CREATE TABLE IF NOT EXISTS submissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL CHECK (kind IN ('node','epicbox')),
    host        TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL,
    operator    TEXT,
    submitted_at TEXT   NOT NULL,
    submitter_hash TEXT NOT NULL,
    -- A salted hash of the submitter's address, not the address. Enough to rate
    -- limit and to spot a flood; not a log of who looked at what.
    probes_passed INTEGER NOT NULL DEFAULT 0,
    probes_attempted INTEGER NOT NULL DEFAULT 0,
    next_probe_at TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','accepted','rejected')),
    last_error  TEXT,
    UNIQUE (kind, host)
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


class Database:
    """Thin, explicit data layer. No ORM: the queries are few, they are the part
    worth reading, and an ORM would hide the index the board depends on."""

    def __init__(self, path: Path, prober_id: str) -> None:
        self.path = path
        self.prober_id = prober_id
        self.conn = connect(path)
        self.apply_schema()

    def apply_schema(self) -> None:
        """Idempotent, run at every boot. Cheaper than tracking migrations for a
        schema this small, and it means a fresh clone needs no setup step."""
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN")
        try:
            yield self.conn
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    # ------------------------------------------------------------------ targets

    def reconcile_seeds(self, seeds: list[Target]) -> None:
        """Make the database agree with the committed file.

        Seed rows are updated in place rather than deleted and reinserted, because
        deleting a target cascades its history away. Editing a label in TOML must
        not silently destroy three months of uptime data.

        A seed removed from the file is disabled, not deleted, for the same
        reason — and because "this used to be a public node" is worth keeping.
        """
        with self.tx() as conn:
            live_slugs: set[tuple[str, str]] = set()
            for t in seeds:
                live_slugs.add((t.kind.value, t.slug))
                conn.execute(
                    """
                    INSERT INTO targets
                        (kind, slug, endpoint, display_host, p2p, operator, label,
                         notes, ours, source, enabled, geo_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,1,?)
                    ON CONFLICT (kind, slug) DO UPDATE SET
                        endpoint = excluded.endpoint,
                        display_host = excluded.display_host,
                        p2p = excluded.p2p,
                        operator = excluded.operator,
                        label = excluded.label,
                        notes = excluded.notes,
                        ours = excluded.ours,
                        source = excluded.source,
                        enabled = 1,
                        -- Only the hand-set country is taken from the file. The rest
                        -- of geo_json is looked-up data and must survive an edit to
                        -- a label, so the two are merged by key rather than replaced.
                        geo_json = json_set(
                            COALESCE(targets.geo_json, '{}'),
                            '$.country_manual',
                            json_extract(excluded.geo_json, '$.country_manual')
                        )
                    """,
                    (
                        t.kind.value,
                        t.slug,
                        t.endpoint,
                        t.display_host,
                        t.p2p,
                        t.operator,
                        t.label,
                        t.notes,
                        int(t.ours),
                        Source.SEED.value,
                        json.dumps(t.geo.model_dump(mode="json")),
                    ),
                )

            for row in conn.execute(
                "SELECT kind, slug FROM targets WHERE source = 'seed' AND enabled = 1"
            ).fetchall():
                if (row["kind"], row["slug"]) not in live_slugs:
                    conn.execute(
                        "UPDATE targets SET enabled = 0 WHERE kind = ? AND slug = ?",
                        (row["kind"], row["slug"]),
                    )

    def targets(self, *, enabled_only: bool = True) -> list[Target]:
        sql = "SELECT * FROM targets"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY kind, slug"
        return [_row_to_target(r) for r in self.conn.execute(sql).fetchall()]

    def insert_target(self, t: Target) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO targets
                (kind, slug, endpoint, display_host, p2p, operator, label, notes,
                 ours, source, enabled, geo_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,1,?)
            ON CONFLICT (kind, slug) DO NOTHING
            """,
            (
                t.kind.value,
                t.slug,
                t.endpoint,
                t.display_host,
                t.p2p,
                t.operator,
                t.label,
                t.notes,
                int(t.ours),
                t.source.value,
                json.dumps(t.geo.model_dump(mode="json")),
            ),
        )
        if cur.lastrowid:
            return int(cur.lastrowid)
        row = self.conn.execute(
            "SELECT id FROM targets WHERE kind = ? AND slug = ?", (t.kind.value, t.slug)
        ).fetchone()
        return int(row["id"])

    def delete_target(self, target_id: int) -> None:
        """Only ever called for a submitted target that has never succeeded. The
        cascade takes its history with it, which is the intent: an entry that was
        never real should leave no trace."""
        self.conn.execute(
            "DELETE FROM targets WHERE id = ? AND source = 'submitted' AND last_ok_at IS NULL",
            (target_id,),
        )

    def set_geo(self, target_id: int, geo: GeoInfo) -> None:
        self.conn.execute(
            "UPDATE targets SET geo_json = ?, geo_looked_up_at = ? WHERE id = ?",
            (json.dumps(geo.model_dump(mode="json")), _iso(_now()), target_id),
        )

    def set_node_version(self, target_id: int, version: str | None) -> None:
        self.conn.execute(
            "UPDATE targets SET node_version = ? WHERE id = ?", (version, target_id)
        )

    def set_protocol_version(self, target_id: int, version: str | None) -> None:
        self.conn.execute(
            "UPDATE targets SET protocol_version = ? WHERE id = ?", (version, target_id)
        )

    def set_cert_expiry(self, target_id: int, expires_at: datetime | None) -> None:
        self.conn.execute(
            "UPDATE targets SET cert_expires_at = ? WHERE id = ?",
            (_iso(expires_at) if expires_at else None, target_id),
        )

    # ------------------------------------------------------------------- checks

    def record_check(
        self,
        *,
        target_id: int,
        ok: bool,
        state: str,
        reason: str,
        latency_ms: int | None,
        height: int | None,
        tip_hash: str | None,
        error: str | None,
        at: datetime | None = None,
    ) -> None:
        """One row per probe, plus the denormalised fields the board reads.

        `last_ok_at` only ever moves forward and only on success — that is the
        whole contract behind the "last seen" note, and the reason it is updated
        in the same statement rather than by a later pass.
        """
        at = at or _now()
        stamp = _iso(at)
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO checks
                    (target_id, prober_id, checked_at, ok, state, reason,
                     latency_ms, height, tip_hash, error)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    target_id,
                    self.prober_id,
                    stamp,
                    int(ok),
                    state,
                    reason,
                    latency_ms,
                    height,
                    tip_hash,
                    error,
                ),
            )
            if ok:
                conn.execute(
                    """
                    UPDATE targets
                       SET last_checked_at = ?, last_ok_at = ?,
                           consecutive_failures = 0, last_error = NULL
                     WHERE id = ?
                    """,
                    (stamp, stamp, target_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE targets
                       SET last_checked_at = ?,
                           consecutive_failures = consecutive_failures + 1,
                           last_error = ?
                     WHERE id = ?
                    """,
                    (stamp, error, target_id),
                )

            hour = stamp[:13] + ":00:00Z"
            conn.execute(
                """
                INSERT INTO rollup_hourly
                    (target_id, prober_id, hour, checks, ok_checks, p50_latency_ms)
                VALUES (?,?,?,1,?,?)
                ON CONFLICT (target_id, prober_id, hour) DO UPDATE SET
                    checks = checks + 1,
                    ok_checks = ok_checks + excluded.ok_checks,
                    -- A running approximation, not a true median. Storing every
                    -- latency for 90 days to compute an exact one is not a
                    -- trade worth making for a number displayed to 0 decimals.
                    p50_latency_ms = CASE
                        WHEN excluded.p50_latency_ms IS NULL THEN p50_latency_ms
                        WHEN p50_latency_ms IS NULL THEN excluded.p50_latency_ms
                        ELSE (p50_latency_ms * 3 + excluded.p50_latency_ms) / 4
                    END
                """,
                (target_id, self.prober_id, hour, int(ok), latency_ms),
            )

    def history(self, target_id: int, limit: int) -> list[bool]:
        rows = self.conn.execute(
            "SELECT ok FROM checks WHERE target_id = ? ORDER BY checked_at DESC, id DESC LIMIT ?",
            (target_id, limit),
        ).fetchall()
        return [bool(r["ok"]) for r in reversed(rows)]

    def uptime(self, target_id: int, window: timedelta) -> float | None:
        """Uptime over a window, from rollups so it stays cheap at 90 days.

        Returns None rather than 0.0 when there is nothing to divide by. A target
        with no data is not a target with no uptime, and rendering 0% for one is
        how a status page libels an operator.
        """
        since = _iso(_now() - window)[:13] + ":00:00Z"
        row = self.conn.execute(
            """
            SELECT SUM(checks) AS total, SUM(ok_checks) AS ok
              FROM rollup_hourly
             WHERE target_id = ? AND hour >= ?
            """,
            (target_id, since),
        ).fetchone()
        total = row["total"] or 0
        if total == 0:
            return None
        return float(row["ok"] or 0) / float(total)

    def daily_uptime(self, target_id: int, days: int) -> list[tuple[str, float | None]]:
        """One bucket per day for the 90-day bar. Missing days come back as None
        so the bar shows a gap rather than inventing an outage."""
        rows = self.conn.execute(
            """
            SELECT substr(hour, 1, 10) AS day,
                   SUM(checks) AS total, SUM(ok_checks) AS ok
              FROM rollup_hourly
             WHERE target_id = ? AND hour >= ?
             GROUP BY day
            """,
            (target_id, _iso(_now() - timedelta(days=days))[:10] + "T00:00:00Z"),
        ).fetchall()
        by_day = {
            r["day"]: (float(r["ok"] or 0) / float(r["total"]) if r["total"] else None)
            for r in rows
        }
        today = _now().date()
        out: list[tuple[str, float | None]] = []
        for i in range(days - 1, -1, -1):
            d = (today - timedelta(days=i)).isoformat()
            out.append((d, by_day.get(d)))
        return out

    def prune(self, keep_success_days: int) -> int:
        """Drop old successes. Failures are never pruned.

        Nobody ever needs to prove a node was up. Everybody eventually needs to
        prove it was down, usually in an argument with its operator.
        """
        cutoff = _iso(_now() - timedelta(days=keep_success_days))
        cur = self.conn.execute(
            "DELETE FROM checks WHERE ok = 1 AND checked_at < ?", (cutoff,)
        )
        return cur.rowcount or 0

    # -------------------------------------------------------------- submissions

    def pending_submission_count(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM submissions WHERE status = 'pending'"
        ).fetchone()
        return int(row["n"])

    def recent_submissions_by(self, submitter_hash: str, window: timedelta) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM submissions WHERE submitter_hash = ? AND submitted_at >= ?",
            (submitter_hash, _iso(_now() - window)),
        ).fetchone()
        return int(row["n"])

    def insert_submission(
        self,
        *,
        kind: Kind,
        host: str,
        endpoint: str,
        operator: str | None,
        submitter_hash: str,
        next_probe_at: datetime,
    ) -> int | None:
        cur = self.conn.execute(
            """
            INSERT INTO submissions
                (kind, host, endpoint, operator, submitted_at, submitter_hash, next_probe_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT (kind, host) DO NOTHING
            """,
            (
                kind.value,
                host,
                endpoint,
                operator,
                _iso(_now()),
                submitter_hash,
                _iso(next_probe_at),
            ),
        )
        return int(cur.lastrowid) if cur.lastrowid else None

    def due_submissions(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT * FROM submissions
             WHERE status = 'pending' AND (next_probe_at IS NULL OR next_probe_at <= ?)
             ORDER BY submitted_at
            """,
            (_iso(_now()),),
        ).fetchall()

    def update_submission(
        self,
        submission_id: int,
        *,
        probes_passed: int,
        probes_attempted: int,
        next_probe_at: datetime | None,
        status: str,
        last_error: str | None,
    ) -> None:
        self.conn.execute(
            """
            UPDATE submissions
               SET probes_passed = ?, probes_attempted = ?, next_probe_at = ?,
                   status = ?, last_error = ?
             WHERE id = ?
            """,
            (
                probes_passed,
                probes_attempted,
                _iso(next_probe_at) if next_probe_at else None,
                status,
                last_error,
                submission_id,
            ),
        )


# --------------------------------------------------------------------- helpers


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _row_to_target(row: sqlite3.Row) -> Target:
    geo_raw: dict[str, Any] = {}
    if row["geo_json"]:
        try:
            geo_raw = json.loads(row["geo_json"])
        except (TypeError, ValueError):
            geo_raw = {}
    return Target(
        id=row["id"],
        kind=Kind(row["kind"]),
        slug=row["slug"],
        endpoint=row["endpoint"],
        display_host=row["display_host"],
        p2p=row["p2p"],
        operator=row["operator"],
        label=row["label"],
        notes=row["notes"],
        ours=bool(row["ours"]),
        source=Source(row["source"]),
        enabled=bool(row["enabled"]),
        geo=GeoInfo.model_validate(geo_raw),
        created_at=parse_iso(row["created_at"]),
    )
