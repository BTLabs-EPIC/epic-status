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
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from .models import Chain, Check, GeoInfo, Kind, Source, Target

def _sql_in(enum: type[Enum]) -> str:
    """Render an enum as a SQL `IN` list.

    The reason this exists: the kind set was written out by hand in three places, and the
    day `pool` was added two of them were updated. A deployed database then refused
    `kind='pool'` with an IntegrityError from inside a write while every test passed,
    because tests build a fresh file from the current schema. One source, generated.
    """
    return ",".join(f"'{member.value}'" for member in enum)


#: Every status the `submissions.status` column accepts. Named so the migration can notice
#: a live CHECK constraint that is missing one: `CREATE TABLE IF NOT EXISTS` cannot widen a
#: constraint, so the mismatch would otherwise surface as a write failure in production.
SUBMISSION_STATUSES = ("pending", "verified", "accepted", "rejected")

#: Pre-rendered for the schema f-string. `_sql_in` takes an Enum; these are plain strings
#: because the status set is not modelled as one anywhere else.
_sql_in_statuses = ",".join(f"'{status}'" for status in SUBMISSION_STATUSES)

SCHEMA = f"""
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- Monitored things. Seeds are reconciled from config/targets.toml at every boot;
-- submissions are only ever inserted here by the submission pipeline, after they
-- have passed validation and three spaced probes.
CREATE TABLE IF NOT EXISTS targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT    NOT NULL CHECK (kind IN ({_sql_in(Kind)})),
    -- Which network the host serves. Defaulted, which is what makes this column
    -- migratable: `_rebuild` copies only the columns the old table had, so every row
    -- already in a live database takes 'mainnet' here — correct, because mainnet was
    -- the only chain that existed when those rows were written.
    chain         TEXT    NOT NULL DEFAULT 'mainnet' CHECK (chain IN ({_sql_in(Chain)})),
    slug          TEXT    NOT NULL,
    endpoint      TEXT    NOT NULL,
    display_host  TEXT    NOT NULL,
    p2p           TEXT,
    operator      TEXT,
    label         TEXT,
    notes         TEXT,
    -- `Target.verified`: vouched for as an official server rather than community-run.
    -- The column keeps its original name because renaming it would mean rebuilding the
    -- table and dropping the values in it, and the name is not published anywhere.
    ours          INTEGER NOT NULL DEFAULT 0,
    source        TEXT    NOT NULL CHECK (source IN ({_sql_in(Source)})),
    enabled       INTEGER NOT NULL DEFAULT 1,

    -- Denormalised so the board is one query rather than one per row.
    last_ok_at    TEXT,
    last_checked_at TEXT,
    last_error    TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,

    -- Which response shape to expect. Pool-only: every pool's API differs, so the
    -- adapter is declared per target rather than inferred. NULL for other kinds.
    adapter       TEXT,

    -- Slow-changing facts, refreshed on their own cadences.
    node_version      TEXT,
    protocol_version  TEXT,
    cert_expires_at   TEXT,
    geo_json          TEXT,
    geo_looked_up_at  TEXT,

    -- Which fields a human has set from /admin, as a JSON object keyed by the admin
    -- field name: `{{"operator": "2026-09-22T21:14:03Z", ...}}`. The value is when, and is
    -- for the dashboard to show; the *presence of the key* is what matters.
    --
    -- This exists because config/targets.toml and /admin are two writers for the same
    -- columns, and without a record of which one spoke last the file always won:
    -- `reconcile_seeds` runs on every boot and its ON CONFLICT clause overwrote
    -- operator, label, notes, ours, enabled and the hand-set country on every seed row.
    -- An edit made in the dashboard therefore survived exactly until the next restart,
    -- silently, with the dashboard still showing the new value until the page reloaded.
    --
    -- A pin is per field, not per row, so the file stays authoritative for everything
    -- nobody has touched — a corrected endpoint in the file still reaches a row whose
    -- operator was renamed by hand.
    admin_json        TEXT,

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
    kind        TEXT    NOT NULL CHECK (kind IN ({_sql_in(Kind)})),
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
                CHECK (status IN ({_sql_in_statuses})),
    -- 'verified' is the state this table gained when submissions stopped promoting
    -- themselves: the host passed its probes and is waiting for a human. Nothing reaches
    -- 'accepted' without someone deciding, so an unvetted third-party host can no longer
    -- appear on the board on its own.
    last_error  TEXT,
    -- A country the submitter volunteered. Optional, and a hint rather than authority: RDAP
    -- is frequently wrong about location and the person running the host is not. It becomes
    -- the hand-set override when an admin approves the request, who can change or clear it.
    country     TEXT,
    reviewed_at TEXT,
    reviewed_note TEXT,
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
        self.migrate()

    def apply_schema(self) -> None:
        """Idempotent, run at every boot. Cheaper than tracking migrations for a
        schema this small, and it means a fresh clone needs no setup step."""
        self.conn.executescript(SCHEMA)

    def migrate(self) -> None:
        """Bring an existing file up to the current SCHEMA.

        `apply_schema` is `CREATE TABLE IF NOT EXISTS`, which is a no-op on a table that
        already exists — so it cannot add a column and it cannot widen a CHECK constraint.
        That is fine until a new target kind appears: the enum accepts `pool`, the live file
        still says `CHECK (kind IN ('node','epicbox'))`, and the mismatch surfaces as an
        IntegrityError from inside a write. Tests pass throughout, because tests build a
        fresh database.

        Only `targets` and `submissions` are ever rebuilt, and neither holds irreplaceable
        state. `checks` and `rollup_hourly` are never touched here: they hold the only data
        nothing can reconstruct.
        """
        for table in ("targets", "submissions"):
            if self._needs_rebuild(table):
                self._rebuild(table)

    def _needs_rebuild(self, table: str) -> bool:
        row = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if row is None:
            return False
        live = row["sql"]
        if any(f"'{k.value}'" not in live for k in Kind):
            return True
        # Every enum that reaches a CHECK constraint has to be listed here, not just
        # the first one that ever did. A widened enum is invisible to the column diff
        # below — the column already exists, only the set of values it accepts
        # changed — so without this a new `Chain` member would pass every test on a
        # fresh database and then raise IntegrityError from inside a write against the
        # live file. That is precisely how `kind='pool'` broke once; `chain` is the
        # same trap with a different column name.
        if table == "targets" and any(f"'{c.value}'" not in live for c in Chain):
            return True
        if table == "submissions" and any(
            f"'{status}'" not in live for status in SUBMISSION_STATUSES
        ):
            return True
        # Column adds are detected the same way, so one pass fixes both.
        wanted = _column_names(_create_table_sql(table))
        return bool(wanted - _column_names(live))

    def _rebuild(self, table: str) -> None:
        """SQLite's supported table-alteration dance.

        SQLite has no DROP CONSTRAINT, so widening a CHECK means building a new table and
        moving the rows. Two details are load-bearing:

        `targets.id` values must survive exactly, because `checks.target_id` and
        `rollup_hourly.target_id` reference them and that history is irreplaceable. Copying
        `id` explicitly rather than letting AUTOINCREMENT reassign is the whole game.

        `foreign_keys` must be OFF around it, and `PRAGMA foreign_keys` is a no-op inside a
        transaction, so it is set outside one. With it ON, dropping the old table would
        cascade every check row away.
        """
        new_sql = _create_table_sql(table).replace(
            f"CREATE TABLE IF NOT EXISTS {table} (", f"CREATE TABLE {table}__new ("
        )
        old_cols = _column_names(
            self.conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()["sql"]
        )
        # Only columns present in both, so a rebuild that adds a column works and a
        # rebuild that retires one does not reference a column that is gone.
        shared = [c for c in _column_order(_create_table_sql(table)) if c in old_cols]
        cols = ", ".join(shared)

        self.conn.execute("PRAGMA foreign_keys = OFF")
        try:
            self.conn.execute("BEGIN")
            self.conn.execute(new_sql)
            self.conn.execute(
                f"INSERT INTO {table}__new ({cols}) SELECT {cols} FROM {table}"
            )
            self.conn.execute(f"DROP TABLE {table}")
            self.conn.execute(f"ALTER TABLE {table}__new RENAME TO {table}")
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        finally:
            self.conn.execute("PRAGMA foreign_keys = ON")
        # Indexes live in SCHEMA as CREATE INDEX IF NOT EXISTS and are dropped with the
        # table, so re-running the script restores them.
        self.apply_schema()

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
        """Make the database agree with the committed file, except where a human disagrees.

        Seed rows are updated in place rather than deleted and reinserted, because
        deleting a target cascades its history away. Editing a label in TOML must
        not silently destroy three months of uptime data.

        A seed removed from the file is disabled, not deleted, for the same
        reason — and because "this used to be a public node" is worth keeping.

        **Every column a human can edit is guarded by a pin.** This method runs on every
        boot, and its first version overwrote `operator`, `label`, `notes`, `ours`,
        `enabled` and the hand-set country unconditionally — so an edit made in /admin
        lasted until the next `systemctl restart` and then quietly reverted to whatever
        the file said. It was not visible as a failure anywhere: the dashboard saved, said
        "Saved", and showed the new value until someone reloaded hours later.

        `enabled` is in that set deliberately. Deactivating a host by clicking its tag is
        an operator decision about a host that is still listed in the file, and forcing it
        back to 1 on boot made the control look broken rather than overridden.
        """
        with self.tx() as conn:
            live_slugs: set[tuple[str, str]] = set()
            for t in seeds:
                live_slugs.add((t.kind.value, t.slug))
                conn.execute(
                    """
                    INSERT INTO targets
                        (kind, chain, slug, endpoint, display_host, p2p, operator, label,
                         notes, ours, adapter, source, enabled, geo_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)
                    ON CONFLICT (kind, slug) DO UPDATE SET
                        -- Not editable from /admin, so the file stays authoritative.
                        -- Identity and transport: changing where a host is reached is a
                        -- reviewed change to a committed file, not a dashboard field.
                        endpoint = excluded.endpoint,
                        display_host = excluded.display_host,
                        p2p = excluded.p2p,
                        adapter = excluded.adapter,
                        source = excluded.source,
                        -- Which chain a host serves is a property of the host, not a
                        -- preference: there is no /admin control for it and no pin, so
                        -- the file corrects it unconditionally. A seed that moves from
                        -- mainnet to floonet in the file moves on the next boot, keeping
                        -- its id and therefore its history.
                        chain = excluded.chain,

                        -- Editable, therefore pinned. `json_extract` of a missing key is
                        -- NULL, and a NULL `admin_json` extracts to NULL too, so an
                        -- untouched row takes the file value exactly as before.
                        operator = CASE
                            WHEN json_extract(targets.admin_json, '$.operator') IS NULL
                            THEN excluded.operator ELSE targets.operator END,
                        label = CASE
                            WHEN json_extract(targets.admin_json, '$.label') IS NULL
                            THEN excluded.label ELSE targets.label END,
                        notes = CASE
                            WHEN json_extract(targets.admin_json, '$.notes') IS NULL
                            THEN excluded.notes ELSE targets.notes END,
                        ours = CASE
                            WHEN json_extract(targets.admin_json, '$.verified') IS NULL
                            THEN excluded.ours ELSE targets.ours END,
                        enabled = CASE
                            WHEN json_extract(targets.admin_json, '$.enabled') IS NULL
                            THEN 1 ELSE targets.enabled END,

                        -- Only the hand-set country is taken from the file. The rest
                        -- of geo_json is looked-up data and must survive an edit to
                        -- a label, so the two are merged by key rather than replaced.
                        geo_json = CASE
                            WHEN json_extract(targets.admin_json, '$.country') IS NULL
                            THEN json_set(
                                COALESCE(targets.geo_json, '{}'),
                                '$.country_manual',
                                json_extract(excluded.geo_json, '$.country_manual')
                            )
                            ELSE targets.geo_json END
                    """,
                    (
                        t.kind.value,
                        t.chain.value,
                        t.slug,
                        t.endpoint,
                        t.display_host,
                        t.p2p,
                        t.operator,
                        t.label,
                        t.notes,
                        int(t.verified),
                        t.adapter,
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

    def chains(self) -> set[Chain]:
        """Which chains have at least one enabled target.

        Deliberately not `set(Chain)`: the navbar offers what this instance actually
        monitors, so an install with no floonet hosts shows no floonet switch rather
        than a link to an empty board. An unrecognised value in the column is skipped
        rather than raising — the CHECK constraint makes it impossible, and a status
        page should not fail to render a navbar over a row it cannot classify.
        """
        rows = self.conn.execute(
            "SELECT DISTINCT chain FROM targets WHERE enabled = 1"
        ).fetchall()
        found: set[Chain] = set()
        for row in rows:
            try:
                found.add(Chain(row["chain"]))
            except ValueError:
                continue
        return found

    def insert_target(self, t: Target) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO targets
                (kind, chain, slug, endpoint, display_host, p2p, operator, label, notes,
                 ours, adapter, source, enabled, geo_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)
            ON CONFLICT (kind, slug) DO NOTHING
            """,
            (
                t.kind.value,
                t.chain.value,
                t.slug,
                t.endpoint,
                t.display_host,
                t.p2p,
                t.operator,
                t.label,
                t.notes,
                int(t.verified),
                t.adapter,
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

    def target(self, target_id: int) -> Target | None:
        row = self.conn.execute(
            "SELECT * FROM targets WHERE id = ?", (target_id,)
        ).fetchone()
        return _row_to_target(row) if row is not None else None

    def update_target_fields(
        self,
        target_id: int,
        *,
        operator: str | None,
        label: str | None,
        notes: str | None,
        verified: bool,
        enabled: bool,
    ) -> None:
        """The editable half of a target record.

        These are the fields nothing can derive: who runs a host, what to call it, whether
        it is vouched for as an official server, and whether to keep checking it. They
        arrive from the committed registry or a submission form, and before this there was
        no way to correct one without editing TOML and redeploying.

        `slug`, `kind` and `endpoint` are deliberately absent. They identify the target and
        are referenced by `checks.target_id`; changing an endpoint in place would silently
        attribute one host's measurement history to another.
        """
        self.conn.execute(
            """
            UPDATE targets
               SET operator = ?, label = ?, notes = ?, ours = ?, enabled = ?
             WHERE id = ?
            """,
            (
                operator or None,
                label or None,
                notes or None,
                int(verified),
                int(enabled),
                target_id,
            ),
        )
        # Every field this writes is also written by `reconcile_seeds` from
        # config/targets.toml on every boot, so each one has to be pinned or the whole
        # form reverts at the next restart.
        for field in ("operator", "label", "notes", "verified", "enabled"):
            self._pin(target_id, field)

    #: Field name from the dashboard -> how to store it. Explicit rather than derived, so a
    #: request naming `slug`, `endpoint` or `kind` cannot reach a column: those identify the
    #: row that `checks.target_id` points at, and repointing one would attribute a host's
    #: measurement history to another host.
    _EDITABLE_TEXT = {"operator": "operator", "label": "label", "notes": "notes"}
    _EDITABLE_FLAGS = {"verified": "ours", "enabled": "enabled"}
    _EDITABLE_GEO = {"country": "country_manual", "provider": "provider_manual", "city": "city_manual"}

    def _pin(self, target_id: int, field: str) -> None:
        """Record that a human has set this field, so `reconcile_seeds` stops touching it.

        Written on the same connection as the edit that prompted it. If the two could
        diverge — the value written and the pin not — the next restart would revert the
        edit, which is the exact bug this exists to close.
        """
        self.conn.execute(
            """
            UPDATE targets
               SET admin_json = json_set(
                       COALESCE(admin_json, '{}'), '$.' || ?,
                       strftime('%Y-%m-%dT%H:%M:%SZ','now'))
             WHERE id = ?
            """,
            (field, target_id),
        )

    def unpin_target_field(self, target_id: int, field: str) -> bool:
        """Hand a field back to config/targets.toml.

        The way out of a correction that turned out to be wrong. Without it a field, once
        edited, could never follow the file again — which would make the pin a trap rather
        than an override. The file's value returns on the next boot, not immediately.
        """
        if field not in self._editable_fields():
            return False
        self.conn.execute(
            "UPDATE targets SET admin_json = json_remove(COALESCE(admin_json, '{}'), '$.' || ?) "
            "WHERE id = ?",
            (field, target_id),
        )
        self.conn.commit()
        return True

    @classmethod
    def _editable_fields(cls) -> set[str]:
        return set(cls._EDITABLE_TEXT) | set(cls._EDITABLE_FLAGS) | set(cls._EDITABLE_GEO)

    def admin_pins(self, target_id: int) -> dict[str, str]:
        """Which fields on this row are held against the file, and when they were set."""
        row = self.conn.execute(
            "SELECT admin_json FROM targets WHERE id = ?", (target_id,)
        ).fetchone()
        if row is None or not row["admin_json"]:
            return {}
        pins: dict[str, str] = json.loads(row["admin_json"])
        return pins

    def set_target_field(self, target_id: int, field: str, value: str) -> bool:
        """Update exactly one field. Returns False for a field that is not editable.

        One method for all of them because the dashboard saves per field rather than per
        form — a checkbox on click, a text box on blur. A whitelist rather than string
        interpolation of the caller's field name: this is an authenticated endpoint, but an
        authenticated endpoint that will write any column you name is still an arbitrary
        write.

        Every branch pins the field. `config/targets.toml` writes the same columns on every
        boot, so an unpinned edit is an edit with a countdown on it.
        """
        if field in self._EDITABLE_TEXT:
            column = self._EDITABLE_TEXT[field]
            self.conn.execute(
                f"UPDATE targets SET {column} = ? WHERE id = ?",  # noqa: S608 - whitelisted
                (value.strip() or None, target_id),
            )
            self._pin(target_id, field)
            return True
        if field in self._EDITABLE_FLAGS:
            column = self._EDITABLE_FLAGS[field]
            self.conn.execute(
                f"UPDATE targets SET {column} = ? WHERE id = ?",  # noqa: S608 - whitelisted
                (1 if value in ("1", "true", "on") else 0, target_id),
            )
            self._pin(target_id, field)
            return True
        if field in self._EDITABLE_GEO:
            key = self._EDITABLE_GEO[field]
            row = self.conn.execute(
                "SELECT geo_json FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            current = GeoInfo()
            if row is not None and row["geo_json"]:
                current = GeoInfo.model_validate(json.loads(row["geo_json"]))
            cleaned = value.strip()
            if field == "country":
                cleaned = cleaned.upper()
            updated = current.model_copy(update={key: cleaned or None})
            self.conn.execute(
                "UPDATE targets SET geo_json = ? WHERE id = ?",
                (json.dumps(updated.model_dump(mode="json")), target_id),
            )
            self._pin(target_id, field)
            return True
        return False

    def set_geo_overrides(
        self,
        target_id: int,
        *,
        country: str | None,
        provider: str | None,
        city: str | None,
    ) -> None:
        """Write the hand-set half of a target's location, keeping the looked-up half.

        Reads the stored blob, sets only the `*_manual` fields and writes it back rather
        than replacing it: the registry values and `looked_up_at` are evidence of what RDAP
        actually said, and an override is a correction on top of that, not a substitute for
        it. `geo.merge` carries the manual fields through every refresh, so this sticks.

        An empty string clears an override and lets the registry value show again, which is
        the only way back from a correction that turned out to be wrong.

        Only `country` is pinned. `provider_manual` and `city_manual` were never at risk —
        `reconcile_seeds` merges `geo_json` by key and the file carries no provider or city —
        but the country does come from the file, so setting it by hand has to say so.
        """
        row = self.conn.execute(
            "SELECT geo_json FROM targets WHERE id = ?", (target_id,)
        ).fetchone()
        current = GeoInfo()
        if row is not None and row["geo_json"]:
            current = GeoInfo.model_validate(json.loads(row["geo_json"]))
        updated = current.model_copy(
            update={
                "country_manual": (country or "").strip().upper() or None,
                "provider_manual": (provider or "").strip() or None,
                "city_manual": (city or "").strip() or None,
            }
        )
        self.conn.execute(
            "UPDATE targets SET geo_json = ? WHERE id = ?",
            (json.dumps(updated.model_dump(mode="json")), target_id),
        )
        self._pin(target_id, "country")

    def delete_target_admin(self, target_id: int) -> bool:
        """The deliberate path: an authenticated human removing any target.

        Separate from `delete_target` rather than a flag on it, because the two have
        different safety properties and collapsing them would let the automatic rule inherit
        this one's reach. Returns whether a row was actually deleted: the admin route used
        the narrow method first and reported "removed" for a seed target it had not touched,
        which is the worst kind of wrong — the operator believes the host is gone.

        The cascade takes `checks` and `rollup_hourly` with it. That history cannot be
        rebuilt, which is why the dashboard offers disabling in the same place.
        """
        cur = self.conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        return cur.rowcount > 0

    def delete_target(self, target_id: int) -> None:
        """The automatic path: a submitted target that has never once succeeded.

        Narrow on purpose. This is what the self-deleting-dead-submission rule calls, and it
        must never be able to remove a host that has real history — so the conditions live in
        the statement rather than in the caller. `delete_target_admin` is the deliberate
        counterpart.
        """
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

    def history(self, target_id: int, limit: int) -> list[Check]:
        """Recent checks, oldest first, with the time and latency of each.

        Ordered newest-first in SQL so LIMIT takes the newest rows, then reversed — the strip
        reads left to right as time moving forward.
        """
        rows = self.conn.execute(
            """
            SELECT ok, checked_at, latency_ms FROM checks
             WHERE target_id = ? ORDER BY checked_at DESC, id DESC LIMIT ?
            """,
            (target_id, limit),
        ).fetchall()
        out: list[Check] = []
        for r in reversed(rows):
            at = parse_iso(r["checked_at"])
            if at is None:
                continue
            out.append(
                Check(ok=bool(r["ok"]), at=at, latency_ms=r["latency_ms"])
            )
        return out

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
        country: str | None = None,
    ) -> int | None:
        cur = self.conn.execute(
            """
            INSERT INTO submissions
                (kind, host, endpoint, operator, submitted_at, submitter_hash,
                 next_probe_at, country)
            VALUES (?,?,?,?,?,?,?,?)
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
                (country or "").strip().upper() or None,
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

    def submissions(self, status: str | None = None) -> list[sqlite3.Row]:
        """Every submission, newest first, optionally one status.

        For the review dashboard. Ordered by `submitted_at DESC` rather than by status, so
        the newest request is the top row whatever state it is in.
        """
        if status is None:
            return list(
                self.conn.execute(
                    "SELECT * FROM submissions ORDER BY submitted_at DESC"
                ).fetchall()
            )
        return list(
            self.conn.execute(
                "SELECT * FROM submissions WHERE status = ? ORDER BY submitted_at DESC",
                (status,),
            ).fetchall()
        )

    def submission(self, submission_id: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute(
            "SELECT * FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        return row

    def submission_counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM submissions GROUP BY status"
        ).fetchall()
        counts = {status: 0 for status in SUBMISSION_STATUSES}
        for row in rows:
            counts[str(row["status"])] = int(row["n"])
        return counts

    def delete_submission(self, submission_id: int) -> bool:
        """Drop a request entirely.

        Distinct from rejecting it. A rejection is a decision worth keeping — it stops the
        validator, records who was turned away and when, and the unique constraint on
        `(kind, host)` then blocks the same host being resubmitted. Deleting removes that
        record and frees the host to be requested again, which is what you want for a typo
        or a test entry rather than for something you actually declined.
        """
        cur = self.conn.execute("DELETE FROM submissions WHERE id = ?", (submission_id,))
        return cur.rowcount > 0

    def review_submission(
        self, submission_id: int, *, status: str, note: str | None
    ) -> None:
        """Record a human decision. Does not touch the probe counters.

        Separate from `update_submission` on purpose: that method is the validator's, and a
        review must not silently reset the evidence the reviewer just read.
        """
        self.conn.execute(
            """
            UPDATE submissions
               SET status = ?, reviewed_at = ?, reviewed_note = ?, next_probe_at = NULL
             WHERE id = ?
            """,
            (status, _iso(_now()), note, submission_id),
        )

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


def _create_table_sql(table: str) -> str:
    """Pull one CREATE TABLE statement out of SCHEMA.

    The rebuild needs the current definition of a single table, and SCHEMA is one script.
    Extracted by matching rather than kept in separate constants, so there is still exactly
    one place a column is declared.
    """
    match = re.search(
        rf"CREATE TABLE IF NOT EXISTS {table} \(.*?\n\);",
        SCHEMA,
        re.DOTALL,
    )
    if match is None:
        raise KeyError(f"no CREATE TABLE for {table} in SCHEMA")
    return match.group(0)


def _column_order(create_sql: str) -> list[str]:
    """Column names in declaration order, ignoring comments and table constraints.

    A rebuild copies `INSERT INTO new (cols) SELECT cols FROM old`, so it needs names and
    not types. Table-level clauses — UNIQUE, CHECK, PRIMARY KEY, FOREIGN KEY — look like
    lines that start with a word and must not be mistaken for columns, and `--` comment
    lines must not either. Tied to SQLite's own view of the same statement by a test, so a
    schema style this parser mishandles fails there rather than during a rebuild.
    """
    body = create_sql[create_sql.index("(") + 1 : create_sql.rindex(")")]
    reserved = {"UNIQUE", "CHECK", "PRIMARY", "FOREIGN", "CONSTRAINT"}
    names: list[str] = []
    depth = 0
    line_start = True
    current = ""
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        # Only a line at paren depth zero can begin a column definition; a continuation
        # inside CHECK (...) is part of the previous one.
        if depth == 0 and line_start:
            first = stripped.split()[0].strip(",")
            if first.upper() not in reserved and first not in names:
                names.append(first)
        depth += stripped.count("(") - stripped.count(")")
        line_start = depth <= 0
        depth = max(depth, 0)
        current = stripped
    _ = current
    return names


def _column_names(create_sql: str) -> set[str]:
    return set(_column_order(create_sql))


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
        # `_row_to_target` reads every column by name, so a row from a database that
        # has not been rebuilt yet would raise IndexError here rather than defaulting.
        # It cannot happen in practice — `migrate()` runs in the constructor, before
        # anything can read — but the keys() check costs nothing and turns a
        # hypothetical crash into the documented default.
        chain=Chain(row["chain"]) if "chain" in row.keys() else Chain.MAINNET,
        slug=row["slug"],
        endpoint=row["endpoint"],
        display_host=row["display_host"],
        p2p=row["p2p"],
        operator=row["operator"],
        label=row["label"],
        notes=row["notes"],
        adapter=row["adapter"],
        verified=bool(row["ours"]),
        source=Source(row["source"]),
        enabled=bool(row["enabled"]),
        geo=GeoInfo.model_validate(geo_raw),
        created_at=parse_iso(row["created_at"]),
    )
