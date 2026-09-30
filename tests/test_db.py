"""SQLite storage.

Two properties here are irreplaceable and the rest is derived: uptime history and
`last_ok_at` cannot be reconstructed from anything, because no node reports when it
was last up. Most of this file exists to pin the paths along which that history
could be silently destroyed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from epic_status.db import Database
from epic_status.models import GeoInfo, Kind, Source, Target


def _outcomes(history: list) -> list[bool]:
    """Just the pass/fail sequence.

    `Database.history` returns `Check` objects — it gained the time and latency of each check
    when the recent-checks bars became inspectable on hover. These tests are about the order
    and the outcomes, which is what this keeps them about.
    """
    return [c.ok for c in history]



def _seed(slug: str, *, label: str | None = None, kind: Kind = Kind.NODE) -> Target:
    return Target(
        kind=kind,
        slug=slug,
        endpoint=f"https://{slug}:3413",
        display_host=slug,
        label=label,
        source=Source.SEED,
    )


def _submitted(slug: str) -> Target:
    return Target(
        kind=Kind.NODE,
        slug=slug,
        endpoint=f"https://{slug}:3413",
        display_host=slug,
        source=Source.SUBMITTED,
    )


def _id_of(db: Database, slug: str) -> int:
    for t in db.targets(enabled_only=False):
        if t.slug == slug:
            assert t.id is not None
            return t.id
    raise AssertionError(f"{slug} not in targets")


def _ok(db: Database, target_id: int, **kw: object) -> None:
    db.record_check(
        target_id=target_id,
        ok=True,
        state="healthy",
        reason="ok",
        latency_ms=41,
        height=3721166,
        tip_hash="902031772af68dda",
        error=None,
        **kw,  # type: ignore[arg-type]
    )


def _fail(db: Database, target_id: int, error: str = "connection refused", **kw: object) -> None:
    db.record_check(
        target_id=target_id,
        ok=False,
        state="down",
        reason="refused",
        latency_ms=None,
        height=None,
        tip_hash=None,
        error=error,
        **kw,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------- schema


def test_apply_schema_is_idempotent(db: Database) -> None:
    """Run at every boot in place of migration tracking, so running it twice has to
    be free — including over a database that already holds data."""
    db.reconcile_seeds([_seed("node.btlabs.uk")])
    target_id = _id_of(db, "node.btlabs.uk")
    _ok(db, target_id)

    before = db.conn.execute(
        "SELECT name FROM sqlite_master ORDER BY name"
    ).fetchall()

    db.apply_schema()
    db.apply_schema()

    after = db.conn.execute("SELECT name FROM sqlite_master ORDER BY name").fetchall()
    assert [r["name"] for r in after] == [r["name"] for r in before]
    assert _outcomes(db.history(target_id, 10)) == [True]
    assert _id_of(db, "node.btlabs.uk") == target_id


# ------------------------------------------------------------- seed reconciliation


def test_reconcile_seeds_inserts(db: Database) -> None:
    db.reconcile_seeds([_seed("node.btlabs.uk"), _seed("node.epiccash.com")])

    slugs = [t.slug for t in db.targets()]
    assert slugs == ["node.btlabs.uk", "node.epiccash.com"]
    assert all(t.source is Source.SEED for t in db.targets())


def test_reconcile_seeds_updates_in_place_and_keeps_history(db: Database) -> None:
    """The load-bearing one. Deleting a target cascades its history away, so a
    re-run must UPDATE. Editing a label in TOML must never destroy uptime data.
    """
    db.reconcile_seeds([_seed("node.btlabs.uk", label="Old label")])
    target_id = _id_of(db, "node.btlabs.uk")
    _ok(db, target_id)
    _fail(db, target_id)
    _ok(db, target_id)
    last_ok_before = db.conn.execute(
        "SELECT last_ok_at FROM targets WHERE id = ?", (target_id,)
    ).fetchone()["last_ok_at"]

    db.reconcile_seeds([_seed("node.btlabs.uk", label="New label")])

    assert _id_of(db, "node.btlabs.uk") == target_id, "row was replaced, not updated"
    assert db.targets()[0].label == "New label"
    assert _outcomes(db.history(target_id, 10)) == [True, False, True]
    assert (
        db.conn.execute(
            "SELECT last_ok_at FROM targets WHERE id = ?", (target_id,)
        ).fetchone()["last_ok_at"]
        == last_ok_before
    )
    assert db.uptime(target_id, timedelta(hours=1)) == pytest.approx(2 / 3)


def test_reconcile_seeds_disables_a_removed_seed_rather_than_deleting_it(
    db: Database,
) -> None:
    """"This used to be a public node" is worth keeping, and deleting the row would
    take its outage history with it."""
    db.reconcile_seeds([_seed("stays"), _seed("goes")])
    goes_id = _id_of(db, "goes")
    _fail(db, goes_id)

    db.reconcile_seeds([_seed("stays")])

    assert [t.slug for t in db.targets()] == ["stays"]
    all_slugs = [t.slug for t in db.targets(enabled_only=False)]
    assert "goes" in all_slugs
    disabled = [t for t in db.targets(enabled_only=False) if t.slug == "goes"][0]
    assert disabled.enabled is False
    assert disabled.id == goes_id
    assert _outcomes(db.history(goes_id, 10)) == [False]


def test_reconcile_seeds_re_enables_a_returning_seed(db: Database) -> None:
    db.reconcile_seeds([_seed("comes-back")])
    target_id = _id_of(db, "comes-back")
    db.reconcile_seeds([])
    db.reconcile_seeds([_seed("comes-back")])

    assert _id_of(db, "comes-back") == target_id
    assert [t.slug for t in db.targets()] == ["comes-back"]


# --------------------------------------------- admin edits vs the committed file
#
# config/targets.toml and /admin are two writers for the same columns, and
# `reconcile_seeds` runs on every boot. The first version of it overwrote all of them
# unconditionally, so an edit made in the dashboard survived until the next
# `systemctl restart` and then reverted — with no error anywhere, and with the
# dashboard still showing the new value until the page was reloaded.
#
# These tests are the ones that would have caught it. Each edits a field, then runs
# the reconcile a boot would run, then asserts the human's value is still there.


def _file_seed(slug: str) -> Target:
    """A seed as the file declares it: operator, notes and country all set."""
    return Target(
        kind=Kind.NODE,
        slug=slug,
        endpoint=f"https://{slug}:3413",
        display_host=slug,
        operator="From The File",
        label="file label",
        notes="file note",
        source=Source.SEED,
        geo=GeoInfo(country_manual="FI"),
    )


@pytest.mark.parametrize(
    ("field", "value", "read"),
    [
        ("operator", "Renamed By Hand", lambda t: t.operator),
        ("label", "hand label", lambda t: t.label),
        ("notes", "hand note", lambda t: t.notes),
        ("country", "pl", lambda t: t.geo.country_manual),
    ],
)
def test_admin_edit_survives_a_reboot_reconcile(
    db: Database, field: str, value: str, read: object
) -> None:
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")

    assert db.set_target_field(target_id, field, value) is True
    db.conn.commit()

    db.reconcile_seeds([_file_seed("n")])

    target = [t for t in db.targets(enabled_only=False) if t.slug == "n"][0]
    expected = value.upper() if field == "country" else value
    assert read(target) == expected  # type: ignore[operator]


def test_admin_deactivation_survives_a_reboot_reconcile(db: Database) -> None:
    """Clicking a host's tag to deactivate it is a decision about a host that is still
    listed in the file. Forcing `enabled` back to 1 on boot made the control look
    broken rather than overridden."""
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")

    db.set_target_field(target_id, "enabled", "0")
    db.conn.commit()
    db.reconcile_seeds([_file_seed("n")])

    assert [t.slug for t in db.targets()] == []
    assert _id_of(db, "n") == target_id


def test_admin_verified_flag_survives_a_reboot_reconcile(db: Database) -> None:
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")

    db.set_target_field(target_id, "verified", "1")
    db.conn.commit()
    db.reconcile_seeds([_file_seed("n")])

    assert [t for t in db.targets() if t.slug == "n"][0].verified is True


def test_unpinned_fields_still_follow_the_file(db: Database) -> None:
    """The pin is per field, not per row. Correcting an endpoint in the file has to
    still reach a row whose operator was renamed by hand."""
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")
    db.set_target_field(target_id, "operator", "Renamed By Hand")
    db.conn.commit()

    changed = _file_seed("n")
    changed = changed.model_copy(update={"notes": "file note, edited", "label": "v2"})
    db.reconcile_seeds([changed])

    target = [t for t in db.targets() if t.slug == "n"][0]
    assert target.operator == "Renamed By Hand"
    assert target.notes == "file note, edited"
    assert target.label == "v2"


def test_unpin_hands_a_field_back_to_the_file(db: Database) -> None:
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")
    db.set_target_field(target_id, "operator", "Renamed By Hand")
    db.conn.commit()

    assert "operator" in db.admin_pins(target_id)
    assert db.unpin_target_field(target_id, "operator") is True
    assert "operator" not in db.admin_pins(target_id)

    db.reconcile_seeds([_file_seed("n")])
    assert [t for t in db.targets() if t.slug == "n"][0].operator == "From The File"


def test_unpin_rejects_a_field_that_is_not_editable(db: Database) -> None:
    db.reconcile_seeds([_file_seed("n")])
    assert db.unpin_target_field(_id_of(db, "n"), "endpoint") is False


def test_update_target_fields_pins_every_field_it_writes(db: Database) -> None:
    """The whole-form path, not the per-field one. It writes five columns the file also
    writes, so it has to pin all five or the form reverts on the next boot."""
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")

    db.update_target_fields(
        target_id,
        operator="Form Operator",
        label="form label",
        notes="form note",
        verified=True,
        enabled=False,
    )
    db.conn.commit()
    db.reconcile_seeds([_file_seed("n")])

    target = [t for t in db.targets(enabled_only=False) if t.slug == "n"][0]
    assert target.operator == "Form Operator"
    assert target.label == "form label"
    assert target.notes == "form note"
    assert target.verified is True
    assert target.enabled is False


def test_geo_overrides_pin_the_country_and_keep_the_looked_up_half(db: Database) -> None:
    db.reconcile_seeds([_file_seed("n")])
    target_id = _id_of(db, "n")
    db.set_geo(target_id, GeoInfo(country="FI", provider="Hetzner", asn="AS24940"))

    db.set_geo_overrides(target_id, country="pl", provider="MyISP", city="Warsaw")
    db.conn.commit()
    db.reconcile_seeds([_file_seed("n")])

    geo = [t for t in db.targets() if t.slug == "n"][0].geo
    assert geo.country_manual == "PL"
    assert geo.provider_manual == "MyISP"
    assert geo.city_manual == "Warsaw"
    # The registry's own answer is evidence of what RDAP said and is not overwritten.
    assert geo.provider == "Hetzner"
    assert geo.asn == "AS24940"


def test_slug_is_unique_per_kind_not_globally(db: Database) -> None:
    """A node and a relay on one machine legitimately share a name, and they are
    two rows because they are two services."""
    db.reconcile_seeds(
        [_seed("epiccash.com"), _seed("epiccash.com", kind=Kind.EPICBOX)]
    )
    assert len(db.targets()) == 2


# ----------------------------------------------------------------- record_check


def test_record_check_success_sets_last_ok_and_clears_failures(db: Database) -> None:
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    _fail(db, target_id)
    _fail(db, target_id)

    _ok(db, target_id)

    row = db.conn.execute(
        "SELECT * FROM targets WHERE id = ?", (target_id,)
    ).fetchone()
    assert row["consecutive_failures"] == 0
    assert row["last_ok_at"] is not None
    assert row["last_error"] is None
    assert row["last_checked_at"] == row["last_ok_at"]


def test_record_check_failure_increments_and_does_not_move_last_ok(
    db: Database,
) -> None:
    """`last_ok_at` only ever moves forward and only on success. That is the whole
    contract behind the "last seen" note on the board."""
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    _ok(db, target_id, at=datetime.now(UTC) - timedelta(minutes=5))
    last_ok = db.conn.execute(
        "SELECT last_ok_at FROM targets WHERE id = ?", (target_id,)
    ).fetchone()["last_ok_at"]

    _fail(db, target_id, error="connection timed out")
    _fail(db, target_id, error="connection refused")

    row = db.conn.execute(
        "SELECT * FROM targets WHERE id = ?", (target_id,)
    ).fetchone()
    assert row["consecutive_failures"] == 2
    assert row["last_error"] == "connection refused"
    assert row["last_ok_at"] == last_ok
    assert row["last_checked_at"] > last_ok


def test_record_check_writes_the_hourly_rollup(db: Database) -> None:
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    at = datetime(2026, 9, 22, 6, 30, tzinfo=UTC)
    _ok(db, target_id, at=at)
    _fail(db, target_id, at=at + timedelta(minutes=10))

    row = db.conn.execute("SELECT * FROM rollup_hourly").fetchone()
    assert row["hour"] == "2026-09-22T06:00:00Z"
    assert row["checks"] == 2
    assert row["ok_checks"] == 1


# ---------------------------------------------------------------------- uptime


def test_uptime_is_none_with_no_data(db: Database) -> None:
    """None, not 0.0. A target with no data is not a target with no uptime, and
    rendering 0% for one libels its operator."""
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")

    assert db.uptime(target_id, timedelta(hours=1)) is None
    assert db.uptime(target_id, timedelta(days=30)) is None


def test_uptime_maths(db: Database) -> None:
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    at = datetime.now(UTC).replace(minute=30, second=0, microsecond=0)
    for _ in range(3):
        _ok(db, target_id, at=at)
    _fail(db, target_id, at=at)

    assert db.uptime(target_id, timedelta(days=1)) == pytest.approx(0.75)


def test_uptime_is_zero_not_none_when_everything_failed(db: Database) -> None:
    """The distinction that makes the None above meaningful: measured total failure
    is 0.0, and only absence of data is None."""
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    _fail(db, target_id)
    _fail(db, target_id)

    assert db.uptime(target_id, timedelta(days=1)) == 0.0


def test_uptime_excludes_data_outside_the_window(db: Database) -> None:
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    _fail(db, target_id, at=datetime.now(UTC) - timedelta(days=40))
    _ok(db, target_id)

    assert db.uptime(target_id, timedelta(hours=1)) == 1.0
    assert db.uptime(target_id, timedelta(days=60)) == pytest.approx(0.5)


# ----------------------------------------------------------------- daily_uptime


def test_daily_uptime_returns_none_for_days_with_no_data(db: Database) -> None:
    """Missing days are gaps in the bar, not outages. Inventing an outage for a day
    the prober was not running is the same libel as rendering 0%."""
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    _ok(db, target_id)
    _ok(db, target_id)
    _fail(db, target_id)

    series = db.daily_uptime(target_id, days=5)

    assert len(series) == 5
    days = [d for d, _ in series]
    assert days == sorted(days), "oldest first, so the bar reads left to right"
    today = datetime.now(UTC).date().isoformat()
    assert days[-1] == today
    assert series[-1][1] == pytest.approx(2 / 3)
    assert [v for _, v in series[:-1]] == [None, None, None, None]


def test_daily_uptime_buckets_by_day(db: Database) -> None:
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    now = datetime.now(UTC)
    _ok(db, target_id, at=now)
    _fail(db, target_id, at=now - timedelta(days=2))

    series = dict(db.daily_uptime(target_id, days=4))

    assert series[now.date().isoformat()] == 1.0
    assert series[(now.date() - timedelta(days=2)).isoformat()] == 0.0
    assert series[(now.date() - timedelta(days=1)).isoformat()] is None


# ------------------------------------------------------------------------- prune


def test_prune_deletes_old_successes_and_keeps_old_failures(db: Database) -> None:
    """Nobody ever needs to prove a node was up. Everybody eventually needs to
    prove it was down, usually in an argument with its operator."""
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    old = datetime.now(UTC) - timedelta(days=30)
    _ok(db, target_id, at=old)
    _ok(db, target_id, at=old)
    _fail(db, target_id, at=old)
    _ok(db, target_id)

    deleted = db.prune(keep_success_days=7)

    assert deleted == 2
    rows = db.conn.execute("SELECT ok, checked_at FROM checks ORDER BY id").fetchall()
    assert [bool(r["ok"]) for r in rows] == [False, True]


def test_prune_does_not_touch_the_rollups(db: Database) -> None:
    """Raw successes are pruned at seven days; long-range uptime survives because
    it is read from `rollup_hourly`, which is never pruned."""
    db.reconcile_seeds([_seed("n")])
    target_id = _id_of(db, "n")
    _ok(db, target_id, at=datetime.now(UTC) - timedelta(days=30))

    db.prune(keep_success_days=7)

    assert db.conn.execute("SELECT COUNT(*) AS n FROM checks").fetchone()["n"] == 0
    assert db.uptime(target_id, timedelta(days=60)) == 1.0


# ----------------------------------------------------------------- delete_target


def test_delete_target_refuses_a_target_that_has_ever_succeeded(db: Database) -> None:
    """A host that answered once has real history, and the cascade would take it.
    A target that has gone quiet is reported as down, not forgotten."""
    target_id = db.insert_target(_submitted("was-up.example.com"))
    _ok(db, target_id)
    for _ in range(600):
        _fail(db, target_id)

    db.delete_target(target_id)

    assert [t.slug for t in db.targets()] == ["was-up.example.com"]


def test_delete_target_refuses_a_seed(db: Database) -> None:
    """`node.epiccash.com` being down is the single most important thing this page
    can report, so it must not vanish for the crime of being down."""
    db.reconcile_seeds([_seed("node.epiccash.com")])
    target_id = _id_of(db, "node.epiccash.com")
    _fail(db, target_id)

    db.delete_target(target_id)

    assert [t.slug for t in db.targets()] == ["node.epiccash.com"]


def test_delete_target_removes_a_submission_that_was_never_real(db: Database) -> None:
    """The one case it is for: a submitted host that has never once answered leaves
    no trace, history included."""
    target_id = db.insert_target(_submitted("never-was.example.com"))
    _fail(db, target_id)
    assert db.conn.execute("SELECT COUNT(*) AS n FROM checks").fetchone()["n"] == 1

    db.delete_target(target_id)

    assert db.targets(enabled_only=False) == []
    assert db.conn.execute("SELECT COUNT(*) AS n FROM checks").fetchone()["n"] == 0
    assert (
        db.conn.execute("SELECT COUNT(*) AS n FROM rollup_hourly").fetchone()["n"] == 0
    ), "the ON DELETE CASCADE needs PRAGMA foreign_keys to be on"


# ------------------------------------------------------------------ round-tripping


def test_insert_target_is_idempotent_and_returns_the_existing_id(db: Database) -> None:
    first = db.insert_target(_submitted("dupe.example.com"))
    second = db.insert_target(_submitted("dupe.example.com"))

    assert first == second
    assert len(db.targets()) == 1


def test_target_round_trips_through_sqlite(db: Database) -> None:
    """Booleans are stored as INTEGER and geo as JSON, so the mapping back is real
    work and not a cast."""
    from epic_status.models import GeoInfo

    original = Target(
        kind=Kind.EPICBOX,
        slug="epicbox.btlabs.uk",
        endpoint="wss://epicbox.btlabs.uk:443/",
        display_host="epicbox.btlabs.uk",
        p2p=None,
        operator="btlabs",
        label="Relay",
        notes="a note",
        verified=True,
        source=Source.SEED,
        geo=GeoInfo(provider="Hetzner", country="GB", asn="AS24940"),
    )
    db.insert_target(original)

    stored = db.targets()[0]
    assert stored.kind is Kind.EPICBOX
    assert stored.verified is True
    assert stored.enabled is True
    assert stored.source is Source.SEED
    assert stored.geo.provider == "Hetzner"
    assert stored.geo.country == "GB"
    assert stored.geo.asn == "AS24940"
    assert stored.created_at is not None
