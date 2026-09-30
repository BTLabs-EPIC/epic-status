"""Login, sessions, CSRF and the review gate.

The board is public and read-only. `/admin` is not: approving a submission makes this
service start probing a stranger's host and publishes it to every consumer of the API. The
tests below pin the properties that make that safe to expose, and each one corresponds to a
way the obvious implementation would have been wrong.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from epic_status.admin import (
    MAX_ATTEMPTS,
    SESSION_TTL_S,
    Sessions,
    check_credentials,
    hash_password,
    verify_password,
)
from epic_status.config import Settings
from epic_status.db import Database
from epic_status.models import Check, Kind


# ----------------------------------------------------------------- passwords


def test_hash_verifies() -> None:
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)


def test_wrong_password_fails() -> None:
    stored = hash_password("one")
    assert not verify_password("two", stored)


def test_every_hash_has_its_own_salt() -> None:
    """Two identical passwords must not produce identical stored values, or the hash file
    tells an attacker which accounts share a password."""
    assert hash_password("same") != hash_password("same")


def test_parameters_travel_with_the_digest() -> None:
    """Cost is read from the stored string, not from the module constants, so raising the
    work factor later does not invalidate hashes already deployed."""
    stored = hash_password("x")
    scheme, n, r, p, _salt, _digest = stored.split("$")
    assert scheme == "scrypt"
    assert int(n) >= 2**14
    assert (int(r), int(p)) == (8, 1)


@pytest.mark.parametrize(
    "broken",
    [
        "",
        "notascheme$1$2$3$4$5",
        "scrypt$notanumber$8$1$AAAA$BBBB",
        "scrypt$16384$8$1$!!!$!!!",
        "plaintextpassword",
    ],
)
def test_malformed_hash_fails_closed(broken: str) -> None:
    """A misconfigured `ADMIN_PASSWORD_HASH` must read as "wrong password", never as a
    traceback — and must never accidentally authenticate."""
    assert not verify_password("anything", broken)


def test_credentials_require_both_halves() -> None:
    stored = hash_password("pw")
    assert check_credentials(
        user="admin", password="pw", expected_user="admin", stored_hash=stored
    )
    assert not check_credentials(
        user="root", password="pw", expected_user="admin", stored_hash=stored
    )
    assert not check_credentials(
        user="admin", password="nope", expected_user="admin", stored_hash=stored
    )


# ------------------------------------------------------------------ sessions


def test_session_round_trip() -> None:
    s = Sessions()
    session = s.create("admin")
    assert s.get(session.token) is session


def test_unknown_token_is_not_a_session() -> None:
    s = Sessions()
    s.create("admin")
    assert s.get("made up") is None
    assert s.get(None) is None


def test_session_tokens_are_unguessable() -> None:
    s = Sessions()
    tokens = {s.create("admin").token for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(t) >= 32 for t in tokens)


def test_csrf_differs_from_the_session_token() -> None:
    """Reusing the session token as the CSRF token would put it in the page body, where a
    markup-injection bug turns into session theft."""
    session = Sessions().create("admin")
    assert session.csrf != session.token


def test_expired_session_is_refused_and_forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Sessions()
    session = s.create("admin")

    import epic_status.admin as mod

    base = mod.time.monotonic()
    monkeypatch.setattr(mod.time, "monotonic", lambda: base + SESSION_TTL_S + 1)
    assert s.get(session.token) is None
    # Refused once and dropped, not left in the dict to be re-checked forever.
    monkeypatch.setattr(mod.time, "monotonic", lambda: base)
    assert s.get(session.token) is None


def test_logout_revokes_immediately() -> None:
    """The reason sessions live in a dict rather than a signed cookie: a signed cookie
    cannot be taken back."""
    s = Sessions()
    session = s.create("admin")
    s.destroy(session.token)
    assert s.get(session.token) is None


def test_csrf_must_match() -> None:
    s = Sessions()
    session = s.create("admin")
    assert s.valid_csrf(session, session.csrf)
    assert not s.valid_csrf(session, "wrong")
    assert not s.valid_csrf(session, "")
    assert not s.valid_csrf(session, None)


# ---------------------------------------------------------------- rate limit


def test_lockout_after_repeated_failures() -> None:
    s = Sessions()
    for _ in range(MAX_ATTEMPTS):
        assert not s.locked_out("1.2.3.4")
        s.record_failure("1.2.3.4")
    assert s.locked_out("1.2.3.4")


def test_lockout_is_per_address() -> None:
    s = Sessions()
    for _ in range(MAX_ATTEMPTS):
        s.record_failure("1.2.3.4")
    assert s.locked_out("1.2.3.4")
    assert not s.locked_out("5.6.7.8")


def test_success_clears_the_counter() -> None:
    """Otherwise an attacker's failed guesses against a shared proxy address lock out the
    legitimate admin behind it, turning the rate limit into a denial of service."""
    s = Sessions()
    for _ in range(MAX_ATTEMPTS - 1):
        s.record_failure("1.2.3.4")
    s.clear_failures("1.2.3.4")
    for _ in range(MAX_ATTEMPTS - 1):
        s.record_failure("1.2.3.4")
    assert not s.locked_out("1.2.3.4")


# -------------------------------------------------------------- the gate itself


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "s.db", prober_id="test")
    database.apply_schema()
    return database


def _submit(db: Database, host: str, status: str = "verified") -> int:
    sid = db.insert_submission(
        kind=Kind.NODE,
        host=host,
        endpoint=f"https://{host}",
        operator="Example",
        submitter_hash="deadbeef",
        next_probe_at=datetime.now(UTC) + timedelta(days=1),
    )
    assert sid is not None
    db.update_submission(
        sid,
        probes_passed=3,
        probes_attempted=3,
        next_probe_at=None,
        status=status,
        last_error=None,
    )
    return sid


def test_verified_submission_is_not_on_the_board(db: Database) -> None:
    """The whole point of the change. A host that passed its probes is evidence awaiting a
    decision, not a target — it used to insert itself and appear publicly with no human in
    the loop."""
    _submit(db, "node.example.org")
    assert db.submission_counts()["verified"] == 1
    assert db.targets() == []


def test_review_promotes_only_on_approval(db: Database) -> None:
    sid = _submit(db, "node.example.org")
    db.review_submission(sid, status="accepted", note="approved")
    row = db.submission(sid)
    assert row is not None
    assert row["status"] == "accepted"
    assert row["reviewed_at"] is not None


def test_rejection_records_a_decision_without_a_target(db: Database) -> None:
    sid = _submit(db, "bad.example.org")
    db.review_submission(sid, status="rejected", note="rejected")
    row = db.submission(sid)
    assert row is not None
    assert row["status"] == "rejected"
    assert db.targets() == []


def test_review_does_not_reset_the_evidence(db: Database) -> None:
    """A reviewer reads the probe counters to decide. Recording the decision must not
    overwrite what they just read, which is why review is a separate method from the
    validator's update."""
    sid = _submit(db, "node.example.org")
    before = db.submission(sid)
    assert before is not None
    db.review_submission(sid, status="accepted", note="approved")
    after = db.submission(sid)
    assert after is not None
    assert after["probes_passed"] == before["probes_passed"]
    assert after["probes_attempted"] == before["probes_attempted"]


def test_counts_cover_every_status(db: Database) -> None:
    counts = db.submission_counts()
    assert set(counts) == {"pending", "verified", "accepted", "rejected"}


# ------------------------------------------------------------------- settings


def test_admin_is_off_by_default() -> None:
    """No default credential. With no hash configured the routes are never registered and
    /admin is a 404 rather than a login form advertising the surface."""
    assert Settings().admin_password_hash == ""



# ----------------------------------------------------- editing existing records


def _target(db: Database, host: str = "node.example.org") -> int:
    from epic_status.models import Source, Target

    return db.insert_target(
        Target(
            kind=Kind.NODE,
            slug=host,
            endpoint=f"https://{host}",
            display_host=host,
            operator="Old Operator",
            source=Source.SEED,
        )
    )


def test_editable_fields_round_trip(db: Database) -> None:
    tid = _target(db)
    db.update_target_fields(
        tid, operator="New Operator", label="A label", notes="internal", verified=True,
        enabled=True,
    )
    t = db.target(tid)
    assert t is not None
    assert (t.operator, t.label, t.notes, t.verified) == (
        "New Operator",
        "A label",
        "internal",
        True,
    )


def test_blank_clears_rather_than_storing_empty(db: Database) -> None:
    """An empty form field means "no value", not the empty string — otherwise the board
    renders a zero-width operator instead of falling back to "operator not stated"."""
    tid = _target(db)
    db.update_target_fields(
        tid, operator="", label="", notes="", verified=False, enabled=True
    )
    t = db.target(tid)
    assert t is not None
    assert t.operator is None
    assert t.label is None


def test_disabling_removes_a_target_from_the_sweep(db: Database) -> None:
    tid = _target(db)
    db.update_target_fields(
        tid, operator=None, label=None, notes=None, verified=False, enabled=False
    )
    assert db.targets() == []
    # Still listed for an admin, or the record could never be turned back on.
    assert len(db.targets(enabled_only=False)) == 1


def test_geo_override_wins_over_the_registry(db: Database) -> None:
    """The reason this exists: RDAP says this project's own London host is in India."""
    from epic_status.models import GeoInfo

    tid = _target(db)
    db.set_geo(tid, GeoInfo(country="IN", provider="Hostinger NOC", city=None))
    db.set_geo_overrides(tid, country="gb", provider="Hostinger", city="London")

    t = db.target(tid)
    assert t is not None
    assert t.geo.country == "IN"           # what the registry said, preserved
    assert t.geo.display_country == "GB"   # uppercased, and what the page shows
    assert t.geo.display_provider == "Hostinger"
    assert t.geo.display_city == "London"


def test_clearing_an_override_restores_the_registry(db: Database) -> None:
    """The only way back from a correction that turned out to be wrong."""
    from epic_status.models import GeoInfo

    tid = _target(db)
    db.set_geo(tid, GeoInfo(country="IN", provider="Hostinger NOC"))
    db.set_geo_overrides(tid, country="GB", provider="", city="")
    db.set_geo_overrides(tid, country="", provider="", city="")

    t = db.target(tid)
    assert t is not None
    assert t.geo.display_country == "IN"
    assert t.geo.display_provider == "Hostinger NOC"


def test_overrides_survive_a_registry_refresh(db: Database) -> None:
    """The weekly RDAP pass must not undo a correction. Without this the admin fixes the
    same country every seven days."""
    from epic_status.geo import merge
    from epic_status.models import GeoInfo

    tid = _target(db)
    db.set_geo(tid, GeoInfo(country="IN", provider="Hostinger NOC"))
    db.set_geo_overrides(tid, country="GB", provider="Hostinger", city="London")

    stored = db.target(tid)
    assert stored is not None
    refreshed = merge(stored.geo, GeoInfo(country="IN", provider="Hostinger NOC"))
    db.set_geo(tid, refreshed)

    t = db.target(tid)
    assert t is not None
    assert t.geo.display_country == "GB"
    assert t.geo.display_provider == "Hostinger"
    assert t.geo.display_city == "London"


def test_identity_is_not_editable(db: Database) -> None:
    """`checks.target_id` points at this row. Repointing an endpoint in place would
    attribute one host's measurement history to another, so identity is deliberately absent
    from the edit surface."""
    import inspect

    source = inspect.signature(Database.update_target_fields).parameters
    assert "slug" not in source
    assert "endpoint" not in source
    assert "kind" not in source



# --------------------------------------------- verified, removal, and the counts


def test_verified_maps_to_a_listing(db: Database) -> None:
    """`verified` replaced a flag called `ours`, which told a reader something about the
    instance operator rather than something about the host."""
    tid = _target(db)
    db.update_target_fields(
        tid, operator=None, label=None, notes=None, verified=True, enabled=True
    )
    t = db.target(tid)
    assert t is not None
    assert t.verified is True
    assert t.listing == "official"


def test_unverified_is_community_not_a_judgement(db: Database) -> None:
    tid = _target(db)
    t = db.target(tid)
    assert t is not None
    assert t.verified is False
    assert t.listing == "community"


def test_verified_survives_the_historical_column_name(db: Database) -> None:
    """The SQL column is still `ours`. The round trip has to work through it, because
    renaming the column would mean rebuilding the table and dropping the values in it."""
    tid = _target(db)
    db.update_target_fields(
        tid, operator=None, label=None, notes=None, verified=True, enabled=True
    )
    raw = db.conn.execute("SELECT ours FROM targets WHERE id = ?", (tid,)).fetchone()
    assert raw["ours"] == 1
    reloaded = db.target(tid)
    assert reloaded is not None and reloaded.verified is True


def test_admin_removal_deletes_any_target(db: Database) -> None:
    tid = _target(db)
    assert db.delete_target_admin(tid) is True
    assert db.target(tid) is None
    assert db.targets(enabled_only=False) == []


def test_admin_removal_reports_whether_it_did_anything(db: Database) -> None:
    """The dashboard reported "removed" for a seed target it had not touched, because it
    called the narrow automatic delete. An operator believing a host is gone when it is not
    is the worst available outcome, so the method returns what happened."""
    assert db.delete_target_admin(99999) is False


def test_automatic_removal_cannot_touch_a_host_with_history(db: Database) -> None:
    """The self-deleting-dead-submission rule must never reach a target that has ever been
    up. The conditions live in the statement, not in the caller."""
    tid = _target(db)
    db.delete_target(tid)
    assert db.target(tid) is not None


def test_disable_is_the_reversible_alternative_to_removal(db: Database) -> None:
    """Removal cascades into `checks` and destroys history nothing can rebuild. Disabling
    stops the probing and keeps the record, which is what an operator wants almost every
    time — so both have to work and the difference has to be real."""
    tid = _target(db)
    db.update_target_fields(
        tid, operator=None, label=None, notes=None, verified=False, enabled=False
    )
    assert db.target(tid) is not None
    assert db.targets() == []

    db.update_target_fields(
        tid, operator=None, label=None, notes=None, verified=False, enabled=True
    )
    assert len(db.targets()) == 1


def test_on_board_count_is_the_published_fleet_not_approved_submissions(
    db: Database,
) -> None:
    """The dashboard read 0 for "on the board" while eight hosts were being published: it
    was counting submissions with status `accepted`, and every seed target was approved by
    being committed to the registry rather than by passing through this queue."""
    _target(db, "a.example")
    _target(db, "b.example")
    _submit(db, "c.example", status="verified")

    assert len(db.targets()) == 2
    assert db.submission_counts()["accepted"] == 0
