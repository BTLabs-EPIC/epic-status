"""Mining pool probe.

Every payload in this file is a real recorded response from the pool it claims to
come from, trimmed only by dropping entries from the `latest` block array. Two pools
implement the same idea with different envelopes and different units for the fee, so
synthetic fixtures here would test the fixtures rather than the adapters.

The two assertions that matter most, because both are silent failures in production:

* The fee unit. One pool says `"0.02"` meaning 2%, the other says `2.5` meaning 2.5%.
  Get it wrong and the board shows 0.02%, which looks like a number rather than like
  a bug.
* That `currentHeight` is never published as a chain height. It is the last block the
  pool *found*, and comparing it to the network tip marks small pools degraded for
  being small. There is a test below that fails if a `height` field reappears.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from epic_status.config import Thresholds
from epic_status.models import PoolProbe, Reason, State
from epic_status.probes.pool import (
    ADAPTERS,
    PoolAdapter,
    _as_float,
    _as_int,
    parse_pool_stats,
)
from epic_status.score import pool_state

# Recorded from https://epic.iniaku.my.id/api/pool/stats on 2026-09-22.
INIAKU: dict[str, Any] = {
    "status": True,
    "data": {
        "poolInfo": {"method": ["pplns", "solo"], "fee": "0.02", "threshold": "p1/s3"},
        "poolStats": {
            "activeUsers": 9,
            "activeWorkers": 25,
            "hashrateRandomX": 600317.8622949035,
            "hashrateProgPow": 8640849593.129318,
            "hashrateCuckoo": 0,
            "onlineRandomX": 11,
            "onlineProgPow": 14,
            "onlineCuckoo": 0,
            "currentHeight": 3721246,
        },
        "poolBlocks": {
            "total": 4093,
            "soloBlocks": 233,
            "poolBlocks": 3783,
            "orphans": 77,
            "paid": 2515,
            "unpaid": 1501,
            "lastFound": 3721246,
            "latest": [
                {
                    "blockHeight": 3721246,
                    "time": 1790062475,
                    "algo": "Progpow",
                    "reward": 0.9889,
                    "hash": "4122824b6ebbfbb45f2ee993b9bc204156dcdd3ac6928ad677475e3f03c68ca9",
                    "is_solo": False,
                    "maturity": "immature",
                    "paid": False,
                }
            ],
        },
    },
}

# Recorded from https://api.epicmine.io/pool/getstats on 2026-09-22. No envelope,
# fee as a number of percent, and the key order differs — all three are why this is
# a separate adapter rather than a tolerant parser.
EPICMINE: dict[str, Any] = {
    "poolInfo": {"method": ["pplns", "solo", "party"], "fee": 2.5, "threshold": 0.1},
    "poolStats": {
        "activeUsers": 118,
        "activeWorkers": 523,
        "hashrateRandomX": 5277677.523545707,
        "hashrateProgPow": 10103547918.168043,
        "hashrateCuckoo": 0.989010989010989,
        "onlineRandomX": 340,
        "onlineProgPow": 181,
        "onlineCuckoo": 2,
        "currentHeight": 3721247,
    },
    "poolBlocks": {
        "lastFound": 3721247,
        "latest": [
            {
                "blockHeight": 3721247,
                "time": 1790062486,
                "algo": "RandomX",
                "hash": "867d9215900d85801b6ab0d14d8a607c76504b0c624ac0b9a8f9fcc19371ad5e",
            }
        ],
    },
}

# What api.epicmine.io returns for a path that does not exist. It is a 200 with a
# valid JSON body, which is why a status code cannot be trusted there.
EPICMINE_INDEX: dict[str, Any] = {
    "endpoints": {
        "/explorer": ["/getsupply", "/getheight"],
        "/pool": ["/getlocations", "/getstats"],
    },
    "method": "GET",
    "version": "1.1",
}


# ------------------------------------------------------------------ real payloads


def test_iniaku_payload_parses() -> None:
    probe = parse_pool_stats(INIAKU, ADAPTERS["iniaku"])
    assert probe.ok
    assert probe.miners == 9
    assert probe.workers == 25
    assert probe.last_block_height == 3721246
    assert probe.reason is Reason.OK


def test_epicmine_payload_parses() -> None:
    probe = parse_pool_stats(EPICMINE, ADAPTERS["epicmine"])
    assert probe.ok
    assert probe.miners == 118
    assert probe.workers == 523
    assert probe.last_block_height == 3721247


@pytest.mark.parametrize(
    ("name", "payload", "expected_percent"),
    [
        # THE POINT. Same real-world fee magnitude, two units. A parser that trusts
        # the number reports one of these as 0.02%.
        ("iniaku", INIAKU, 2.0),
        ("epicmine", EPICMINE, 2.5),
    ],
)
def test_fee_is_normalised_to_percent(
    name: str, payload: dict[str, Any], expected_percent: float
) -> None:
    probe = parse_pool_stats(payload, ADAPTERS[name])
    assert probe.fee_percent == pytest.approx(expected_percent)


def test_last_block_time_becomes_an_aware_datetime() -> None:
    probe = parse_pool_stats(EPICMINE, ADAPTERS["epicmine"])
    assert probe.last_block_at == datetime(2026, 9, 22, 7, 34, 46, tzinfo=UTC)
    # Naive datetimes silently compare wrong against datetime.now(UTC).
    assert probe.last_block_at is not None
    assert probe.last_block_at.tzinfo is not None


# -------------------------------------------------------- the height misreading


def test_pool_probe_publishes_no_chain_height() -> None:
    """`currentHeight` must never be surfaced as a height.

    It is `lastFound` under a misleading name. An earlier version of this module
    exposed it as `height`, the poller copied it into the field a node's chain tip
    lives in, and the board marked a healthy nine-miner pool as lagging the tip.
    """
    assert "height" not in PoolProbe.model_fields
    assert "tip_lag" not in PoolProbe.model_fields


def test_current_height_is_required_but_not_reported() -> None:
    # Required, because its presence is what distinguishes a real stats payload from
    # epicmine's catch-all endpoint index...
    stripped = {
        "poolInfo": EPICMINE["poolInfo"],
        "poolStats": {k: v for k, v in EPICMINE["poolStats"].items() if k != "currentHeight"},
        "poolBlocks": EPICMINE["poolBlocks"],
    }
    assert not parse_pool_stats(stripped, ADAPTERS["epicmine"]).ok

    # ...but never reported, so `lastFound` is the only block height in the result.
    probe = parse_pool_stats(EPICMINE, ADAPTERS["epicmine"])
    assert probe.last_block_height == EPICMINE["poolBlocks"]["lastFound"]


# ------------------------------------------------------------------ the 200 trap


def test_epicmine_endpoint_index_is_not_a_healthy_pool() -> None:
    """A 200 from api.epicmine.io proves nothing.

    Any path returns the endpoint index, so a typo in the adapter path would
    otherwise read as a working pool with every metric null.
    """
    probe = parse_pool_stats(EPICMINE_INDEX, ADAPTERS["epicmine"])
    assert not probe.ok
    assert probe.reason is Reason.BAD_RESPONSE
    assert "poolStats" in (probe.error or "")


def test_each_adapter_rejects_the_other_pool_s_payload() -> None:
    """Applying the wrong adapter must fail loudly rather than half-parse."""
    assert not parse_pool_stats(INIAKU, ADAPTERS["epicmine"]).ok
    assert not parse_pool_stats(EPICMINE, ADAPTERS["iniaku"]).ok


def test_wrapped_adapter_requires_status_true() -> None:
    payload = {"status": False, "data": INIAKU["data"]}
    probe = parse_pool_stats(payload, ADAPTERS["iniaku"])
    assert not probe.ok
    assert "status false" in (probe.error or "")


@pytest.mark.parametrize(
    "payload", [None, [], "text", 0, {}, {"data": None}, {"status": True}]
)
def test_garbage_never_raises(payload: Any) -> None:
    probe = parse_pool_stats(payload, ADAPTERS["iniaku"])
    assert not probe.ok
    assert probe.error


# ------------------------------------------------------------------- coercion


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (5, 5),
        (5.9, 5),
        ("5", 5),
        ("5.9", 5),
        ("", None),
        ("x", None),
        (None, None),
        # True is an int in Python and would read as the number 1.
        (True, None),
        ([], None),
    ],
)
def test_as_int(raw: Any, expected: int | None) -> None:
    assert _as_int(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(2.5, 2.5), (2, 2.0), ("0.02", 0.02), ("x", None), (None, None), (True, None)],
)
def test_as_float(raw: Any, expected: float | None) -> None:
    assert _as_float(raw) == expected


def test_quoted_numbers_are_accepted() -> None:
    """These APIs are inconsistent about quoting, and a quoted count is not a fault."""
    payload = {
        "poolInfo": {"fee": "2.5"},
        "poolStats": {"activeUsers": "9", "activeWorkers": "25", "currentHeight": "100"},
        "poolBlocks": {"lastFound": "100", "latest": []},
    }
    probe = parse_pool_stats(payload, ADAPTERS["epicmine"])
    assert probe.ok
    assert (probe.miners, probe.workers, probe.last_block_height) == (9, 25, 100)


def test_missing_optional_sections_still_parse() -> None:
    """A pool that publishes stats but no block list is degraded data, not an outage."""
    probe = parse_pool_stats(
        {"poolStats": {"currentHeight": 100}}, ADAPTERS["epicmine"]
    )
    assert probe.ok
    assert probe.fee_percent is None
    assert probe.last_block_at is None
    assert probe.last_block_height == 100


@pytest.mark.parametrize("stamp", [0, -1, 10**18])
def test_absurd_block_timestamps_become_none(stamp: int) -> None:
    payload = {
        "poolStats": {"currentHeight": 100},
        "poolBlocks": {"lastFound": 100, "latest": [{"time": stamp}]},
    }
    probe = parse_pool_stats(payload, ADAPTERS["epicmine"])
    assert probe.ok
    assert probe.last_block_at is None


# -------------------------------------------------------------------- adapters


def test_every_adapter_has_a_rooted_path() -> None:
    for name, adapter in ADAPTERS.items():
        assert isinstance(adapter, PoolAdapter), name
        assert adapter.path.startswith("/"), name
        assert not adapter.path.endswith("/"), name


def test_adapter_names_are_stable_identifiers() -> None:
    """They are written into the database and the committed registry, so a rename is
    a migration rather than a tidy-up."""
    for name in ADAPTERS:
        assert name.islower()
        assert name.isidentifier()


# ----------------------------------------------------------------- the verdict


def test_a_reachable_pool_is_healthy() -> None:
    state, reason, detail = pool_state(
        parse_pool_stats(EPICMINE, ADAPTERS["epicmine"]),
        consecutive_failures=0,
        thresholds=Thresholds(),
    )
    assert (state, reason, detail) == (State.HEALTHY, Reason.OK, None)


def test_a_quiet_pool_is_not_penalised() -> None:
    """The regression guard for the whole design.

    iniaku had not found a block for eighteen minutes while epicmine had found one
    seconds earlier. Both were working. Anything that degrades the first is wrong.
    """
    probe = parse_pool_stats(INIAKU, ADAPTERS["iniaku"])
    state, reason, _ = pool_state(
        probe, consecutive_failures=0, thresholds=Thresholds()
    )
    assert state is State.HEALTHY
    assert reason is not Reason.TIP_LAG


def test_failures_are_confirmed_before_being_called_down() -> None:
    th = Thresholds()
    probe = PoolProbe(ok=False, reason=Reason.TIMEOUT, error="timed out")
    assert (
        pool_state(probe, consecutive_failures=1, thresholds=th)[0] is State.DEGRADED
    )
    assert (
        pool_state(
            probe, consecutive_failures=th.down_after_failures, thresholds=th
        )[0]
        is State.DOWN
    )
