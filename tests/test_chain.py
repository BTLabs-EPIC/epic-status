"""Reorg detection and the chain panel, against a scripted chain.

Every test builds branches of headers in memory and serves them through the same
`fetch(height)` callable the poller hands the tracker, so the walk, the backfill and the
database round-trip are all real. Nothing here touches the network.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from epic_status.chain import ChainTracker, canonical_tip
from epic_status.db import Database
from epic_status.models import BlockHeader, Chain, Difficulty, NodeProbe

GENESIS_TIME = datetime(2026, 9, 1, tzinfo=UTC)


def build(
    start: int,
    count: int,
    *,
    branch: str,
    parent: str,
    interval_s: int = 60,
    proofs: tuple[str, ...] = ("RandomX", "ProgPow", "Cuckoo"),
) -> list[BlockHeader]:
    """`count` linked headers from `start`, on a branch whose hashes carry its name."""
    out: list[BlockHeader] = []
    previous = parent
    for i in range(count):
        height = start + i
        header = BlockHeader(
            height=height,
            hash=f"{branch}-{height}",
            previous=previous,
            mined_at=GENESIS_TIME + timedelta(seconds=interval_s * height),
            proof=proofs[height % len(proofs)],
            total_difficulty=Difficulty(
                randomx=1000 * height, progpow=2000 * height, cuckatoo=10 * height
            ),
        )
        out.append(header)
        previous = header.hash
    return out


def fetcher(headers: list[BlockHeader]):  # type: ignore[no-untyped-def]
    by_height = {h.height: h for h in headers}

    async def fetch(height: int) -> BlockHeader | None:
        return by_height.get(height)

    return fetch


def tracker(db: Database, **kwargs: int) -> ChainTracker:
    return ChainTracker(db, Chain.MAINNET, **{"window": 50, "backfill_per_run": 100, **kwargs})


async def test_first_sync_records_without_claiming_a_reorg(db: Database) -> None:
    chain = build(1, 20, branch="a", parent="genesis")
    t = tracker(db)

    assert await t.sync(fetcher(chain), 20, "a-20") is None
    assert len(db.headers_between(Chain.MAINNET, 0, 20)) == 20


async def test_a_growing_chain_is_not_a_reorg(db: Database) -> None:
    chain = build(1, 30, branch="a", parent="genesis")
    t = tracker(db)
    await t.sync(fetcher(chain[:20]), 20, "a-20")

    for height in range(21, 31):
        assert await t.sync(fetcher(chain), height, f"a-{height}") is None


async def test_a_replaced_tip_is_a_depth_one_reorg(db: Database) -> None:
    """The orphan race every PoW chain has: the block seen at 20 lost to another."""
    main = build(1, 20, branch="a", parent="genesis")
    t = tracker(db)
    await t.sync(fetcher(main), 20, "a-20")

    winner = main[:19] + build(20, 2, branch="b", parent="a-19")
    reorg = await t.sync(fetcher(winner), 21, "b-21")

    assert reorg is not None
    assert (reorg.depth, reorg.fork_height) == (1, 20)
    assert reorg.old_hash == "a-20" and reorg.new_hash == "b-20"
    assert not reorg.depth_is_lower_bound
    assert db.headers_between(Chain.MAINNET, 20, 20)[20].hash == "b-20"


async def test_depth_is_the_number_of_blocks_replaced(db: Database) -> None:
    main = build(1, 20, branch="a", parent="genesis")
    t = tracker(db)
    await t.sync(fetcher(main), 20, "a-20")

    winner = main[:17] + build(18, 5, branch="b", parent="a-17")
    reorg = await t.sync(fetcher(winner), 22, "b-22")

    assert reorg is not None
    assert (reorg.depth, reorg.fork_height) == (3, 18)


async def test_a_reorg_deeper_than_the_walk_is_reported_as_a_lower_bound(
    db: Database,
) -> None:
    main = build(1, 40, branch="a", parent="genesis")
    t = tracker(db, walk_limit=5)
    await t.sync(fetcher(main), 40, "a-40")

    winner = main[:20] + build(21, 20, branch="b", parent="a-20")
    reorg = await t.sync(fetcher(winner), 40, "b-40")

    assert reorg is not None
    assert reorg.depth_is_lower_bound
    assert reorg.depth == 5


async def test_a_source_that_moves_mid_walk_writes_nothing(db: Database) -> None:
    """Half a walk could interleave two branches in the record."""
    main = build(1, 20, branch="a", parent="genesis")
    t = tracker(db, backfill_per_run=0)
    await t.sync(fetcher(main), 20, "a-20")

    # Asked for the tip b-21, the node now answers with something else.
    moved = main[:19] + build(20, 2, branch="c", parent="a-19")
    assert await t.sync(fetcher(moved), 21, "b-21") is None
    assert 21 not in db.headers_between(Chain.MAINNET, 21, 21)


async def test_several_new_blocks_since_the_last_sync_are_walked(db: Database) -> None:
    """Two blocks can land between syncs. The walk must reach the record to know
    whether the older of them replaced anything."""
    main = build(1, 25, branch="a", parent="genesis")
    t = tracker(db, backfill_per_run=0)
    await t.sync(fetcher(main[:20]), 20, "a-20")

    assert await t.sync(fetcher(main), 25, "a-25") is None
    assert len(db.headers_between(Chain.MAINNET, 21, 25)) == 5


async def test_a_gap_after_an_outage_is_not_mistaken_for_a_reorg(db: Database) -> None:
    main = build(1, 60, branch="a", parent="genesis")
    t = tracker(db, backfill_per_run=0)
    await t.sync(fetcher(main[:10]), 10, "a-10")

    assert await t.sync(fetcher(main), 60, "a-60") is None


def test_canonical_tip_takes_the_majority_at_the_top() -> None:
    probes = [
        NodeProbe(ok=True, height=10, tip_hash="x"),
        NodeProbe(ok=True, height=10, tip_hash="x"),
        NodeProbe(ok=True, height=10, tip_hash="y"),
        NodeProbe(ok=True, height=9, tip_hash="z"),
        NodeProbe(ok=False),
    ]
    assert canonical_tip(probes) == (10, "x")


def test_canonical_tip_refuses_an_even_split() -> None:
    probes = [
        NodeProbe(ok=True, height=10, tip_hash="x"),
        NodeProbe(ok=True, height=10, tip_hash="y"),
    ]
    assert canonical_tip(probes) is None


async def test_activity_reads_intervals_algorithms_and_difficulty(db: Database) -> None:
    chain = build(1, 31, branch="a", parent="genesis", interval_s=60)
    t = tracker(db)
    await t.sync(fetcher(chain), 31, "a-31")

    activity = t.activity(reorg_depths=[1, 3])

    assert activity is not None
    assert activity.window_blocks == 30
    assert activity.median_interval_s == 60
    assert activity.reorgs_24h == 2 and activity.deepest_reorg_24h == 3
    names = {a.algo for a in activity.algos}
    assert names == {"RandomX", "ProgPow", "Cuckatoo"}
    assert sum(a.blocks for a in activity.algos) == 30
    randomx = next(a for a in activity.algos if a.algo == "RandomX")
    assert randomx.difficulty == 1000
    assert randomx.difficulty_change == 0.0


async def test_activity_needs_three_headers(db: Database) -> None:
    t = tracker(db)
    await t.sync(fetcher(build(1, 2, branch="a", parent="genesis")), 2, "a-2")
    assert t.activity(reorg_depths=[]) is None
