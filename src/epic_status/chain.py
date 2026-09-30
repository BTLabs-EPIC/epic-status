"""The chain itself: recent headers, replaced blocks, and whether blocks arrive normally.

Everything else in this service is about hosts. This module is about the one thing
they all serve, and it answers two questions no single node's `get_tip` can:

**Was a block replaced?** A reorg is invisible in any one snapshot — after it, every
node agrees again. It is only visible as a *difference from what was seen before*. So
the canonical header at every recent height is kept, and when the fleet's tip changes
the new chain is walked back, header by header, until it rejoins a block already on
record. Every stored block passed on the way was replaced; the count is the depth.

All of it comes from the public foreign API. `get_tip` names the tip hash, and
`get_header` at a height returns that block's hash, its parent's hash, its timestamp,
the algorithm that solved it and the cumulative per-algorithm difficulty. No owner API,
no peer connection, no node of our own required — any node agreeing on the tip is an
equally good source, which is also why the source is chosen per walk.

**Is the chain moving normally?** Block intervals, the algorithm mix and per-algorithm
difficulty over the recent window, computed from the same headers.

What this cannot see: a reorg that happens and is undone entirely between two sweeps,
since the replaced block was never observed as the tip; and anything deeper than the
walk limit, which is reported as "at least" that deep rather than guessed at.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from .db import Database
from .models import AlgoActivity, BlockHeader, Chain, ChainActivity, NodeProbe

HeaderFetch = Callable[[int], Awaitable[BlockHeader | None]]

#: How the header's `proof` names each algorithm, how a reader knows it, and which
#: `total_difficulty` counter belongs to it. `Cuckoo` on Epic mainnet is Cuckatoo31+.
ALGORITHMS: dict[str, tuple[str, str]] = {
    "RandomX": ("RandomX", "randomx"),
    "ProgPow": ("ProgPow", "progpow"),
    "Cuckoo": ("Cuckatoo", "cuckatoo"),
}

TARGET_INTERVAL_S = 60
"""Epic's block target. Used to label the panel, not to judge anything."""


@dataclass(frozen=True)
class Reorg:
    """A replaced run of blocks, as observed from outside."""

    chain: Chain
    fork_height: int
    """The lowest replaced height. The block below it is the common ancestor."""
    depth: int
    depth_is_lower_bound: bool
    """True when the walk hit its limit before rejoining the stored chain."""
    old_hash: str
    """What used to be the block at `fork_height`."""
    new_hash: str
    tip_height: int


def canonical_tip(probes: Iterable[NodeProbe]) -> tuple[int, str] | None:
    """The fleet's tip as (height, hash): the highest height reported, and the hash
    most nodes at that height agree on.

    None when the nodes at the top disagree evenly. That is an orphan race or a fork in
    progress, which `score.ForkDetector` reports; recording either side as canonical
    would make the loser look like a reorg one sweep later.
    """
    reports = [
        (p.height, p.tip_hash)
        for p in probes
        if p.ok and p.height is not None and p.tip_hash
    ]
    if not reports:
        return None
    top = max(height for height, _ in reports)
    votes = Counter(h for height, h in reports if height == top).most_common()
    if len(votes) > 1 and votes[0][1] == votes[1][1]:
        return None
    return top, votes[0][0]


class ChainTracker:
    """Keeps the recent canonical headers for one chain and notices replacements.

    Stateless apart from the database, so a restart resumes exactly where it stopped
    and a reorg that happened while the service was down is still noticed — as long
    as it is within `walk_limit` of the tip when the service comes back.
    """

    def __init__(
        self,
        db: Database,
        chain: Chain,
        *,
        window: int = 1440,
        walk_limit: int = 30,
        backfill_per_run: int = 10,
    ) -> None:
        self.db = db
        self.chain = chain
        self.window = window
        """Heights kept. 1,440 is a day at the 60-second target."""
        self.walk_limit = walk_limit
        self.backfill_per_run = backfill_per_run
        """Headers fetched per sync to fill the window. At one sync per sweep this is
        two requests a second to one node until the day is filled, once, and then
        nothing — the window is persisted."""

    async def sync(
        self, fetch: HeaderFetch, tip_height: int, tip_hash: str
    ) -> Reorg | None:
        """Record the chain up to `tip_hash`, returning the reorg that got it there,
        if any. `fetch` must read from a node whose tip is `tip_hash`."""
        stored = self.db.headers_between(self.chain, tip_height, tip_height)
        reorg: Reorg | None = None
        if stored.get(tip_height) is None or stored[tip_height].hash != tip_hash:
            reorg = await self._walk(fetch, tip_height, tip_hash)
        await self._backfill(fetch, tip_height)
        return reorg

    async def _walk(
        self, fetch: HeaderFetch, tip_height: int, tip_hash: str
    ) -> Reorg | None:
        """Fetch back from the new tip until the chain rejoins what is on record.

        Stops at the first height whose parent is the stored block (rejoined), or is
        missing from a record that does reach that high — a gap, where there is nothing
        to compare with. The gap case is resolved in favour of saying nothing: an absent
        record is not evidence of a replacement.

        Aborts without writing if the source moves to a different tip mid-walk. Half a
        walk could interleave two branches in the table, and the next sweep will walk
        again from the new tip anyway.
        """
        known = self.db.headers_between(
            self.chain, tip_height - self.walk_limit - 1, tip_height
        )
        fetched: list[BlockHeader] = []
        replaced: list[tuple[int, str]] = []
        height, expected = tip_height, tip_hash
        # Heights above the newest record are simply new blocks — several arrive between
        # two syncs whenever blocks come fast — so a missing parent there means "keep
        # walking", and only a missing parent at or below it means "nothing to compare".
        newest_known = max(known, default=-1)
        rejoined = False
        while len(fetched) < self.walk_limit:
            header = await fetch(height)
            if header is None or header.hash != expected:
                return None
            old = known.get(height)
            if old is not None and old.hash != header.hash:
                replaced.append((height, old.hash))
            fetched.append(header)
            parent = known.get(height - 1)
            if parent is not None and parent.hash == header.previous:
                rejoined = True
                break
            if parent is None and height - 1 <= newest_known:
                rejoined = True
                break
            if newest_known < 0:
                # Nothing on record near the tip at all: a first run, or back from an
                # outage longer than the walk. There is nothing to compare against,
                # and the backfill fills the window without walking it.
                rejoined = True
                break
            height, expected = height - 1, header.previous

        self.db.put_headers(self.chain, fetched, keep=self.window)
        if not replaced:
            return None
        fork_height, old_hash = min(replaced)
        new_hash = next(h.hash for h in fetched if h.height == fork_height)
        return Reorg(
            chain=self.chain,
            fork_height=fork_height,
            depth=len(replaced),
            depth_is_lower_bound=not rejoined,
            old_hash=old_hash,
            new_hash=new_hash,
            tip_height=tip_height,
        )

    async def _backfill(self, fetch: HeaderFetch, tip_height: int) -> None:
        """Fill missing heights in the window, newest first, a few per call.

        Newest first so a gap after an outage closes from the tip down, which is the
        end the panel reads. A fetched header that does not link to the stored block
        above it is from a different branch and is skipped rather than stored.
        """
        low = max(0, tip_height - self.window)
        have = self.db.headers_between(self.chain, low, tip_height)
        missing = [h for h in range(tip_height, low - 1, -1) if h not in have]
        got: list[BlockHeader] = []
        for height in missing[: self.backfill_per_run]:
            header = await fetch(height)
            if header is None:
                break
            child = have.get(height + 1)
            if child is not None and child.previous != header.hash:
                continue
            got.append(header)
            have[height] = header
        self.db.put_headers(self.chain, got, keep=self.window)

    # --------------------------------------------------------------- activity

    def newest(self) -> BlockHeader | None:
        headers = self.db.recent_headers(self.chain, 1)
        return headers[0] if headers else None

    def activity(self, *, reorg_depths: list[int]) -> ChainActivity | None:
        """The panel's numbers, over the contiguous run of headers ending at the newest.

        Contiguous because an interval across a gap in the record is not an interval
        between two blocks. None below three headers: two points make one interval,
        and one interval is an anecdote.
        """
        run = _contiguous(self.db.recent_headers(self.chain, self.window + 1))
        if len(run) < 3:
            return None
        newest, oldest = run[0], run[-1]
        gaps = [
            (int((run[i].mined_at - run[i + 1].mined_at).total_seconds()), run[i].height)
            for i in range(len(run) - 1)
        ]
        intervals = [seconds for seconds, _ in gaps]
        longest, longest_at = max(gaps)
        # The oldest header is the base of the window and its own block is outside it:
        # counting its algorithm would count one block the intervals do not cover.
        counted = Counter(h.proof for h in run[:-1] if h.proof)
        total = sum(counted.values())

        algos: list[AlgoActivity] = []
        for proof, blocks in counted.most_common():
            label, key = ALGORITHMS.get(proof, (proof, ""))
            current = _step(run[0], run[1], key)
            base = _step(run[-2], run[-1], key)
            change = (current / base - 1.0) if current and base else None
            algos.append(
                AlgoActivity(
                    algo=label,
                    blocks=blocks,
                    share=blocks / total if total else 0.0,
                    difficulty=current,
                    difficulty_change=change,
                )
            )

        return ChainActivity(
            window_blocks=len(run) - 1,
            window_s=int((newest.mined_at - oldest.mined_at).total_seconds()),
            median_interval_s=int(statistics.median(intervals)),
            mean_interval_s=int(statistics.fmean(intervals)),
            longest_gap_s=longest,
            longest_gap_height=longest_at,
            target_interval_s=TARGET_INTERVAL_S,
            algos=algos,
            reorgs_24h=len(reorg_depths),
            deepest_reorg_24h=max(reorg_depths, default=0),
        )


def _contiguous(headers: list[BlockHeader]) -> list[BlockHeader]:
    """The newest-first prefix in which each header is the parent of the one before."""
    run: list[BlockHeader] = headers[:1]
    for header in headers[1:]:
        if header.height != run[-1].height - 1 or header.hash != run[-1].previous:
            break
        run.append(header)
    return run


def _step(child: BlockHeader, parent: BlockHeader, key: str) -> int | None:
    """One algorithm's difficulty at `child`: the step in its cumulative counter."""
    if not key:
        return None
    after = getattr(child.total_difficulty, key, None)
    before = getattr(parent.total_difficulty, key, None)
    if not isinstance(after, int) or not isinstance(before, int) or after <= before:
        return None
    return after - before
