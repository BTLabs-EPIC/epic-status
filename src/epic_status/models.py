"""Domain types.

Everything that crosses a trust boundary — a probe response from a third-party
host, a submission from the public form, a row out of SQLite — becomes one of
these before any other module sees it. Nothing downstream handles a raw dict.

The one modelling decision worth flagging: a target's endpoint is a *URL*, not a
host and port. Public Epic nodes are deployed both ways in the wild — some expose
the node's own listener directly on 3413 (node.epiccash.com), others keep the
listener on loopback and front it with nginx on 443 (node.btlabs.uk). A host:port
model silently fails on the second, which is the *better* deployment.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class Kind(str, enum.Enum):
    NODE = "node"
    EPICBOX = "epicbox"
    POOL = "pool"
    """A mining pool's public stats API. Monitored for reachability and for whether
    its own node is at the chain tip — a pool mining on a stale tip is the failure
    that costs miners money, and it looks identical to a healthy pool from outside.

    Unlike the other two kinds there is no protocol here: every pool exposes a
    different JSON shape, so each one needs a named adapter in `probes.pool` and is
    integrated by hand rather than auto-promoted from the submission form."""


class Chain(str, enum.Enum):
    """Which Epic Cash network a target belongs to.

    A second chain is not a filter over one fleet, it is a second fleet that happens
    to be rendered by the same code. Floonet's tip is in the hundreds while mainnet's
    is in the millions, so every comparison that asks "is this host keeping up?" —
    `score.fleet_tip`, the lag thresholds, fork detection, the health score — has to
    be scoped to one chain or it reports the smaller network as catastrophically
    behind the larger one. That is the whole reason this enum exists rather than a
    boolean `testnet` flag: the code reads better when the fleet is chosen than when
    it is excluded.

    Deliberately not called `Network`. `Snapshot.network` already means "the summary
    of this fleet", and `GeoInfo.network_name` means "the RDAP handle for the IP
    block". A third meaning of the same word in the same models file would be
    guaranteed to be misread. `NetworkSummary.chain` has been the name for this
    concept since the first commit — it was simply hardcoded to `"mainnet"` and never
    assigned. This fills it in.
    """

    MAINNET = "mainnet"
    FLOONET = "floonet"
    """Epic Cash's test network. Its own genesis, its own difficulty, its own tip."""

    @property
    def label(self) -> str:
        """The name as a reader should see it, so the casing lives in one place
        rather than being re-capitalised in each template that prints it."""
        return "Mainnet" if self is Chain.MAINNET else "Floonet"


class IPv6(str, enum.Enum):
    """Whether a host can be used over IPv6, as measured rather than as advertised."""

    YES = "yes"
    """Has an AAAA record and answered the same probe over it."""
    UNREACHABLE = "unreachable"
    """Publishes an AAAA record that does not answer — worse than none, because a
    client that prefers IPv6 tries it first and waits for the timeout."""
    ABSENT = "absent"
    """No AAAA record."""


class Source(str, enum.Enum):
    """Where a target came from, which decides whether it may be auto-removed."""

    SEED = "seed"
    """From the committed config file. Never auto-removed: `node.epiccash.com`
    being down is the single most important thing this page can report, so it
    must not vanish for being down."""

    SUBMITTED = "submitted"
    """From the public form. Self-removes after sustained total failure."""


class State(str, enum.Enum):
    """Three states, deliberately.

    A two-state light reports our own network blips as the operator's outage, and
    shows a node 5,000 blocks behind the chain as perfectly healthy. Both are
    visible to the operators being reported on.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"
    """Never probed yet. Distinct from down, and rendered as such."""


class Reason(str, enum.Enum):
    """Why a target is not healthy. Rendered verbatim, so it has to read well."""

    OK = "ok"
    TIP_LAG = "tip_lag"
    FORKED = "forked"
    API_RESTRICTED = "api_restricted"
    """HTTP 401. The node is up and participating; its API is simply not public.
    Reporting this as down is wrong and generates complaints from operators."""
    P2P_ONLY = "p2p_only"
    TIMEOUT = "timeout"
    DNS = "dns"
    TLS = "tls"
    REFUSED = "refused"
    BAD_RESPONSE = "bad_response"
    RATE_LIMITED = "rate_limited"
    CERT_EXPIRING = "cert_expiring"
    """No longer produced. Kept because `checks.reason` is a TEXT column with months
    of rows in it, and parsing a stored value back through this enum has to keep
    working for history that was written while an approaching expiry was still a
    state. Relay certificate expiry is now a marker on the TLS column, not a verdict —
    see `score.epicbox_state`."""
    NEVER_SEEN = "never_seen"


# --------------------------------------------------------------------------- probes


class Difficulty(BaseModel):
    """Epic is multi-algorithm, so `total_difficulty` is an object, not a scalar.

    Verified against mainnet: the four keys are cuckaroo, cuckatoo, progpow and
    randomx. Treating it as an integer — which every Grin-derived example does —
    raises a TypeError on the first real response.
    """

    model_config = ConfigDict(extra="allow")

    cuckaroo: int | None = None
    cuckatoo: int | None = None
    progpow: int | None = None
    randomx: int | None = None

    def fingerprint(self) -> tuple[int | None, ...]:
        return (self.cuckaroo, self.cuckatoo, self.progpow, self.randomx)


class NodeProbe(BaseModel):
    """Result of one `get_tip` against one node."""

    ok: bool
    latency_ms: int | None = None
    height: int | None = None
    tip_hash: str | None = None
    prev_hash: str | None = None
    difficulty: Difficulty | None = None
    http_status: int | None = None
    reason: Reason = Reason.OK
    error: str | None = None
    """Short, human-readable, and shown to the operator so they can self-diagnose
    without contacting us. Never a raw traceback."""


class EpicboxProbe(BaseModel):
    """Result of one WebSocket handshake against one relay.

    The relay pushes `{"type":"Challenge","str":...}` unprompted on connect, so a
    single frame read with no bytes sent proves TLS, the reverse proxy, the relay
    process and a responsive event loop. Verified against mainnet.
    """

    ok: bool
    latency_ms: int | None = None
    challenge_seen: bool = False
    protocol_version: str | None = None
    cert_expires_in_days: int | None = None
    reason: Reason = Reason.OK
    error: str | None = None


class PoolProbe(BaseModel):
    """Result of one GET against one pool's stats API.

    Deliberately thin. A pool's hashrate is a big, constantly-moving number that
    says nothing about whether the pool is working, so it is not collected.

    `last_block_height` is the last block the pool FOUND, not its chain tip — the
    APIs' `currentHeight` is the same number, despite the name. It must not be
    compared against the fleet tip; see the note in probes.pool.

    `fee_percent` is always a percentage, whatever unit the pool reported it in.
    """

    ok: bool
    latency_ms: int | None = None
    miners: int | None = None
    workers: int | None = None
    fee_percent: float | None = None
    last_block_height: int | None = None
    last_block_at: datetime | None = None
    http_status: int | None = None
    reason: Reason = Reason.OK
    error: str | None = None


class VersionProbe(BaseModel):
    """`get_version`. Slow cadence — it only changes when a node restarts."""

    ok: bool
    node_version: str | None = None
    block_header_version: int | None = None
    error: str | None = None


class StatusSource(str, enum.Enum):
    """Which endpoint answered a node's status call.

    Epic 4.1.0-1 serves `GET /v1/status` without auth. A stock 4.1.0 answers that
    with 401 but still serves the same struct through the owner API's `get_status`,
    which needs no secret on 4.x. Recorded because the second is a fallback an
    operator may not know is open, and the reader of the details should see which
    one produced the numbers."""

    V1 = "v1_status"
    OWNER = "owner_get_status"

    @property
    def label(self) -> str:
        return "/v1/status" if self is StatusSource.V1 else "owner get_status"


class StatusProbe(BaseModel):
    """One node status call: peers, sync state, agent and the node's own tip.

    The one place peer counts come from. `ok=False` means neither endpoint
    answered usably; the row keeps everything `get_tip` gave it and says only
    that status is unavailable."""

    ok: bool
    source: StatusSource | None = None
    connections: int | None = None
    user_agent: str | None = None
    protocol_version: int | None = None
    sync_status: str | None = None
    height: int | None = None
    tip_hash: str | None = None
    error: str | None = None


class BlockHeader(BaseModel):
    """One block header, as the foreign API's `get_header` returns it.

    `total_difficulty` is cumulative and per algorithm. Epic advances all four
    counters on every block whichever algorithm mined it, so the difference between
    two consecutive headers is the current difficulty of each algorithm — which is
    what the chain panel shows, without needing an owner API or a hashrate model.
    """

    height: int
    hash: str
    previous: str
    mined_at: datetime
    proof: str | None = None
    """Which algorithm solved the block: `Cuckoo`, `RandomX` or `ProgPow` on mainnet."""
    total_difficulty: Difficulty = Field(default_factory=Difficulty)


class HeaderProbe(BaseModel):
    """`get_header` at one height.

    Used for two things that are both properties of the chain rather than of a node:
    how old the newest block is, and — by keeping the canonical header at every recent
    height — whether a block this service already saw has since been replaced.
    """

    ok: bool
    header: BlockHeader | None = None
    error: str | None = None


# ----------------------------------------------------------------------- enrichment


class GeoInfo(BaseModel):
    """Provider and location, from RDAP.

    Deliberately two separate confidences. The provider is registry data and is
    reliable. The country is not: a Vultr allocation carries no country in its
    RDAP record at all, and anycast or proxied hosts report the proxy's country.
    So it is surfaced as "registry location", an operator may override it, and it
    never overrides a measurement.
    """

    provider: str | None = None
    country: str | None = None
    """ISO 3166-1 alpha-2 from the registry, uppercase, or None when genuinely
    unknown. Vultr allocations carry no country at all."""
    country_manual: str | None = None
    """Set by hand in config/targets.toml or at submission, and never overwritten by
    a lookup. This exists because the registry is wrong often enough to matter: this
    project's own host is a London VPS whose RDAP record says India, because the
    allocation is registered to the provider's NOC."""
    provider_manual: str | None = None
    """Set by hand, and never overwritten by a lookup. Same reason as
    `country_manual`: RDAP returns the registered holder of the allocation, which for a
    reseller or a NOC-registered block is not the company an operator would name. An
    admin correcting it once should not have to correct it again next week."""

    city: str | None = None
    city_manual: str | None = None
    """Set by hand, never overwritten. RDAP carries a city inconsistently and often
    names the datacentre's registered office rather than where the metal is."""

    network_name: str | None = None
    """The registry's own handle for the block, e.g. CLOUD-FSN1, which often
    identifies the datacentre more precisely than the country does."""
    asn: str | None = None
    looked_up_at: datetime | None = None

    @property
    def display_country(self) -> str | None:
        """What the page shows. A human-supplied value always beats the registry."""
        return self.country_manual or self.country

    @property
    def display_provider(self) -> str | None:
        return self.provider_manual or self.provider

    @property
    def display_city(self) -> str | None:
        return self.city_manual or self.city


class Target(BaseModel):
    """A thing being monitored."""

    id: int | None = None
    kind: Kind
    chain: Chain = Chain.MAINNET
    """Which network this host serves.

    Defaulted rather than required, and that is a deliberate compatibility choice in
    three places at once: every existing `Target(...)` construction site keeps
    working, the DDL default fills the column for every row already in the database
    when the table is rebuilt, and a seed entry in the committed registry that says
    nothing about a chain means mainnet — which is what every entry written before
    floonet existed meant."""
    slug: str
    """Stable public identifier, used in URLs and as the API's `id`."""
    endpoint: str
    """For a node, the base URL the JSON-RPC lives under (no trailing slash), so
    the probe posts to `{endpoint}/v2/foreign`. For a relay, the `wss://` URL."""
    display_host: str
    """What a human reads. Not necessarily parseable back into the endpoint."""
    p2p: str | None = None
    """host:port for the TCP liveness fallback used when the HTTP API is closed."""
    adapter: str | None = None
    """Pool-only. Names the response shape to expect, resolved against the registry
    in `probes.pool`. Nodes and relays speak one protocol each and need no adapter;
    every pool's stats API is its own invention, so the shape is declared per target
    in the committed registry rather than sniffed at runtime."""
    operator: str | None = None
    label: str | None = None
    notes: str | None = None
    verified: bool = False
    """Vouched for by whoever runs this instance: an official server rather than a
    community one.

    This replaced a flag called `ours`, which meant "operated by the instance operator" and
    read on a public page as *your* node — the one thing it did not mean. The new flag says
    something a reader can act on: somebody has checked this host and stands behind it.
    Unset means community-run, which is not a judgement, just an absence of vouching.

    The SQL column is still named `ours`. Renaming it would mean rebuilding the table and
    dropping the values already in it, and the column name is not published anywhere —
    the API field, the admin control and the board badge all say `verified`."""

    @property
    def listing(self) -> str:
        """`official` or `community`, for the API and for grouping on the board."""
        return "official" if self.verified else "community"
    source: Source = Source.SUBMITTED
    enabled: bool = True
    geo: GeoInfo = Field(default_factory=GeoInfo)
    created_at: datetime | None = None


class Check(BaseModel):
    """One probe result, for the recent-checks strip.

    The strip used to be a list of bare booleans, which is all it needs to *draw* — but a bar
    a reader can point at should be able to say when it was and what happened, and a boolean
    cannot. `latency_ms` comes along because it is the one number that explains a slow-looking
    success.
    """

    ok: bool
    at: datetime
    latency_ms: int | None = None
    state: State | None = None
    """The row's verdict when this check was recorded. What separates a failure that
    was still being confirmed (amber in the strip) from one that meant down (red)."""


# --------------------------------------------------------------------------- events


class EventKind(str, enum.Enum):
    """Something that started, and usually later ended, and is worth a line in the log.

    Deliberately short. A status page that logs every amber flicker produces a feed
    nobody reads; each of these is a change a reader could act on or would ask about.
    """

    DOWN = "down"
    """A target reached `down`. Ends when it leaves it."""
    REORG = "reorg"
    """A block this service had already seen as the fleet tip was replaced. Instant:
    started and ended in the same moment, with the depth in the detail."""
    FORK = "fork"
    """A tip-hash conflict that survived confirmation. Ends when the fleet agrees."""
    STALL = "stall"
    """No new block for far longer than the target interval. Ends on the next block."""
    CERT_EXPIRING = "cert_expiring"
    """A relay certificate inside the warning window. Ends when it is renewed."""


class Severity(str, enum.Enum):
    INFO = "info"
    WARN = "warn"
    BAD = "bad"

    @property
    def rank(self) -> int:
        return {"info": 0, "warn": 1, "bad": 2}[self.value]


class Event(BaseModel):
    """One incident-log entry."""

    id: int | None = None
    chain: Chain
    kind: EventKind
    severity: Severity
    subject: str
    """What it happened to, as a reader would name it: a host, or the chain itself.
    Stored as text rather than only as a target id, so the entry still reads correctly
    after the target is removed."""
    target_slug: str | None = None
    detail: str | None = None
    depth: int | None = None
    """Blocks replaced, for a reorg. None for every other kind."""
    prober_id: str
    started_at: datetime
    """When the first occurrence began."""
    ended_at: datetime | None = None
    """When the latest occurrence ended; None while it lasts."""
    occurrences: int = 1
    """How many times this happened to this subject inside the dedupe window. One row
    stands for every occurrence of the same kind for the same source within 24 hours
    of `started_at` — see `db.DEDUPE_WINDOW_S` — and each is kept in
    `event_occurrences`, so the count is a summary and not a loss of history."""
    last_started_at: datetime | None = None
    """When the latest occurrence began. Equal to `started_at` when there is one."""
    active_s: float | None = None
    """Seconds the condition was active, summed over closed occurrences only."""

    @property
    def ongoing(self) -> bool:
        return self.ended_at is None

    @property
    def duration_s(self) -> int | None:
        """First start to latest end. For a single occurrence, its duration; for an
        aggregate, the span it covers, gaps included — `active_total_s` is the time the
        condition actually held."""
        if self.ended_at is None:
            return None
        return max(0, int((self.ended_at - self.started_at).total_seconds()))

    @property
    def latest_start(self) -> datetime:
        return self.last_started_at or self.started_at

    @property
    def last_duration_s(self) -> int | None:
        """How long the latest occurrence lasted, or None while it lasts."""
        if self.ended_at is None:
            return None
        return max(0, int((self.ended_at - self.latest_start).total_seconds()))

    @property
    def active_total_s(self) -> int:
        """Closed occurrences plus the one still running, if any, up to now."""
        total = self.active_s or 0.0
        if self.ended_at is None:
            total += max(0.0, (datetime.now(UTC) - self.latest_start).total_seconds())
        return int(total)

    @property
    def updated_at(self) -> datetime:
        """The latest change to this entry: a new occurrence or an end."""
        return max(t for t in (self.started_at, self.last_started_at, self.ended_at) if t)


# ----------------------------------------------------------------------- chain panel


class AlgoActivity(BaseModel):
    """One proof-of-work algorithm over the panel's window."""

    algo: str
    """As a reader knows it: `RandomX`, `ProgPow`, `Cuckatoo`."""
    blocks: int
    share: float
    difficulty: int | None = None
    """Current per-block difficulty: the step in this algorithm's cumulative counter
    between the two newest headers."""
    difficulty_change: float | None = None
    """Fractional change against the oldest header in the window, or None when the
    window is too short to say anything."""


class ChainActivity(BaseModel):
    """Is the chain moving normally — derived from recent headers, not from any node's
    opinion of itself."""

    window_blocks: int
    window_s: int
    median_interval_s: int | None = None
    mean_interval_s: int | None = None
    longest_gap_s: int | None = None
    longest_gap_height: int | None = None
    """The height of the block that *ended* the longest gap."""
    target_interval_s: int = 60
    algos: list[AlgoActivity] = Field(default_factory=list)
    reorgs_24h: int = 0
    deepest_reorg_24h: int = 0


class Vantage(BaseModel):
    """The newest check of one target from a prober other than this one."""

    prober_id: str
    ok: bool
    latency_ms: int | None = None
    error: str | None = None
    at: datetime


class RemoteCheck(BaseModel):
    """One check in a batch pushed by a remote prober. Validated on arrival: it comes
    from another machine and crosses a trust boundary like any probe response."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(max_length=253)
    """The target's slug on the hub."""
    kind: Kind
    ok: bool
    latency_ms: int | None = Field(default=None, ge=0, le=600_000)
    height: int | None = Field(default=None, ge=0)
    tip_hash: str | None = Field(default=None, max_length=128)
    error: str | None = Field(default=None, max_length=300)
    checked_at: datetime


class ProbeBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prober_id: str = Field(min_length=1, max_length=64)
    checks: list[RemoteCheck] = Field(max_length=500)


class TargetStatus(BaseModel):
    """A target plus its current computed verdict. This is what the board renders
    and what the JSON API serialises."""

    target: Target
    state: State = State.UNKNOWN
    reason: Reason = Reason.NEVER_SEEN
    detail: str | None = None

    latency_ms: int | None = None
    height: int | None = None
    tip_lag: int | None = None
    tip_hash: str | None = None
    node_version: str | None = None
    protocol_version: str | None = None
    cert_expires_in_days: int | None = None

    ipv6: IPv6 | None = None
    """Nodes and relays. None until the first capability check."""
    browser_access: bool | None = None
    """Nodes only: whether the CORS preflight a web wallet sends is accepted. None
    until measured, or when the preflight itself could not be completed."""
    peers: int | None = None
    """Nodes only: `connections` from the status call. None when it did not answer."""
    status_probe: StatusProbe | None = None
    """Nodes only: the latest status call, or None before the first one returns."""
    tip_agrees: bool | None = None
    """Nodes only: whether this node's tip hash matches the most common hash among
    the other nodes of its chain at the same height. None when no other node is at
    that height, so there is nothing to compare against."""

    # Pool-only. On one flat model with the other kinds' fields for the same reason
    # they are: the board renders one row shape and the alternative is a union type
    # that every consumer has to narrow before reading a latency.
    miners: int | None = None
    workers: int | None = None
    fee_percent: float | None = None
    last_block_height: int | None = None
    last_block_at: datetime | None = None

    last_checked_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0

    uptime_1h: float | None = None
    uptime_24h: float | None = None
    uptime_30d: float | None = None
    history: list[Check] = Field(default_factory=list)
    """Most recent checks, oldest first. Rendered as the recent-checks strip."""
    vantages: list[Vantage] = Field(default_factory=list)
    """What other probers saw recently. Evidence beside the verdict, never part of it."""


class NetworkSummary(BaseModel):
    """The headline. One sentence's worth of derived facts, so the first screen
    answers "can I transact right now" rather than posing it.

    Every field here describes exactly one chain. There is one of these per
    `Snapshot`, and one `Snapshot` per chain — the alternative, a single summary with
    the two fleets added together, would produce numbers that are true of neither:
    "4 of 5 nodes healthy" across two networks tells a floonet reader nothing and
    misleads a mainnet one.
    """

    chain: Chain = Chain.MAINNET
    """Which network these numbers describe. Typed rather than a bare string, and
    now actually assigned by the poller — it was a hardcoded `"mainnet"` literal for
    as long as there was only one chain to summarise."""
    tip_height: int | None = None
    tip_hash: str | None = None
    tip_age_s: int | None = None
    tip_mined_at: datetime | None = None
    """When the tip block was mined, from the block's own timestamp.

    The absolute value, as well as the age. `tip_age_s` is computed once per snapshot from
    a header fetched every 60 seconds, so a page that renders it as "45s ago" and then
    leaves it there is showing an age that was already up to a minute stale when it was
    written and only gets staler. A UTC timestamp cannot go stale — it is a fact about a
    block, not about when someone looked."""
    health_score: int | None = None
    forked: bool = False
    fork_detail: str | None = None

    nodes_total: int = 0
    nodes_healthy: int = 0
    nodes_degraded: int = 0
    nodes_down: int = 0
    epicbox_total: int = 0
    epicbox_healthy: int = 0
    epicbox_degraded: int = 0
    epicbox_down: int = 0
    pools_total: int = 0
    pools_healthy: int = 0
    pools_degraded: int = 0
    pools_down: int = 0

    median_node_latency_ms: int | None = None
    median_epicbox_latency_ms: int | None = None
    median_pool_latency_ms: int | None = None

    countries: list[str] = Field(default_factory=list)
    providers: dict[str, int] = Field(default_factory=dict)
    co_hosted: int = 0
    """Distinct addresses serving more than one listed role. Currently three, all
    of them a node and a relay on one machine — a fact the page should state
    rather than obscure by listing the rows separately."""

    released_node_version: str | None = None
    """What upstream has published, read from GitHub by `upstream.py`. Stated once for
    the fleet rather than repeated as a complaint on every lagging row."""

    released_node_url: str | None = None
    """The release page for exactly that version."""

    released_node_source: str | None = None
    """Where the number came from: `github`, `seed` (GitHub not yet reached) or
    `pinned` (set by the operator). Published so a reader can tell a live answer
    from a fallback."""

    released_wallet_version: str | None = None

    nodes_current: int = 0
    """Nodes reporting exactly `released_node_version`. Counted only over nodes that
    reported a version at all, so an unreachable node is absent from the numerator
    and from `nodes_versioned` rather than being scored as stale."""

    nodes_versioned: int = 0
    """Nodes that reported any version. The denominator for `nodes_current`; a node
    whose foreign API is closed answers `get_tip` but not `get_version`, so this is
    routinely smaller than `nodes_total`."""

    activity: ChainActivity | None = None
    """Block intervals, algorithm mix and difficulty from recent headers. None until
    enough headers have been collected to say anything."""


class Snapshot(BaseModel):
    """The whole board, rebuilt after each sweep and served without touching the
    database."""

    generated_at: datetime
    prober_id: str
    network: NetworkSummary
    nodes: list[TargetStatus] = Field(default_factory=list)
    epicbox: list[TargetStatus] = Field(default_factory=list)
    pools: list[TargetStatus] = Field(default_factory=list)
    stale: bool = False
    """True when the poller has not completed a sweep recently. Frozen numbers
    presented as live are worse than an admission."""
