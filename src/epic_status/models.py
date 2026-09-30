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
from datetime import datetime

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


class TipAge(BaseModel):
    """`get_header` on the tip, for "is the chain actually moving".

    A node can answer `get_tip` flawlessly while stuck. Height alone cannot tell
    you whether the whole network has stalled or just this node.
    """

    ok: bool
    timestamp: datetime | None = None
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
    """What upstream has published, from `releases.py`. Stated once for the fleet
    rather than repeated as a complaint on every lagging row."""

    nodes_current: int = 0
    """Nodes reporting exactly `released_node_version`. Counted only over nodes that
    reported a version at all, so an unreachable node is absent from the numerator
    and from `nodes_versioned` rather than being scored as stale."""

    nodes_versioned: int = 0
    """Nodes that reported any version. The denominator for `nodes_current`; a node
    whose foreign API is closed answers `get_tip` but not `get_version`, so this is
    routinely smaller than `nodes_total`."""


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
