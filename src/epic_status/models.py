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
    city: str | None = None
    network_name: str | None = None
    """The registry's own handle for the block, e.g. CLOUD-FSN1, which often
    identifies the datacentre more precisely than the country does."""
    asn: str | None = None
    looked_up_at: datetime | None = None

    @property
    def display_country(self) -> str | None:
        """What the page shows. A human-supplied value always beats the registry."""
        return self.country_manual or self.country


class Target(BaseModel):
    """A thing being monitored."""

    id: int | None = None
    kind: Kind
    slug: str
    """Stable public identifier, used in URLs and as the API's `id`."""
    endpoint: str
    """For a node, the base URL the JSON-RPC lives under (no trailing slash), so
    the probe posts to `{endpoint}/v2/foreign`. For a relay, the `wss://` URL."""
    display_host: str
    """What a human reads. Not necessarily parseable back into the endpoint."""
    p2p: str | None = None
    """host:port for the TCP liveness fallback used when the HTTP API is closed."""
    operator: str | None = None
    label: str | None = None
    notes: str | None = None
    ours: bool = False
    """Operated by whoever runs this instance. Shown as a badge, because listing
    your own infrastructure on a page you control without saying so reads as
    promotion."""
    source: Source = Source.SUBMITTED
    enabled: bool = True
    geo: GeoInfo = Field(default_factory=GeoInfo)
    created_at: datetime | None = None


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

    last_checked_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0

    uptime_1h: float | None = None
    uptime_24h: float | None = None
    uptime_30d: float | None = None
    history: list[bool] = Field(default_factory=list)
    """Most recent checks, oldest first. Rendered as the sparkline."""


class NetworkSummary(BaseModel):
    """The headline. One sentence's worth of derived facts, so the first screen
    answers "can I transact right now" rather than posing it."""

    chain: str = "mainnet"
    tip_height: int | None = None
    tip_hash: str | None = None
    tip_age_s: int | None = None
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

    median_node_latency_ms: int | None = None
    median_epicbox_latency_ms: int | None = None

    countries: list[str] = Field(default_factory=list)
    providers: dict[str, int] = Field(default_factory=dict)
    co_hosted: int = 0
    """Distinct addresses serving more than one listed role. Currently three, all
    of them a node and a relay on one machine — a fact the page should state
    rather than obscure by listing the rows separately."""


class Snapshot(BaseModel):
    """The whole board, rebuilt after each sweep and served without touching the
    database."""

    generated_at: datetime
    prober_id: str
    network: NetworkSummary
    nodes: list[TargetStatus] = Field(default_factory=list)
    epicbox: list[TargetStatus] = Field(default_factory=list)
    stale: bool = False
    """True when the poller has not completed a sweep recently. Frozen numbers
    presented as live are worse than an admission."""
