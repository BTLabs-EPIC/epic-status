"""Response schemas, for the OpenAPI document only.

The routes build their responses by hand so they can control `ETag`, caching and
CORS headers, which means FastAPI cannot infer a return type from them. These models
are attached via `responses={200: {"model": ...}}` instead: the API reference gets
real schemas, field descriptions and examples, and the handlers keep their explicit
control over the wire format.

Keeping them in a separate module rather than reusing the internal models in
`models.py` is deliberate. Those are domain types and will change as probes change;
this is a published contract that third parties build against, and the two should be
free to move independently. Where they drift, `api._serialise` is the one place that
has to be updated — and the field names here are the ones documented to consumers.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Uptime(BaseModel):
    """Fraction of successful checks in the window, or null when there is no data.

    Null is not zero. A target with no history has no uptime; rendering it as 0%
    would misreport a server nobody has measured yet as one that is always down.
    """

    one_hour: float | None = Field(None, alias="1h", examples=[1.0])
    day: float | None = Field(None, alias="24h", examples=[0.9998])
    month: float | None = Field(None, alias="30d", examples=[0.9971])


class Location(BaseModel):
    """Where the host appears to be, from registry records.

    Low confidence by construction, which is why `source` is present and says
    `registry`. RDAP carries country inconsistently — some allocations have none at
    all — and a host behind a proxy or anycast reports the proxy's location. Never
    treat this as a measurement.
    """

    country: str | None = Field(None, description="ISO 3166-1 alpha-2.", examples=["FI"])
    country_registry: str | None = Field(
        None,
        description="What the registry said, before any operator-supplied override.",
        examples=["FI"],
    )
    city: str | None = Field(None, examples=["Helsinki"])
    provider: str | None = Field(None, examples=["Hetzner"])
    network_name: str | None = Field(
        None,
        description="The registry's handle for the allocation. Often identifies the "
        "datacentre more precisely than the country does.",
        examples=["CLOUD-FSN1"],
    )
    source: str = Field("registry", examples=["registry"])


class TargetBase(BaseModel):
    id: str = Field(description="Stable identifier.", examples=["node.epiccash.com"])
    kind: str = Field(
        description="`node`, `epicbox` or `pool`.", examples=["node"]
    )
    host: str = Field(examples=["node.epiccash.com:3413"])
    endpoint: str = Field(
        description="What is actually contacted.",
        examples=["https://node.epiccash.com:3413"],
    )
    operator: str | None = Field(None, examples=["Epic Cash"])
    label: str | None = Field(None, examples=["Default node"])
    notes: str | None = None
    verified: bool = Field(
        False,
        description=(
            "Vouched for by this instance's operator as an official server. False means "
            "community-run, which is an absence of vouching rather than a judgement."
        ),
    )
    listing: str = Field(
        "community",
        description="`official` or `community` — the same fact as `verified`, as the value the board groups by.",
        examples=["official"],
    )
    source: str = Field(description="`seed` or `submitted`.", examples=["seed"])

    state: str = Field(
        description=(
            "`healthy`, `degraded`, `down`, or `unknown`. Three states rather than "
            "two: a node whose API needs credentials is up but unpollable, a node far "
            "behind the tip answers perfectly, and a probe that failed from this host "
            "is not proof about that one."
        ),
        examples=["healthy"],
    )
    reason: str = Field(
        description="Machine-readable cause when not healthy, e.g. `tip_lag`, "
        "`api_restricted`, `timeout`, `p2p_only`. A relay with a certificate near "
        "expiry is not one of these: it stays `healthy` with `ok`, and the day count "
        "is published on its own in `cert_expires_in_days`.",
        examples=["ok"],
    )
    detail: str | None = Field(
        None, description="The same cause in a sentence, as shown on the board."
    )

    latency_ms: int | None = Field(
        None,
        description="Round trip from this prober only. A latency figure is a "
        "statement about the measuring host's network as much as the target's.",
        examples=[118],
    )
    last_checked_at: str | None = Field(None, examples=["2026-09-22T06:42:35Z"])
    last_ok_at: str | None = Field(
        None,
        description="Last successful check. Only ever moves forward, and only on "
        "success. Null means it has never answered.",
        examples=["2026-09-22T06:42:35Z"],
    )
    last_error: str | None = Field(
        None,
        description="Verbatim failure text, published so an operator can diagnose "
        "their own endpoint without contacting anyone.",
        examples=["connection timed out"],
    )
    error_count: int = Field(0, description="Consecutive failures.", examples=[0])
    uptime: Uptime
    location: Location


class NodeStatus(TargetBase):
    height: int | None = Field(None, examples=[3721218])
    tip_lag: int | None = Field(
        None,
        description="Blocks behind the highest tip seen across the fleet. 0 is at the "
        "tip. This, not reachability, is what separates health from liveness.",
        examples=[0],
    )
    tip_hash: str | None = Field(
        None,
        description="Tip block hash. Two nodes at one height with different hashes is "
        "how a fork becomes visible.",
    )
    node_version: str | None = Field(None, examples=["4.0.4"])


class EpicboxStatus(TargetBase):
    protocol_version: str | None = Field(None, examples=["3.0.1"])
    cert_expires_in_days: int | None = Field(None, examples=[61])


class PoolStatus(TargetBase):
    miners: int | None = Field(None, examples=[118], description="Connected accounts.")
    workers: int | None = Field(
        None, examples=[521], description="Connected rigs, which exceeds `miners`."
    )
    fee_percent: float | None = Field(
        None,
        examples=[2.5],
        description=(
            "Always a percentage. One pool publishes its fee as the fraction "
            "`\"0.02\"`; that is normalised here so the two are comparable."
        ),
    )
    last_block_height: int | None = Field(
        None,
        examples=[3721267],
        description=(
            "The last block this pool **found** — not its chain tip, which no pool "
            "API exposes. Do not compare it with `network.tip_height`: the expected "
            "gap is inversely proportional to the pool's share, so a small pool is "
            "legitimately hundreds of blocks back while working perfectly."
        ),
    )
    last_block_at: str | None = Field(
        None,
        examples=["2026-09-22T07:52:15Z"],
        description="When that block was found. The useful form of the field above.",
    )


class Prober(BaseModel):
    """Where the measurements were taken. One vantage point today; every stored check
    carries this id from the first schema so a second region is additive."""

    id: str = Field(examples=["btlabs-lon"])
    region: str = Field(examples=["GB"])
    measures: str = Field(
        description="What the figures from this probe describe, and what they do not.",
        examples=["reachability and round-trip latency from this host only"],
    )


class Network(BaseModel):
    chain: str = Field(
        "mainnet",
        description=(
            "Which network this document describes: `mainnet` or `floonet`. One "
            "document per chain — request the other with `?chain=floonet`. The two are "
            "scored entirely separately, so no field here ever mixes them."
        ),
        examples=["mainnet"],
    )
    tip_height: int | None = Field(None, examples=[3721218])
    tip_hash: str | None = None
    tip_mined_at: str | None = Field(
        None,
        description=(
            "When the tip block was mined, from the block's own timestamp. Absolute, so it "
            "cannot go stale the way a rendered age does."
        ),
        examples=["2026-09-22T19:20:54Z"],
    )
    tip_age_s: int | None = Field(
        None,
        description="Age of the tip block, from its own timestamp. Catches a stalled "
        "chain, which height alone cannot.",
        examples=[64],
    )
    health_score: int | None = Field(
        None,
        description=(
            "0–100, nodes only. Reachability 40%, tip agreement 35%, latency 15%, "
            "version spread 10%, and a flat −25 when forked. Epicbox is excluded: a "
            "dead relay breaks one transport, a forked chain breaks everything."
        ),
        examples=[74],
    )
    forked: bool = Field(
        False,
        description="Only true after the same conflict persists across consecutive "
        "sweeps. A single sweep cannot tell a fork from a normal orphan race.",
    )
    fork_detail: str | None = None
    nodes_total: int = Field(0, examples=[7])
    nodes_healthy: int = Field(0, examples=[3])
    nodes_degraded: int = Field(0, examples=[0])
    nodes_down: int = Field(0, examples=[4])
    epicbox_total: int = Field(0, examples=[6])
    epicbox_healthy: int = Field(0, examples=[3])
    epicbox_degraded: int = Field(0, examples=[0])
    epicbox_down: int = Field(0, examples=[3])
    pools_total: int = Field(0, examples=[2])
    pools_healthy: int = Field(0, examples=[2])
    pools_degraded: int = Field(0, examples=[0])
    pools_down: int = Field(0, examples=[0])
    median_node_latency_ms: int | None = Field(None, examples=[256])
    median_epicbox_latency_ms: int | None = Field(None, examples=[748])
    median_pool_latency_ms: int | None = Field(None, examples=[1564])
    countries: list[str] = Field(default_factory=list, examples=[["DE", "FI", "GB", "US"]])
    providers: dict[str, int] = Field(
        default_factory=dict,
        description="Count of listed services per hosting provider. Concentration "
        "here is a correlated-failure risk no single operator can fix.",
        examples=[{"Hetzner": 6, "Vultr": 4}],
    )
    co_hosted_addresses: int = Field(
        0,
        description="Addresses serving more than one listed service — typically a "
        "node and a relay on one machine, which fail together.",
        examples=[3],
    )
    released_node_version: str | None = Field(
        None,
        description=(
            "The node version upstream has published. Deliberately not derived from "
            "what the fleet is running: the highest version seen across monitored "
            "nodes would score a uniformly out-of-date fleet as unanimous."
        ),
        examples=["4.0.4"],
    )
    nodes_current: int = Field(
        0,
        description="Nodes reporting exactly released_node_version.",
        examples=[2],
    )
    nodes_versioned: int = Field(
        0,
        description="Nodes that reported any version — the denominator for "
        "nodes_current. A node with a closed foreign API answers get_tip but not "
        "get_version, so this is routinely lower than nodes_total.",
        examples=[3],
    )
    activity: dict[str, Any] | None = Field(
        None,
        description=(
            "Block intervals, the per-algorithm mix and difficulty, and reorgs over the "
            "last day, from block headers on the public API. Null until enough headers "
            "have been collected."
        ),
    )


class StatusMeta(BaseModel):
    """What the payload is, inside the payload.

    Present so a consumer that never reads the reference page still knows what the three
    states mean and which facts are deliberately absent. Documenting that only in prose
    puts it out of reach of the scripts that actually consume this.
    """

    describes: str
    states: dict[str, str] = Field(
        description="What each value of a target's `state` field means."
    )
    fields: dict[str, str] = Field(
        description=(
            "Encoding and meaning for the fields that are not self-evident, so a "
            "consumer does not have to read the reference page to use them correctly."
        )
    )
    absent: list[str] = Field(
        description="Facts this API deliberately does not carry, and why.",
    )
    docs: str
    schema_url: str = Field(
        alias="schema", description="The OpenAPI document for these routes."
    )


class StatusResponse(BaseModel):
    meta: StatusMeta
    generated_at: str = Field(examples=["2026-09-22T06:42:35Z"])
    stale: bool = Field(
        False,
        description="True when the poller has not completed a sweep recently. "
        "Frozen numbers presented as live are worse than an admission.",
    )
    prober: Prober
    network: Network
    nodes: list[NodeStatus]
    epicbox: list[EpicboxStatus]
    pools: list[PoolStatus]


class ListMeta(BaseModel):
    """What this list is, carried in the list.

    A bare array of URLs tells a consumer nothing about what it is holding: whether the
    set was filtered, how old it is, how often it changes, or where the measurements
    behind it were taken. That knowledge used to live only in the prose on /api, which
    means a script that fetched the route had no access to it and a reader who found the
    route through a search engine never saw it.

    Every list route now answers those questions in the response. It is four extra keys
    and it removes the need for the page to explain the route at all.
    """

    describes: str = Field(
        description="What the list contains, in one phrase.",
        examples=["Epic Cash mainnet public node endpoints"],
    )
    filtered: str = Field(
        description=(
            "Which subset this response holds. `healthy` means every entry answered its "
            "last check and, for nodes, is within the tip-lag threshold. `all` means "
            "every monitored target including the ones that are down."
        ),
        examples=["healthy"],
    )
    count: int = Field(description="Entries in this response.", examples=[3])
    total_monitored: int = Field(
        description="Targets of this kind being monitored, before filtering.",
        examples=[5],
    )
    refreshed_every_s: float = Field(
        description="Cadence of the checks behind this list. Polling faster gains nothing.",
        examples=[5.0],
    )
    measured_from: str = Field(
        description=(
            "Identifier of the probe these measurements were taken from. One vantage "
            "point: reachability and latency describe the path from this host."
        ),
        examples=["btlabs-lon"],
    )
    docs: str = Field(
        description="Human reference for this route.", examples=["https://status.btlabs.uk/api"]
    )


class EndpointList(BaseModel):
    meta: ListMeta
    generated_at: str
    chain: str | None = None
    tip_height: int | None = None
    nodes: list[str] = Field(
        default_factory=list,
        description="Endpoint URLs, ready to paste into a wallet or a failover config.",
        examples=[["https://node.epiccash.com:3413", "https://node.btlabs.uk"]],
    )


class EpicboxList(BaseModel):
    meta: ListMeta
    generated_at: str
    epicbox: list[str] = Field(
        default_factory=list, examples=[["epicbox.epiccash.com", "epicbox.epicnet.us"]]
    )


class PoolList(BaseModel):
    meta: ListMeta
    generated_at: str
    pools: list[str] = Field(
        default_factory=list, examples=[["epicmine.io", "epic.iniaku.my.id"]]
    )


class EventOut(BaseModel):
    """One incident. Conditions open and close; a reorg is an instant."""

    id: int = Field(examples=[412])
    kind: str = Field(
        description="`down`, `reorg`, `fork`, `stall` or `cert_expiring`.",
        examples=["down"],
    )
    severity: str = Field(description="`info`, `warn` or `bad`.", examples=["warn"])
    subject: str = Field(
        description="A host, or the chain itself.", examples=["node.epicnet.us:3413"]
    )
    target: str | None = Field(
        None, description="The target's `id`, while it is still monitored."
    )
    detail: str | None = Field(None, examples=["connection timed out"])
    depth: int | None = Field(None, description="Blocks replaced, for a reorg.")
    started_at: str = Field(examples=["2026-09-29T20:14:05Z"])
    ended_at: str | None = Field(
        None, description="Null while ongoing. Equal to `started_at` for a reorg."
    )
    duration_s: int | None = None
    measured_from: str = Field(examples=["btlabs-lon"])


class EventList(BaseModel):
    generated_at: str
    chain: str
    min_severity: str
    events: list[EventOut]


class HealthResponse(BaseModel):
    """Liveness of this monitoring service, not of the Epic Cash network.

    Point alerting here. A 503 means the observer is broken; it says nothing about
    the nodes, and conflating the two is the most damaging mistake a status page can
    make.
    """

    service: str = Field(examples=["epic-status"])
    version: str = Field(examples=["0.1.0"])
    prober_id: str = Field(examples=["btlabs-lon"])
    has_data: bool
    stale: bool
    generated_at: str | None = None


class SubmitAccepted(BaseModel):
    ok: bool = Field(True)
    message: str = Field(
        examples=["node.example.org:3413 queued. It will be probed 3 times, 60 seconds apart."]
    )


class SubmitRejected(BaseModel):
    ok: bool = Field(False)
    error: str = Field(
        description="Why it was refused, phrased to be actionable on its own.",
        examples=["node.example.org resolves to the non-public address 10.0.0.5"],
    )


class ErrorResponse(BaseModel):
    error: str = Field(examples=["no data yet"])
    generated_at: str | None = None
