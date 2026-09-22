"""Settings and the committed target registry.

Two sources, on purpose. Seed targets live in a TOML file in git so that adding
the Epic Cash Foundation's node or Cypher Stack's relay is a reviewable commit.
Public submissions live in SQLite. The split is what keeps the canonical list
auditable while still letting anyone add a server without asking permission.

Nothing here hardcodes a hostname for *this* deployment. SITE_URL and SITE_NAME
are environment, so moving from status.btlabs.uk to status.epiccash.com is a DNS
record and one variable rather than a grep.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import GeoInfo, Kind, Source, Target

REPO_ROOT = Path(__file__).resolve().parents[2]


class Cadence(BaseModel):
    """How often each probe runs, in seconds.

    The asymmetry between nodes and relays is not an oversight. One `get_tip` is
    468 bytes and 0.2 requests per second per host — trivial. An Epicbox
    connection is meant to live for hours: a wallet opens one and speaks once a
    minute. Connect-and-drop every 5 seconds is a churn pattern no legitimate
    client produces, and operators fronting with nginx commonly cap concurrent
    connections in single digits.
    """

    node_tip_s: float = 5.0
    node_version_s: float = 300.0
    node_header_s: float = 60.0
    node_p2p_s: float = 30.0
    epicbox_s: float = 30.0
    epicbox_cert_s: float = 21600.0
    geo_refresh_s: float = 604800.0


class Thresholds(BaseModel):
    tip_lag_healthy: int = 10
    """Blocks behind the fleet's highest tip before a node is degraded. Epic
    targets ~60 s blocks, so ten blocks is roughly ten minutes — generous enough
    that normal propagation never trips it. monero.fail uses 500 on a chain with
    two-minute blocks."""

    tip_lag_down: int = 720
    """Twelve hours behind is not a lagging node, it is a different chain."""

    down_after_failures: int = 3
    """Consecutive failed checks before red. One dropped packet is not an outage,
    and at a 5-second cadence three checks is 15 seconds of honesty."""

    cert_warn_days: int = 14
    stale_snapshot_s: float = 120.0
    remove_after_failures: int = 500
    """A submitted target that has never once succeeded and has failed this many
    consecutive checks deletes itself. At 5 seconds that is about 40 minutes.
    Seed targets are exempt."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EPIC_STATUS_", env_file=".env", extra="ignore"
    )

    bind: str = "127.0.0.1"
    """Loopback only, and this should stay that way. The submit endpoint accepts
    unauthenticated writes; a reverse proxy is the only thing that should ever
    hold the public socket."""

    port: int = 13431
    db: Path = REPO_ROOT / "data" / "status.db"
    targets_file: Path = REPO_ROOT / "config" / "targets.toml"

    site_name: str = "Epic Cash Status"
    site_url: str = "http://127.0.0.1:13431"
    prober_id: str = "local"
    """Which vantage point these measurements come from. Stored on every check so
    a second prober in another region is additive rather than a migration. A
    latency column measured from one host is a statement about that host's
    network, so the board labels it with this value."""

    prober_region: str = "unknown"

    own_node_url: str | None = None
    """A node this instance operates. The board may time one request to it from
    the reader's browser automatically, because the reader already connected to
    us to load the page and so discloses nothing new. Every other target stays
    behind an explicit opt-in."""

    http_timeout_s: float = 4.0
    ws_timeout_s: float = 8.0
    max_concurrency: int = 16
    """Bounded because probing N third-party hosts is bursty work sharing a
    process with page serving on a 2-vCPU box."""

    submissions_enabled: bool = True
    max_pending_submissions: int = 200
    submit_probes_required: int = 3
    submit_probe_interval_s: float = 60.0
    allow_private_targets: bool = False
    """Only ever true for local development. Flipping it on a public instance
    turns the submit form into a port scanner aimed at your own network."""

    keep_success_days: int = 7
    """Nobody needs to prove a node was up. Everybody eventually needs to prove
    it was down, so failures are never pruned."""

    history_points: int = 30
    cadence: Cadence = Field(default_factory=Cadence)
    thresholds: Thresholds = Field(default_factory=Thresholds)


@lru_cache(maxsize=1)
def settings() -> Settings:
    return Settings()


# --------------------------------------------------------------------------- seeds


def _node_target(raw: dict[str, object]) -> Target:
    host = str(raw["display_host"])
    return Target(
        kind=Kind.NODE,
        slug=str(raw.get("slug") or host),
        endpoint=str(raw["endpoint"]).rstrip("/"),
        display_host=host,
        p2p=str(raw["p2p"]) if raw.get("p2p") else None,
        operator=str(raw["operator"]) if raw.get("operator") else None,
        label=str(raw["label"]) if raw.get("label") else None,
        notes=str(raw["notes"]) if raw.get("notes") else None,
        ours=bool(raw.get("ours", False)),
        source=Source.SEED,
        geo=GeoInfo(
            country_manual=str(raw["country"]).upper() if raw.get("country") else None
        ),
    )


def _epicbox_target(raw: dict[str, object]) -> Target:
    host = str(raw["display_host"])
    return Target(
        kind=Kind.EPICBOX,
        slug=str(raw.get("slug") or host),
        endpoint=str(raw["endpoint"]),
        display_host=host,
        operator=str(raw["operator"]) if raw.get("operator") else None,
        label=str(raw["label"]) if raw.get("label") else None,
        notes=str(raw["notes"]) if raw.get("notes") else None,
        ours=bool(raw.get("ours", False)),
        source=Source.SEED,
        geo=GeoInfo(
            country_manual=str(raw["country"]).upper() if raw.get("country") else None
        ),
    )


def load_seed_targets(path: Path | None = None) -> list[Target]:
    """Read the committed registry. A malformed entry is a startup failure, not a
    silently skipped row — a status page that quietly stops monitoring something
    is worse than one that refuses to boot."""
    path = path or settings().targets_file
    with path.open("rb") as fh:
        doc = tomllib.load(fh)

    targets: list[Target] = []
    for raw in doc.get("node", []):
        targets.append(_node_target(raw))
    for raw in doc.get("epicbox", []):
        targets.append(_epicbox_target(raw))

    slugs = [t.slug for t in targets]
    duplicates = {s for s in slugs if slugs.count(s) > 1}
    if duplicates:
        raise ValueError(f"duplicate slugs in {path}: {sorted(duplicates)}")
    return targets
