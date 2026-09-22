"""Server-side rendering.

Jinja2 with autoescaping, which is a security decision rather than a style one:
hostnames and operator names on this page can come from the public submit form, and
an unescaped template would make the board stored-XSS with extra steps.

The page is rendered complete on the server and works with JavaScript disabled.
JavaScript only patches numbers in place and ticks the relative timestamps. For a
status page that is the whole point: it has to work on the worst day, and the worst
day is not the one to discover the client-side render is broken.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from functools import lru_cache

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from .config import Settings
from .flags import flag, flag_title
from .models import Kind, Snapshot, State, TargetStatus

TEMPLATE_DIR = Path(__file__).parent / "templates"

_STATE_LABEL = {
    State.HEALTHY: "Online",
    State.DEGRADED: "Degraded",
    State.DOWN: "Offline",
    State.UNKNOWN: "No data",
}

_STATE_VERDICT = {
    State.HEALTHY: "verdict-ok",
    State.DEGRADED: "verdict-warn",
    State.DOWN: "verdict-bad",
    State.UNKNOWN: "verdict-info",
}


@lru_cache(maxsize=1)
def _environment() -> Environment:
    """Built lazily and cached.

    Constructed at first render rather than at import, because the filters it
    registers are defined further down this file and a module-level call would run
    before they exist.
    """
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["thousands"] = _thousands
    env.filters["ms"] = _ms
    env.filters["pct"] = _pct
    env.filters["relative"] = _relative
    env.filters["epoch_ms"] = _epoch_ms
    env.filters["state_label"] = lambda s: _STATE_LABEL.get(s, "Unknown")
    env.filters["flag"] = lambda c: Markup(flag(c))
    env.filters["flag_title"] = flag_title
    env.filters["short_hash"] = _short_hash
    return env


# --------------------------------------------------------------------- filters


def _thousands(value: int | None) -> str:
    return f"{value:,}" if isinstance(value, int) else "—"


def _ms(value: int | None) -> str:
    if value is None:
        return "—"
    if value >= 10000:
        return f"{value / 1000:.1f} s"
    return f"{value} ms"


def _pct(value: float | None) -> str:
    """No data renders as an em dash, never as 0%.

    A target with no history is not a target with no uptime, and printing 0% for one
    is how a status page libels an operator.
    """
    if value is None:
        return "—"
    if value >= 0.9995:
        return "100%"
    return f"{value * 100:.2f}%"


def _relative(value: datetime | None) -> str:
    """The server-rendered fallback. JavaScript replaces this with a ticking value,
    but it has to be correct on its own for a reader without JavaScript."""
    if value is None:
        return "never"
    seconds = int((datetime.now(UTC) - value).total_seconds())
    if seconds < 5:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s ago"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m ago"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h ago"


def _epoch_ms(value: datetime | None) -> str:
    return "" if value is None else str(int(value.timestamp() * 1000))


def _short_hash(value: str | None) -> str:
    return f"{value[:10]}…" if value else "—"


# ------------------------------------------------------------------- verdicts


def _headline(snapshot: Snapshot | None) -> tuple[str, str, str]:
    """(css class, headline, subline).

    Written to answer the question a beginner actually arrived with — can I transact
    right now — rather than to restate the counts that are already below.
    """
    if snapshot is None:
        return (
            "verdict-info",
            "Starting up",
            "The first round of checks has not finished yet.",
        )

    net = snapshot.network

    if snapshot.stale:
        return (
            "verdict-warn",
            "These numbers are not current",
            "The checker has not completed a round recently, so everything below is "
            "the last known state rather than live.",
        )

    if net.forked:
        return (
            "verdict-bad",
            "The network is reporting conflicting blocks",
            net.fork_detail or "Nodes disagree about the chain. Wait before transacting.",
        )

    if net.nodes_healthy == 0:
        return (
            "verdict-bad",
            "No public node is responding",
            "Either the network is in trouble or this checker has lost its "
            "connection. Both are possible; treat with suspicion.",
        )

    sub = (
        f"{net.nodes_healthy} of {net.nodes_total} public nodes agree on the chain tip"
        f" · {net.epicbox_healthy} of {net.epicbox_total} Epicbox relays reachable"
    )

    if net.epicbox_healthy == 0:
        return (
            "verdict-bad",
            "Nodes are up, but no Epicbox relay is reachable",
            "The chain is fine. Sending by Epicbox address will not work right now — "
            "a transaction file still will. " + sub,
        )

    if net.nodes_degraded or net.nodes_down or net.epicbox_down:
        return ("verdict-warn", "Working, with problems", sub)

    return ("verdict-ok", "Everything is operating normally", sub)


def _lag_note(status: TargetStatus) -> str:
    if status.tip_lag is None:
        return "—"
    if status.tip_lag <= 0:
        return "at tip"
    return f"−{status.tip_lag:,}"


# --------------------------------------------------------------------- render


def _base_context(snapshot: Snapshot | None, settings: Settings) -> dict[str, Any]:
    verdict_class, headline, subline = _headline(snapshot)
    return {
        "site_name": settings.site_name,
        "site_url": settings.site_url,
        "snapshot": snapshot,
        "network": snapshot.network if snapshot else None,
        "prober_id": settings.prober_id,
        "prober_region": settings.prober_region,
        "cadence_s": int(settings.cadence.node_tip_s),
        "epicbox_cadence_s": int(settings.cadence.epicbox_s),
        "submissions_enabled": settings.submissions_enabled,
        "verdict_class": verdict_class,
        "headline": headline,
        "subline": subline,
        "generated_at": snapshot.generated_at if snapshot else None,
        "State": State,
        "Kind": Kind,
        "lag_note": _lag_note,
        "own_node_url": settings.own_node_url,
    }


def render_board(
    *,
    snapshot: Snapshot | None,
    settings: Settings,
    request_region: str | None = None,
) -> str:
    context = _base_context(snapshot, settings)
    context["reader_region"] = request_region
    context["nodes"] = snapshot.nodes if snapshot else []
    context["relays"] = snapshot.epicbox if snapshot else []
    return _environment().get_template("board.html").render(**context)


def render_history(
    *,
    snapshot: Snapshot | None,
    settings: Settings,
    bars: dict[str, list[tuple[str, float | None]]],
) -> str:
    context = _base_context(snapshot, settings)
    context["rows"] = (snapshot.nodes + snapshot.epicbox) if snapshot else []
    context["bars"] = bars
    context["bar_class"] = _bar_class
    return _environment().get_template("history.html").render(**context)


def render_submit(
    *,
    snapshot: Snapshot | None,
    settings: Settings,
    message: str | None = None,
    error: str | None = None,
    submitted_host: str = "",
) -> str:
    context = _base_context(snapshot, settings)
    context["message"] = message
    context["error"] = error
    context["submitted_host"] = submitted_host
    context["probes_required"] = settings.submit_probes_required
    context["probe_interval_s"] = int(settings.submit_probe_interval_s)
    return _environment().get_template("submit.html").render(**context)


def _bar_class(value: float | None) -> str:
    """A day with no data is a gap, not an outage.

    The thresholds are deliberately generous: a single failed check in an hour is
    not a day worth colouring amber, and a bar that flickers on noise teaches
    readers to ignore it.
    """
    if value is None:
        return "none"
    if value >= 0.995:
        return ""
    if value >= 0.9:
        return "warn"
    return "bad"
