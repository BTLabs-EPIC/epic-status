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
import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

from functools import lru_cache, partial

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from . import icons, releases
from .config import Settings
from .flags import flag, flag_title
from .models import (
    Chain,
    Event,
    EventKind,
    Kind,
    Severity,
    Snapshot,
    State,
    Target,
    TargetStatus,
)
from .probes.pool import ADAPTERS
from .quickcheck import QuickCheckResult
from .score import version_behind
from .web import onion_request

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


@lru_cache(maxsize=1)
def asset_version() -> str:
    """A short hash of the stylesheet and the script, for cache-busting their URLs.

    This exists because of a specific and nasty failure. `/static/app.js` is served
    with an ETag and a Last-Modified but **no Cache-Control**, and under heuristic
    freshness a browser may reuse a response with no explicit lifetime without
    revalidating it at all. That was harmless while the script only patched numbers
    into the page it came from. It stopped being harmless the moment the script had to
    know *which chain* the page was showing: a browser holding the previous script
    polled `/api/v1/status.json` with no chain parameter, got mainnet, and wrote
    mainnet's tip height into a floonet board. Correct server, correct HTML, a page
    confidently displaying the wrong network's numbers.

    Versioning the URL means a deploy cannot be half-applied: the reader either has the
    document and the script that belong together, or fetches both. Content hash rather
    than mtime, so a redeploy that rewrites files without changing them does not
    invalidate every reader's cache for nothing.

    Cached for the life of the process, which is the life of a deployment — the files
    cannot change under a running service without a restart, and hashing them on every
    page render would be two file reads per request for an answer that never moves.
    """
    digest = hashlib.sha256()
    for name in ("app.css", "app.js"):
        path = STATIC_DIR / name
        try:
            digest.update(path.read_bytes())
        except OSError:
            # A missing asset is a deployment problem, not a reason to fail the page.
            # The version simply stops reflecting that file.
            digest.update(name.encode())
    return digest.hexdigest()[:12]

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

# The tab strip is chrome the reader did not ask for, so it gets the state as one word and
# one hue rather than as the headline sentence: "Epic Cash Status — Degraded" beside a
# coloured tile is readable in a strip of thirty tabs, and `verdict.lead` is not.
#
# Both maps are keyed on `Verdict.tone` so the tab and the headline cannot disagree — there
# is one state model and `_headline` owns it.
_STATUS_WORD = {
    "ok": "Healthy",
    "warn": "Degraded",
    "bad": "Down",
    "info": "Starting up",
}

_STATUS_ICON = {
    "ok": "icon.svg",
    "warn": "icon-degraded.svg",
    "bad": "icon-down.svg",
    "info": "icon-unknown.svg",
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
        # XML too: the Atom feed carries hostnames and operator-supplied text.
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["thousands"] = _thousands
    env.globals["server_initials"] = server_initials
    env.globals["server_tint"] = server_tint
    env.filters["ms"] = _ms
    env.filters["pct"] = _pct
    env.filters["relative"] = _relative
    env.filters["epoch_ms"] = _epoch_ms
    env.filters["age_clock"] = _age_clock
    env.filters["utc"] = _utc
    env.filters["day"] = _day
    env.filters["when"] = _when
    env.filters["rfc3339"] = _rfc3339
    env.filters["duration"] = _duration
    env.filters["event_label"] = lambda k: _EVENT_LABEL.get(k, str(k))
    env.filters["event_plural"] = lambda k: _EVENT_PLURAL.get(k, "occurrences")
    env.filters["event_active"] = lambda k: _EVENT_ACTIVE.get(k)
    env.filters["event_latest"] = _event_latest
    env.filters["event_first"] = _event_first
    env.filters["state_label"] = lambda s: _STATE_LABEL.get(s, "Unknown")
    env.filters["flag"] = lambda c: Markup(flag(c))
    env.filters["flag_title"] = flag_title
    env.filters["short_hash"] = _short_hash
    env.filters["sync_label"] = _sync_label
    env.filters["lat_w"] = _lat_w
    env.filters["lat_band"] = _lat_band
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


#: Where the latency bar tops out. A fixed ceiling rather than the slowest host in the
#: group: a relative scale redraws every bar the moment one host recovers, and a bar
#: whose meaning changes between renders is decoration.
_LATENCY_CEILING_MS = 2000


def _lat_w(value: int | None) -> int:
    """Bar width as a percentage, quantised to 5% steps.

    Quantised because the width ships as a CSS class. The service sets its own CSP with
    `style-src 'self'` and no `unsafe-inline`, so a `style="width:42%"` attribute is
    dropped by the browser and every bar renders at zero width — silently, with nothing
    in the logs to explain it. Twenty classes is cheaper than weakening the policy.

    A reachable host never renders as nothing: anything that answered at all floors at
    5%, so "fast" reads as a short bar rather than an absent one.
    """
    if value is None:
        return 0
    capped = min(value, _LATENCY_CEILING_MS)
    step = round(capped / _LATENCY_CEILING_MS * 100 / 5) * 5
    return max(5, min(100, step))


def _lat_band(value: int | None) -> str:
    """Three bands, so the bar carries a judgement as well as a length.

    The thresholds are about what the latency means for a wallet, not about round
    numbers: under 150ms is a local or well-peered host, under 600ms is usable from
    anywhere, and past that a wallet call feels slow even when it succeeds.
    """
    if value is None:
        return "none"
    if value < 150:
        return "fast"
    if value < 600:
        return "mid"
    return "slow"


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


def _age_clock(value: datetime | None) -> str:
    """An age as a fixed-width clock: 0:04, 0:59, 3:07, 1:02:11.

    The board updates every second and should keep doing so — a status page that hides
    how fresh it is has lost the plot. What made that read as flickering was not the
    update, it was the reflow: "just now" becoming "5s ago" becoming "1m 12s ago" changes
    the string's width on almost every tick, so the text around it shifts and the eye
    reads motion where there is only a number.

    A clock changes one digit per second at a constant width. Same information, same
    cadence, no movement.
    """
    if value is None:
        return "—"
    seconds = max(0, int((datetime.now(UTC) - value).total_seconds()))
    if seconds < 3600:
        return f"{seconds // 60}:{seconds % 60:02d}"
    if seconds < 86400:
        return f"{seconds // 3600}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}:{(seconds % 3600) // 60:02d}"


def _utc(value: datetime | None) -> str:
    """An absolute UTC timestamp, to the second.

    For facts about the chain rather than facts about the page. A block's mined time does
    not change, so rendering it as "45s ago" means rendering something that was already up
    to a minute stale when it was written — the header it comes from is fetched once a
    minute — and then goes staler with every second the tab stays open. The timestamp is
    correct forever and needs no ticking.
    """
    if value is None:
        return "unknown"
    return value.astimezone(UTC).strftime("%H:%M:%S UTC")


def _day(value: datetime | None) -> str:
    """A calendar date, for facts older than one day.

    `_utc` prints a time of day, which is the right thing for a block that was mined four
    minutes ago and nonsense for the day a host joined the list: "listed since 06:46:21
    UTC" names no point in time at all.
    """
    if value is None:
        return "unknown"
    return value.astimezone(UTC).strftime("%Y-%m-%d")


def _when(value: datetime | None) -> str:
    """Date and minute, for an incident: `2026-09-29 20:14 UTC`.

    The log spans days, so a time of day alone is ambiguous, and seconds are noise at
    the resolution anyone reads an incident log.
    """
    if value is None:
        return "unknown"
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _rfc3339(value: datetime | None) -> str:
    """For Atom and `<time datetime>`."""
    if value is None:
        return ""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _duration(seconds: int | None) -> str:
    """Two units at most: `42s`, `4m 12s`, `2h 03m`, `3d 4h`."""
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


_EVENT_LABEL = {
    EventKind.DOWN: "Down",
    EventKind.REORG: "Reorg",
    EventKind.FORK: "Fork",
    EventKind.STALL: "Chain stalled",
    EventKind.CERT_EXPIRING: "Certificate expiring",
}

#: What several of one kind are called, for "7 outages in 24 h".
_EVENT_PLURAL = {
    EventKind.DOWN: "outages",
    EventKind.REORG: "reorgs",
    EventKind.FORK: "fork alerts",
    EventKind.STALL: "stalls",
    EventKind.CERT_EXPIRING: "warnings",
}

#: How the summed active time reads, for "14m 05s down in total". Absent for kinds whose
#: duration means nothing: a reorg is an instant, and a certificate warning lasts until
#: someone renews it.
_EVENT_ACTIVE = {
    EventKind.DOWN: "down",
    EventKind.FORK: "forked",
    EventKind.STALL: "stalled",
}


def _event_latest(event: Event) -> str:
    """When the latest occurrence began, as briefly as is unambiguous: a time of day
    when it is the same UTC day as the first, the full `when` otherwise."""
    latest = event.latest_start.astimezone(UTC)
    if latest.date() == event.started_at.astimezone(UTC).date():
        return latest.strftime("%H:%M UTC")
    return _when(latest)


def _event_first(event: Event) -> str:
    """When the first folded occurrence began, as briefly as is unambiguous: a time of day
    when it is the same UTC day as the latest — which is the time the log line leads
    with — and the full `when` otherwise."""
    first = event.started_at.astimezone(UTC)
    if first.date() == event.latest_start.astimezone(UTC).date():
        return first.strftime("%H:%M UTC")
    return _when(first)


def _epoch_ms(value: datetime | None) -> str:
    return "" if value is None else str(int(value.timestamp() * 1000))


def _short_hash(value: str | None) -> str:
    return f"{value[:10]}…" if value else "—"


# The node's `SyncStatus`, as the status API serialises it. Unknown values pass
# through as written rather than being hidden: a new state is still a fact.
_SYNC_LABEL = {
    "no_sync": "in sync",
    "initial": "starting",
    "awaiting_peers": "waiting for peers",
    "header_sync": "syncing headers",
    "txhashset_download": "downloading chain state",
    "txhashset_setup": "preparing chain state",
    "txhashset_rangeproofs_validation": "validating range proofs",
    "txhashset_kernels_validation": "validating kernels",
    "txhashset_save": "saving chain state",
    "txhashset_done": "chain state ready",
    "body_sync": "syncing blocks",
    "shutdown": "shutting down",
}


def _sync_label(value: str | None) -> str:
    if not value:
        return "—"
    return _SYNC_LABEL.get(value, value.replace("_", " "))


# ------------------------------------------------------------------- verdicts


class Verdict(NamedTuple):
    """The first screen's whole content.

    `tone` names the state for CSS: ok, warn, bad, info. `lead` plus `accent` form one
    sentence with the state word separated out so it can be coloured on its own;
    `accent` is None where the sentence has no single word to carry it. `second` is the
    specific fact behind the judgement, and `detail` is the consequence for the reader
    — present only when there is one, because a reassurance nobody needs is noise.
    """

    tone: str
    lead: str
    accent: str | None
    second: str
    detail: str | None


def _headline(snapshot: Snapshot | None) -> Verdict:
    """The answer, written as a sentence rather than a status label.

    The board already knows whether a reader can transact; it used to render that
    knowledge as "Everything is operating normally" in a tinted box the size of a
    cookie banner. This returns the same judgement as a short statement with one word
    carrying the state, so the page can set it at display size and stop repeating the
    counts that are already in the table below.

    `accent` is the one word that changes colour. Keeping it to one word is the whole
    discipline: a sentence where three things are coloured has no emphasis.
    """
    if snapshot is None:
        return Verdict(
            "info",
            "Starting up.",
            None,
            "The first round of checks has not finished.",
            None,
        )

    net = snapshot.network

    if snapshot.stale:
        return Verdict(
            "warn",
            "These numbers are",
            "stale",
            "The checker has not finished a round recently.",
            "Everything below is the last state it managed to record, not the "
            "current one.",
        )

    if net.forked:
        return Verdict(
            "bad",
            "Nodes",
            "disagree",
            net.fork_detail or "Two nodes report different blocks at the same height.",
            "Wait before transacting.",
        )

    if net.nodes_healthy == 0:
        return Verdict(
            "bad",
            "No public node is",
            "answering",
            "Either the network is down or this checker is.",
            "Both are possible. Treat this page with suspicion until it recovers.",
        )

    if net.epicbox_healthy == 0 and net.epicbox_total:
        return Verdict(
            "bad",
            "Epicbox is",
            "unreachable",
            f"The chain itself is fine — {net.nodes_healthy} of {net.nodes_total} "
            "nodes agree on the tip.",
            "Sending to an Epicbox address will fail. A transaction file still works.",
        )

    tip = f"{net.nodes_healthy} of {net.nodes_total} nodes agree on the tip"
    relays = f"{net.epicbox_healthy} of {net.epicbox_total} relays are up"

    if net.nodes_degraded or net.nodes_down or net.epicbox_down:
        return Verdict("warn", "The chain is", "healthy", f"{tip}, {relays}.", None)

    if net.nodes_total == 1:
        return Verdict("ok", "The chain is", "healthy", f"{tip}, {relays}.", None)

    return Verdict(
        "ok",
        "The chain is",
        "healthy",
        f"All {net.nodes_total} nodes agree on the tip, "
        f"all {net.epicbox_total} relays are up.",
        None,
    )


def _lag_note(status: TargetStatus) -> str:
    if status.tip_lag is None:
        return "—"
    if status.tip_lag <= 0:
        return "at tip"
    return f"−{status.tip_lag:,}"


def peers_note(awaiting: bool, tip_lag: int | None, failures: int) -> str | None:
    """The tooltip for a node that keeps reporting `awaiting_peers`, or None.

    Like `cert_note`, the sentence carries the reassurance with the fact: the state
    is transient and the node is usually answering and at tip while it lasts, which
    is exactly what the rest of the row shows. Only the parts that are true right now
    are claimed. Mirrored in app.js `peersNote`; change both.
    """
    if not awaiting:
        return None
    note = "Node reports waiting for peers. Usually clears within seconds"
    if failures == 0 and tip_lag is not None and tip_lag <= 0:
        return note + "; it is still reachable and at tip."
    if failures == 0:
        return note + "; it is still reachable."
    return note + "."


def cert_note(days: int | None, warn_days: int) -> str | None:
    """The tooltip for a relay whose certificate is near expiry, or None when it is not.

    Returning one value for both questions — is this worth marking, and what does the
    mark say — is deliberate. Two functions would be two places to change the window,
    and the marker appearing without a tooltip is exactly the failure this column
    already had.

    The wording carries the reassurance, not just the number. "Certificate expires in
    14 days" on its own reads as a fault on a row that is serving wallets perfectly
    well, which is how this ended up looking like an outage; saying in the same breath
    that the relay is online and unaffected is the difference between informing a
    reader and alarming one.
    """
    if days is None or days > warn_days:
        return None
    if days <= 0:
        # Practically unreachable — an expired certificate fails verification, so the
        # probe fails and the row is already red — but reachable in principle for the
        # seconds between expiry and the next sweep, and "expires in 0 days" is not a
        # sentence anyone should read.
        return "TLS certificate has expired — connections will fail verification"
    unit = "day" if days == 1 else "days"
    return (
        f"TLS certificate expires in {days} {unit} — the relay is online and "
        "answering; connections are unaffected until then"
    )


def probe_url(target: Target) -> str | None:
    """Where a browser can ask this host the same question the prober asks.

    The measurement a reader actually wants is from where they are sitting, not from
    London: a node that answers this page in 30 ms can be unusable from São Paulo, and
    no amount of server-side probing can tell them that. So the board hands the browser
    the address and lets it ask for itself.

    None means there is no address a browser could use — a pool whose adapter is not in
    the registry — and the control is then not rendered at all rather than rendered and
    broken.
    """
    if target.kind is Kind.NODE:
        return f"{target.endpoint.rstrip('/')}/v2/foreign"
    if target.kind is Kind.EPICBOX:
        # A WebSocket URL is already the whole address; the handshake is the probe.
        return target.endpoint
    adapter = ADAPTERS.get(target.adapter or "")
    if adapter is None:
        return None
    return f"{target.endpoint.rstrip('/')}{adapter.path}"


# --------------------------------------------------------------------- render


class ChainLink(NamedTuple):
    """One segment of the navbar's network switch."""

    chain: Chain
    label: str
    href: str
    current: bool


def _chain_links(chain: Chain, chains: Sequence[Chain], page: str) -> list[ChainLink]:
    """The switch, as links, staying on the page the reader is already on.

    Links rather than a `<select>` and a submit, for three reasons that all matter on
    this page: they work with JavaScript off, they are shareable and bookmarkable, and
    switching networks keeps a reader on /history if that is where they were. A
    control that silently returned them to the board would be a worse answer to
    "show me the same thing for floonet".

    Mainnet's href carries no parameter at all, so the canonical URL of the mainnet
    board stays `/` — the switch cannot create a second address for the same page and
    split search results between them.
    """
    base = "/history" if page == "history" else "/"
    links: list[ChainLink] = []
    for candidate in chains:
        query = "" if candidate is Chain.MAINNET else f"?chain={candidate.value}"
        links.append(
            ChainLink(
                chain=candidate,
                label=candidate.label,
                href=f"{base}{query}",
                current=candidate is chain,
            )
        )
    return links


def _base_context(
    snapshot: Snapshot | None,
    settings: Settings,
    *,
    chain: Chain = Chain.MAINNET,
    chains: Sequence[Chain] = (),
    page: str = "board",
) -> dict[str, Any]:
    verdict = _headline(snapshot)
    return {
        "site_name": settings.site_name,
        "site_url": settings.site_url,
        "source_url": settings.source_url,
        "snapshot": snapshot,
        "network": snapshot.network if snapshot else None,
        # The chain being viewed, and the switch for changing it. `chains` is what this
        # instance actually monitors, so a single-network install renders no switch —
        # see `Service.chains`.
        #
        # `page` is passed in rather than read from the template's own `{% set page %}`
        # because the switch has to build a URL, and URL construction does not belong in
        # Jinja. The two agree by construction: only the board and the history page are
        # chain-scoped, and every other page defaults to sending the switch to the board,
        # which is the only sensible destination from /api or /add.
        "chain": chain,
        "chain_label": chain.label,
        "chains": list(chains),
        "chain_links": _chain_links(chain, chains, page),
        # For links that should keep the reader on the network they are looking at.
        # Empty on mainnet, so `/` and `/history` stay the canonical mainnet URLs and no
        # page acquires a second address for the same content.
        "chain_query": "" if chain is Chain.MAINNET else f"?chain={chain.value}",
        "Chain": Chain,
        # Cache-busts the stylesheet and the script together. See `asset_version`:
        # without it a browser can keep a previous script indefinitely, and a script
        # that predates the network switch polls the wrong chain.
        "asset_v": asset_version(),
        "prober_id": settings.prober_id,
        "prober_region": settings.prober_region,
        "cadence_s": int(settings.cadence.node_tip_s),
        "epicbox_cadence_s": int(settings.cadence.epicbox_s),
        "pool_cadence_s": int(settings.cadence.pool_s),
        "submissions_enabled": settings.submissions_enabled,
        "verdict": verdict,
        # The tab's copy of the verdict: one word for the title, one file for the icon.
        "status_word": _STATUS_WORD.get(verdict.tone, "Starting up"),
        "status_icon": _STATUS_ICON.get(verdict.tone, "icon-unknown.svg"),
        # The header mark is drawn inline from the tone (see _mark.html); the favicon
        # is the file. Both come from the same verdict, so they cannot disagree.
        "status_tone": verdict.tone,
        # The footer's "Also on Tor" row is left out on the onion itself. See
        # `web.onion_request` for how the request is told apart.
        "onion": onion_request.get(),
        "generated_at": snapshot.generated_at if snapshot else None,
        "State": State,
        "Kind": Kind,
        "lag_note": _lag_note,
        "probe_url": probe_url,
        "own_node_url": settings.own_node_url,
        # Stated once per page, not once per row. The row templates compare against
        # these and show a bare number; the summary strip is what names the release.
        #
        # Read from the snapshot first, and fall back to settings only when there is no
        # snapshot to read. The summary strip in board.html already renders
        # `network.released_node_version`, so sourcing the row comparison from settings
        # instead let one page state that 4.0.4 is released while deciding which rows to
        # mark stale against a different number. The two agree whenever the snapshot was
        # produced by the running settings — poller.py sets the field from exactly this
        # value — so this only bites where it matters: re-rendering a snapshot taken
        # before a release bump, which is what the board does on its first paint after a
        # bump and what any stored snapshot does forever.
        "released_node_version": (
            (snapshot.network.released_node_version if snapshot else None)
            or settings.released_node_version
            or None
        ),
        "released_node_url": (
            (snapshot.network.released_node_url if snapshot else None) or releases.NODE_URL
        ),
        "released_wallet_version": (
            (snapshot.network.released_wallet_version if snapshot else None) or releases.WALLET
        ),
        "released_wallet_url": releases.WALLET_URL,
        "epicbox_protocol": releases.EPICBOX_PROTOCOL,
        # The day count at which the TLS column grows its amber marker. Config, not a
        # literal, because the same number is needed by the template that paints the
        # first render and by the script that repaints on every poll — and when it was
        # written as `14` in both, `cert_warn_days` could be changed in config without
        # either of them noticing.
        "cert_warn_days": settings.thresholds.cert_warn_days,
        # Rendered once into the context rather than called per row: a macro invocation per
        # template is the same markup either way, and this keeps the drawing in one module.
        "icon_boxes": icons.boxes(15),
        "icon_check": icons.check_check(15),
        # 12px, and small on purpose. The marker's job is to be findable by someone
        # scanning the TLS column, not to compete with the state word at the end of the
        # row — a relay with three weeks of certificate left is not an incident.
        "icon_warn": icons.triangle_alert(12),
        "icon_peers": icons.users(13),
        "peers_note": peers_note,
        "epicbox_url": releases.EPICBOX_URL,
        # Strictly-older, not merely-different. A relay ahead of the published
        # protocol number is a normal state and must not be marked as behind.
        "version_behind": version_behind,
        # Bound to the configured window here so the template asks one question —
        # "is there a note for this many days?" — and cannot disagree with the
        # threshold the way a second inline comparison would.
        "cert_note": partial(cert_note, warn_days=settings.thresholds.cert_warn_days),
    }


def render_board(
    *,
    snapshot: Snapshot | None,
    settings: Settings,
    chain: Chain = Chain.MAINNET,
    chains: Sequence[Chain] = (),
    qc: QuickCheckResult | None = None,
    qc_input: str = "",
    icons: Mapping[tuple[str, str], Any] | None = None,
) -> str:
    """The board. `qc` is a quick-check result to render already open — the no-JavaScript
    path, where the check is a form post and the answer is the whole page again."""
    context = _base_context(snapshot, settings, chain=chain, chains=chains, page="board")
    context["countries"] = _country_options()
    context["nodes"] = snapshot.nodes if snapshot else []
    context["relays"] = snapshot.epicbox if snapshot else []
    context["pools"] = snapshot.pools if snapshot else []
    context["quickcheck_enabled"] = getattr(settings, "quickcheck_enabled", True)
    context["qc"] = qc
    context["qc_input"] = qc_input
    # (kind, slug) → the approved server icon, drawn in each row's tile. Relative URLs, so
    # the onion mirror serves its own copies and a Tor reader never leaves Tor.
    context["server_icons"] = icons or {}
    return _environment().get_template("board.html").render(**context)


_INITIALS_SKIP = frozenset({"node", "epicbox", "www"})


def server_initials(operator: str | None, host: str) -> str:
    """Two letters for a server's tile, by the wallet's rule (`serverInitials` in the app's
    server list), so a server reads the same on this page and in the app.

    From the operator when there is one: the first letters of its first two words, a
    camel-cased name splitting into words, or the first two letters of a one-word name.
    Otherwise from the host: the first two letters of its first label past `node.`,
    `epicbox.` or `www.`.
    """
    name = (operator or "").strip()
    if name:
        spaced = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name)
        words = [w for w in re.split(r"[\s\-_.]+", spaced) if w]
        if len(words) >= 2:
            return (words[0][0] + words[1][0]).upper()
        if len(words) == 1:
            return words[0][:2].upper()
    labels = [p for p in host.split(":")[0].split(".") if p and p not in _INITIALS_SKIP]
    return labels[0][:2].upper() if labels else "?"


def server_tint(operator: str | None, host: str) -> int:
    """Which of three muted tints an initials tile gets: 0 accent, 1 info, 2 ink.

    The app's hash, kept bit for bit (31-multiplier over UTF-16 code units, masked to 31
    bits), so an operator's tile is the same colour here as in the wallet.
    """
    seed = 17
    data = (operator or host).lower().encode("utf-16-le")
    for i in range(0, len(data), 2):
        seed = (seed * 31 + int.from_bytes(data[i : i + 2], "little")) & 0x7FFFFFFF
    return seed % 3


def render_quickcheck_result(
    *, result: QuickCheckResult, settings: Settings, chain: Chain = Chain.MAINNET
) -> str:
    """Only the result of a quick check, for app.js to swap into the open box.

    Rendered by the same macro the full page uses, so the scripted path and the form path
    cannot drift into describing one result two ways.
    """
    context = _base_context(None, settings, chain=chain, page="board")
    template = _environment().get_template("_quickcheck.html")
    module = template.make_module(context)
    return str(module.result(result))  # type: ignore[attr-defined]


def render_history(
    *,
    snapshot: Snapshot | None,
    settings: Settings,
    bars: dict[str, list[tuple[str, float | None]]],
    events: Sequence[Event] = (),
    chain: Chain = Chain.MAINNET,
    chains: Sequence[Chain] = (),
) -> str:
    context = _base_context(
        snapshot, settings, chain=chain, chains=chains, page="history"
    )
    context["rows"] = (
        (snapshot.nodes + snapshot.epicbox + snapshot.pools) if snapshot else []
    )
    context["bars"] = bars
    context["bar_class"] = _bar_class
    context["events"] = list(events)
    context["activity"] = snapshot.network.activity if snapshot else None
    context["Severity"] = Severity
    return _environment().get_template("history.html").render(**context)


def render_feed(
    *,
    events: Sequence[Event],
    settings: Settings,
    chain: Chain,
    self_url: str,
) -> str:
    """The incident log as Atom.

    One entry per incident, keyed by its database id, so a feed reader shows an outage
    once and then updates the same entry when it resolves rather than posting twice.
    A repeat inside the dedupe window is the same entry again, with a count and a newer
    `<updated>`, so a flapping host is one line in a reader rather than one per drop.
    This is the alerting path the project can offer without sending anything itself:
    a reader, or a feed-to-chat bot, pulls it.
    """
    base = settings.site_url.rstrip("/")
    host = base.split("://", 1)[-1].split("/", 1)[0]
    updated = max((e.updated_at for e in events), default=datetime.now(UTC))
    context = {
        "site_name": settings.site_name,
        "chain": chain,
        "events": list(events),
        "base": base,
        "tag_host": host,
        "self_url": self_url,
        "history_url": f"{base}/history"
        + ("" if chain is Chain.MAINNET else f"?chain={chain.value}"),
        "updated": updated,
    }
    return _environment().get_template("feed.xml").render(**context)


def _country_options() -> list[tuple[str, str]]:
    """(code, name) for every country the flag set can actually draw, alphabetical by name.

    Drawn from `flags.FLAG_CODES` rather than from a full ISO 3166 list on purpose: offering a
    country the board renders as a two-letter chip would let a submitter pick something the
    page cannot show. The field is optional, and an operator can set anything at all from the
    admin editor, so the picker is a convenience rather than the authority.
    """
    from .flags import COUNTRY_NAMES, FLAG_CODES

    pairs = [(code, COUNTRY_NAMES.get(code, code)) for code in FLAG_CODES]
    return sorted(pairs, key=lambda pair: pair[1])


def render_submit(
    *,
    snapshot: Snapshot | None,
    settings: Settings,
    message: str | None = None,
    error: str | None = None,
    submitted_host: str = "",
    icon_max_kb: int = 1024,
) -> str:
    context = _base_context(snapshot, settings)
    context["message"] = message
    context["error"] = error
    context["submitted_host"] = submitted_host
    context["probes_required"] = settings.submit_probes_required
    context["probe_interval_s"] = int(settings.submit_probe_interval_s)
    context["countries"] = _country_options()
    context["icon_max_kb"] = icon_max_kb
    return _environment().get_template("submit.html").render(**context)


def render_api(*, settings: Settings) -> str:
    """The API reference.

    Routes, parameters, a command and the returned shape. Nothing else: the responses
    carry their own `meta`, so the page does not explain the service.
    """
    base = settings.site_url.rstrip("/")
    # One line of purpose, the parameters, a command that runs anywhere, and the shape of
    # what comes back. No explanation of how the service works: every response now carries
    # a `meta` object describing itself, so a consumer that never opens this page still
    # knows what it received.
    #
    # `curl | python3 -m json.tool` rather than `| jq`: jq is not installed by default
    # anywhere, and a documented command that fails on a clean machine is worse than no
    # command. Python 3 is already a requirement to run this service.
    endpoints = [
        {
            "method": "GET",
            "path": "/api/v1/status.json",
            "anchor": "status",
            "tag": "everything",
            "why": "The whole board: network summary, then every node, relay and pool.",
            "params": [
                {
                    "name": "chain=floonet",
                    "what": "The test network instead of mainnet. One chain per document.",
                },
            ],
            "caption": "Network summary",
            "example": (
                f"curl -s {base}/api/v1/status.json \\\n"
                "  | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"network\"])'"
            ),
            "returns": (
                "{\n"
                '  "meta": { "describes": ..., "states": ..., "absent": [...] },\n'
                '  "generated_at": "2026-09-22T18:10:14Z",\n'
                '  "stale": false,\n'
                '  "prober":  { "id": ..., "region": ..., "measures": ... },\n'
                '  "network": { "tip_height": ..., "health_score": ..., ... },\n'
                '  "nodes":   [ ... ],\n'
                '  "epicbox": [ ... ],\n'
                '  "pools":   [ ... ]\n'
                "}"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/nodes.json",
            "anchor": "nodes",
            "tag": "list",
            "why": "Endpoint URLs, for a wallet config or a failover list.",
            "params": [
                {"name": "healthy=true", "what": "Only nodes answering and at the tip."},
                {
                    "name": "chain=floonet",
                    "what": "The test network instead of mainnet.",
                },
            ],
            "caption": "Endpoints you can point a wallet at",
            "example": f"curl -s '{base}/api/v1/nodes.json?healthy=true'",
            "returns": (
                "{\n"
                '  "meta": {\n'
                '    "describes": "Epic Cash mainnet public node endpoints",\n'
                '    "filtered": "healthy",\n'
                '    "count": 3,\n'
                '    "total_monitored": 3,\n'
                '    "refreshed_every_s": 5.0,\n'
                '    "measured_from": "btlabs-lon",\n'
                '    "docs": "' + base + '/api"\n'
                "  },\n"
                '  "generated_at": "2026-09-22T18:10:14Z",\n'
                '  "chain": "mainnet",\n'
                '  "tip_height": 3721882,\n'
                '  "nodes": ["https://node.btlabs.uk", ...]\n'
                "}"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/epicbox.json",
            "anchor": "epicbox",
            "tag": "list",
            "why": "Relay hosts, same shape.",
            "params": [
                {"name": "healthy=true", "what": "Only relays that completed a handshake."},
                {
                    "name": "chain=floonet",
                    "what": "The test network instead of mainnet.",
                },
            ],
            "caption": "Relays reachable now",
            "example": f"curl -s '{base}/api/v1/epicbox.json?healthy=true'",
            "returns": (
                "{\n"
                '  "meta": { "describes": "Epicbox relay hosts, ...", "filtered": "healthy", ... },\n'
                '  "generated_at": "2026-09-22T18:10:14Z",\n'
                '  "epicbox": ["epicbox.epiccash.com", ...]\n'
                "}"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/pools.json",
            "anchor": "pools",
            "tag": "list",
            "why": "Pool hosts, same shape.",
            "params": [
                {"name": "healthy=true", "what": "Only pools returning valid stats."},
                {
                    "name": "chain=floonet",
                    "what": "The test network instead of mainnet.",
                },
            ],
            "caption": "Pools answering",
            "example": f"curl -s '{base}/api/v1/pools.json?healthy=true'",
            "returns": (
                "{\n"
                '  "meta": { "describes": "Mining pools whose stats API answered", ... },\n'
                '  "generated_at": "2026-09-22T18:10:14Z",\n'
                '  "pools": ["epicmine.io", ...]\n'
                "}"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/icons/{hash}-{size}.png",
            "anchor": "icons",
            "tag": "images",
            "why": (
                "A server's icon, as linked from its `icon` in status.json: a square PNG, "
                "128 or 256 px, named by its content hash and cached for a year. Only "
                "approved icons are served. `icon: null` means none: show the initials."
            ),
            "params": [],
            "caption": "Every node that has an icon",
            "example": (
                f"curl -s {base}/api/v1/status.json \\\n"
                "  | python3 -c 'import sys,json; "
                "[print(n[\"id\"], n[\"icon\"][\"url\"]) for n in json.load(sys.stdin)"
                "[\"nodes\"] if n[\"icon\"]]'"
            ),
            "returns": (
                '"icon": {\n'
                '  "url": "' + base + '/api/v1/icons/3f9c0a6d1b2e4c5f7a8b-256.png",\n'
                '  "urls": { "128": ".../3f9c0a6d1b2e4c5f7a8b-128.png", "256": "..." },\n'
                '  "hash": "3f9c0a6d1b2e4c5f7a8b",\n'
                '  "updated_at": "2026-10-24T15:40:00Z"\n'
                "}"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/events.json",
            "anchor": "events",
            "tag": "incidents",
            "why": (
                "The incident log: outages, reorgs, forks, stalls and certificates close "
                "to expiry. One entry per source per 24 hours, with repeats counted in "
                "`occurrences`; `ended_at` is null while the latest one lasts."
            ),
            "params": [
                {"name": "min=warn", "what": "Drop routine one-block reorgs and notices."},
                {"name": "limit=50", "what": "Up to 200, newest first."},
                {"name": "chain=floonet", "what": "The test network instead of mainnet."},
            ],
            "caption": "What is still going on",
            "example": (
                f"curl -s '{base}/api/v1/events.json?min=warn' \\\n"
                "  | python3 -c 'import sys,json; "
                "[print(e[\"kind\"], e[\"subject\"]) for e in json.load(sys.stdin)"
                "[\"events\"] if e[\"ended_at\"] is None]'"
            ),
            "returns": (
                "{\n"
                '  "chain": "mainnet",\n'
                '  "min_severity": "warn",\n'
                '  "events": [{\n'
                '    "kind": "down", "severity": "warn",\n'
                '    "subject": "node.example.org:3413", "detail": "timed out",\n'
                '    "started_at": "2026-09-29T20:14:05Z", "ended_at": null, ...\n'
                "  }]\n"
                "}"
            ),
        },
        {
            "method": "GET",
            "path": "/feed.atom",
            "anchor": "feed",
            "tag": "subscribe",
            "why": (
                "The same log as Atom, for a feed reader or a feed-to-chat bot. An "
                "incident is one entry, updated in place when it resolves."
            ),
            "params": [
                {"name": "min=info", "what": "Include one-block reorgs and notices."},
                {"name": "chain=floonet", "what": "The test network instead of mainnet."},
            ],
            "caption": "Newest entry",
            "example": f"curl -s {base}/feed.atom | grep -m1 '<title>Down'",
            "returns": "<title>Down — node.example.org:3413</title>",
        },
        {
            "method": "GET",
            "path": "/badge/{id}.svg",
            "anchor": "badge",
            "tag": "embed",
            "why": (
                "An SVG badge with a target's state and 30-day uptime, for a README. "
                "Drawn here, so embedding it discloses readers to nobody else."
            ),
            "params": [
                {"name": "kind=epicbox", "what": "When a node and a relay share an id."},
                {"name": "label=my node", "what": "Replace the left-hand text."},
            ],
            "caption": "Markdown",
            "example": f"![status]({base}/badge/node.epiccash.com.svg)",
            "returns": "epic node | healthy · 99.97%",
        },
        {
            "method": "GET",
            "path": "/api/v1/health",
            "anchor": "health",
            "tag": "this service",
            "why": (
                "Liveness of this monitor, not of Epic Cash. 503 when the snapshot is "
                "stale. Point alerting here, not at the board."
            ),
            "params": [],
            "caption": "Exit status is what matters",
            "example": f"curl -sf {base}/api/v1/health > /dev/null || echo down",
            "returns": (
                "200\n"
                "{\n"
                '  "service": "epic-status",\n'
                '  "version": "0.1.0",\n'
                '  "prober_id": "btlabs-lon",\n'
                '  "has_data": true,\n'
                '  "stale": false,\n'
                '  "generated_at": "2026-09-22T18:16:27Z"\n'
                "}"
            ),
        },
        {
            "method": "POST",
            "path": "/api/v1/submit",
            "anchor": "submit",
            "tag": "open",
            "why": "Request a server. Checked automatically, then reviewed before it appears.",
            "params": [
                {"name": "kind", "what": "node, epicbox or pool."},
                {"name": "host", "what": "Hostname, with a port if it is not the default."},
                {"name": "operator", "what": "Optional. Who runs it."},
                {
                    "name": "icon",
                    "what": (
                        "Optional file, as multipart/form-data. PNG, JPEG or WebP, up to "
                        "1 MB and 2048 px, not animated; no SVG. Re-encoded here and shown "
                        "only once approved."
                    ),
                },
            ],
            "caption": "Submit a node, with an icon",
            "example": (
                f"curl -X POST {base}/api/v1/submit \\\n"
                "  -F kind=node \\\n"
                "  -F host=node.example.org:3413 \\\n"
                '  -F operator="Example Pool" \\\n'
                "  -F icon=@logo.png"
            ),
            "returns": (
                "202\n"
                "{\n"
                '  "ok": true,\n'
                '  "message": "example.org:3413 received. It will be checked 3 times...",\n'
                '  "next": {\n'
                '    "review_required": true,\n'
                '    "probed_automatically": true,\n'
                '    "checks_required": 3,\n'
                '    "check_interval_s": 60.0,\n'
                '    "then": "reviewed by an operator before it appears on the board"\n'
                "  }\n"
                "}"
            ),
        },
    ]

    etag_example = (
        f"etag=$(curl -sI {base}/api/v1/status.json | grep -i ^etag | cut -d' ' -f2)\n"
        f"curl -s -o /dev/null -w '%{{http_code}}\\n' \\\n"
        f"  -H \"if-none-match: $etag\" {base}/api/v1/status.json\n"
        "304"
    )

    # The shared context, not a hand-picked subset. This page extends base.html, which
    # reads the nav flags, the cadences, the prober id and the released protocol version —
    # and the environment uses StrictUndefined, so the first missing key is a 500 rather
    # than a blank in the markup. Passing four variables by hand is how /api went down.
    context = _base_context(None, settings)
    context.update(endpoints=endpoints, etag_example=etag_example)
    return _environment().get_template("api.html").render(**context)


def render_admin_login(*, settings: Settings, error: str | None = None) -> str:
    """The sign-in form. No snapshot: it must render before the first sweep and while the
    poller is broken, since a broken poller is one reason to sign in."""
    context = _base_context(None, settings)
    context["error"] = error
    return _environment().get_template("admin_login.html").render(**context)


def render_admin(
    *,
    settings: Settings,
    submissions: Sequence[Any],
    counts: dict[str, int],
    targets: Sequence[Any],
    on_board: int,
    csrf: str,
    user: str,
    notice: str | None = None,
    pending_icons: Sequence[Any] = (),
    icons_by_submission: dict[int, Any] | None = None,
    active_icons: dict[tuple[str, str], Any] | None = None,
    staged_icons: dict[tuple[str, str], Any] | None = None,
    icon_settings: Any = None,
) -> str:
    """The review queue.

    `submissions` is a sequence of `sqlite3.Row`, passed straight through rather than
    mapped into models. The dashboard shows the row as stored — including the probe
    counters and the last error — because the whole point is to look at the evidence before
    deciding, and a model that dropped a field would quietly narrow what a reviewer sees.
    """
    context = _base_context(None, settings)
    context.update(
        submissions=submissions,
        counts=counts,
        targets=targets,
        on_board=on_board,
        csrf=csrf,
        user=user,
        notice=notice,
        pending_icons=pending_icons,
        icons_by_submission=icons_by_submission or {},
        active_icons=active_icons or {},
        staged_icons=staged_icons or {},
        # The preview shows the 128 px rendition, the size a wallet tile draws at 2x.
        icon_preview_size=min(icon_settings.sizes) if icon_settings else 128,
        icon_max_kb=(icon_settings.max_bytes // 1024) if icon_settings else 1024,
    )
    return _environment().get_template("admin.html").render(**context)


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


DONATE_ADDRESSES = (
    {
        "label": "Epicbox",
        "note": "Send over Epicbox.",
        "value": "esWxboBPMgL4RqufRYcGUJ7t6YVWGvyuid6xRM62UkRzSb3jUcNK@epicbox.epiccash.com",
        "qr": "epicbox",
    },
    {
        "label": "HTTPS",
        "note": "BT Labs on the web.",
        "value": "https://wallet.btlabs.uk",
        "qr": "https",
    },
    {
        "label": "Tor",
        "note": "The same, as an onion service.",
        "value": "http://4ulfddx7retnirrzmvdp62xg5w4wunvj5nuivwnpzghrlaqobxiwvcqd.onion",
        "qr": "tor",
    },
)


def render_donate(*, settings: Settings) -> str:
    """The donate page: static addresses and a thank-you, no snapshot needed."""
    context = _base_context(None, settings)
    context["donate_addresses"] = DONATE_ADDRESSES
    return _environment().get_template("donate.html").render(**context)
