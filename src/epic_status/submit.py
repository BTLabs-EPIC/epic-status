"""Public submissions.

The model is monero.fail's and grin.fail's, because it is the only one that has
been shown to work on community infrastructure: an open POST with no human in the
loop. Validate mechanically, promote on repeated successful probes, and let dead
entries remove themselves. Moderation queues on volunteer projects go unattended
within a month, and a queue nobody empties is worse than no queue — it looks like
a process while being a bin.

What is added on top of the prior art, because the prior art does not have it:

* The submitted host is **never contacted by the main poller** until it has passed
  validation. It lives in a separate table until then, so a submission cannot make
  the sweep fan out to an attacker-chosen host.
* The SSRF checks in `net.resolve_endpoint` run before the first connection.
* Three probes, spaced a minute apart, before the entry is public. One success is
  luck; three across three minutes is a server.
* The chain is **detected**, not trusted. A submitter's claim about which network
  their node serves is not evidence.
* Epicbox hostnames are checked for the hyphen rule, which nothing else would
  catch: a hyphenated relay handshakes perfectly and would publish green while
  every address on it is unparseable.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from .config import Settings
from .db import Database
from .models import Kind, Source, Target
from .net import TargetRejected, resolve_endpoint
from .probes.epicbox import domain_is_addressable, probe_relay
from .probes.node import probe_tip

log = logging.getLogger("epic_status.submit")

_HOST_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class SubmissionError(Exception):
    """Rejected at the door, with a reason fit to show the submitter.

    Every message here is written to be actionable on its own. "Invalid input" on a
    form for server operators generates a support conversation; naming the rule does
    not.
    """


def _hash_submitter(address: str, salt: str) -> str:
    """A salted hash of the submitter's address, never the address itself.

    Enough to rate limit and to recognise a flood. Not a record of who submitted
    what, which is not information this project should be holding — least of all on
    a privacy coin's own infrastructure page.
    """
    return hashlib.sha256(f"{salt}:{address}".encode()).hexdigest()[:32]


def normalise(kind: Kind, raw: str) -> tuple[str, str]:
    """Return (display_host, endpoint) or raise SubmissionError.

    Accepts what an operator would actually paste: a bare host, a host:port, or a
    full URL. Normalising here rather than at the probe means the stored endpoint is
    canonical and duplicate detection works.
    """
    text = raw.strip().rstrip("/")
    if not text:
        raise SubmissionError("Enter a hostname.")
    if len(text) > 253:
        raise SubmissionError("That hostname is too long to be real.")

    if "://" in text:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        port = parts.port
    else:
        scheme = ""
        host, _, port_text = text.rpartition(":")
        if not host:
            host, port = text, None
        else:
            try:
                port = int(port_text)
            except ValueError:
                raise SubmissionError(
                    f"Could not read a port from {port_text!r}."
                ) from None

    host = host.lower().strip("[]")
    if not host:
        raise SubmissionError("Enter a hostname.")
    if not (_HOST_RE.match(host) or _IPV4_RE.match(host)):
        raise SubmissionError(
            f"{host!r} is not a hostname or an IPv4 address. "
            "IPv6 targets must be submitted as a hostname."
        )
    if port is not None and not 1 <= port <= 65535:
        raise SubmissionError(f"Port {port} is out of range.")

    if kind is Kind.EPICBOX:
        if not domain_is_addressable(host):
            # The single least guessable rule in the whole project.
            raise SubmissionError(
                f"{host!r} cannot be used as an Epicbox domain. Epicbox addresses "
                "permit only letters, digits and dots — a hyphen or underscore in "
                "the hostname means the relay answers fine but no wallet can parse "
                "an address on it, so listing it would publish a broken endpoint "
                "as healthy."
            )
        # Port 443 is normalised away because Epicbox address display omits it, so
        # `host` and `host:443` are the same relay and must not both be listed.
        port = port or 443
        endpoint = f"wss://{host}:{port}/"
        display = host if port == 443 else f"{host}:{port}"
        return display, endpoint

    if scheme in {"ws", "wss"}:
        raise SubmissionError("That looks like an Epicbox URL. Choose Epicbox above.")

    # A node with no port given is assumed to be fronted by a reverse proxy on 443,
    # which is the better deployment and the one a bare hostname implies.
    if port is None:
        endpoint = f"https://{host}"
        display = host
    else:
        endpoint = f"{scheme or 'https'}://{host}:{port}"
        display = f"{host}:{port}"
    return display, endpoint


async def accept(
    db: Database,
    settings: Settings,
    *,
    kind: Kind,
    raw_host: str,
    operator: str | None,
    submitter_address: str,
    salt: str,
) -> str:
    """Validate and queue a submission. Returns the message to show.

    Nothing here probes the target. The first contact happens on the validation
    pass, out of band, so a POST cannot be used to make this server connect to an
    arbitrary host synchronously — which would turn the form into a port scanner
    with a timing oracle attached.
    """
    if not settings.submissions_enabled:
        raise SubmissionError("Submissions are closed on this instance.")

    display, endpoint = normalise(kind, raw_host)

    if operator:
        operator = operator.strip()[:64] or None

    # SSRF check before anything is stored, so a rejected host leaves no trace and
    # the submitter gets the real reason immediately.
    try:
        await resolve_endpoint(
            endpoint, allow_private=settings.allow_private_targets
        )
    except TargetRejected as exc:
        raise SubmissionError(exc.message) from exc

    # Dedupe on all three identifiers, not just the slug. A seed entry may be
    # recorded as `node.epicnet.us` while the same submission normalises to
    # `node.epicnet.us:3413`; comparing slugs alone let an already-listed node
    # through and would have produced a duplicate row on the board.
    existing = db.conn.execute(
        """
        SELECT display_host FROM targets
         WHERE kind = ? AND (slug = ? OR display_host = ? OR endpoint = ?)
        """,
        (kind.value, display, display, endpoint),
    ).fetchone()
    if existing:
        raise SubmissionError(f"{existing['display_host']} is already listed.")

    if db.pending_submission_count() >= settings.max_pending_submissions:
        # A cap rather than a queue that grows without bound. Without it, the
        # validation pass itself becomes the amplifier.
        raise SubmissionError(
            "There are too many submissions waiting to be checked. Try again later."
        )

    submitter_hash = _hash_submitter(submitter_address, salt)
    if db.recent_submissions_by(submitter_hash, timedelta(hours=1)) >= 5:
        raise SubmissionError("Too many submissions from your address in the last hour.")

    inserted = db.insert_submission(
        kind=kind,
        host=display,
        endpoint=endpoint,
        operator=operator,
        submitter_hash=submitter_hash,
        next_probe_at=datetime.now(UTC),
    )
    if inserted is None:
        raise SubmissionError(f"{display} has already been submitted and is being checked.")

    return (
        f"{display} queued. It will be probed {settings.submit_probes_required} times, "
        f"{int(settings.submit_probe_interval_s)} seconds apart, and appears on the "
        "board as soon as it passes."
    )


class Validator:
    """The out-of-band pass that promotes submissions.

    Runs on its own slow schedule rather than inside the sweep, because a pending
    submission is by definition an unvetted host and must not share a deadline with
    the probes the board depends on.
    """

    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    async def tick(self, client: httpx.AsyncClient, insecure: httpx.AsyncClient) -> None:
        for row in self.db.due_submissions():
            try:
                await self._check(row, client, insecure)
            except Exception:
                log.exception("validating submission %s failed", row["host"])

    async def _check(
        self, row: object, client: httpx.AsyncClient, insecure: httpx.AsyncClient
    ) -> None:
        import sqlite3

        assert isinstance(row, sqlite3.Row)
        kind = Kind(row["kind"])
        attempted = int(row["probes_attempted"]) + 1
        passed = int(row["probes_passed"])
        required = self.settings.submit_probes_required

        try:
            resolved = await resolve_endpoint(
                row["endpoint"], allow_private=self.settings.allow_private_targets
            )
        except TargetRejected as exc:
            self._reject(row, exc.message)
            return

        ok = False
        error: str | None = None
        height: int | None = None

        if kind is Kind.NODE:
            probe = await probe_tip(client, insecure, resolved)
            ok, error, height = probe.ok, probe.error, probe.height
        else:
            relay = await probe_relay(resolved, timeout=self.settings.ws_timeout_s)
            ok, error = relay.ok, relay.error

        if ok and kind is Kind.NODE:
            # Chain detection, not chain declaration. Compared against the fleet
            # rather than a hardcoded height so it stays correct forever.
            tip = self._fleet_tip()
            if tip is not None and height is not None:
                lag = abs(tip - height)
                if lag > self.settings.thresholds.tip_lag_down:
                    ok = False
                    error = (
                        f"height {height:,} is {lag:,} blocks from the network tip "
                        f"({tip:,}) — this does not look like mainnet"
                    )

        if ok:
            passed += 1

        if passed >= required:
            self._promote(row, kind)
            return

        # A single failure does not reject: a host can be restarting. But attempts
        # are capped so a permanently broken submission does not sit in the queue
        # forever occupying a slot against the pending limit.
        if attempted >= required * 3:
            self._reject(row, error or "did not respond to enough probes")
            return

        self.db.update_submission(
            int(row["id"]),
            probes_passed=passed,
            probes_attempted=attempted,
            next_probe_at=datetime.now(UTC)
            + timedelta(seconds=self.settings.submit_probe_interval_s),
            status="pending",
            last_error=error,
        )

    def _fleet_tip(self) -> int | None:
        found = self.db.conn.execute(
            """
            SELECT MAX(height) AS tip FROM checks
             WHERE ok = 1 AND height IS NOT NULL
               AND checked_at >= strftime('%Y-%m-%dT%H:%M:%SZ','now','-5 minutes')
            """
        ).fetchone()
        return int(found["tip"]) if found and found["tip"] is not None else None

    def _promote(self, row: object, kind: Kind) -> None:
        import sqlite3

        assert isinstance(row, sqlite3.Row)
        self.db.insert_target(
            Target(
                kind=kind,
                slug=row["host"],
                endpoint=row["endpoint"],
                display_host=row["host"],
                operator=row["operator"],
                source=Source.SUBMITTED,
            )
        )
        self.db.update_submission(
            int(row["id"]),
            probes_passed=int(row["probes_passed"]) + 1,
            probes_attempted=int(row["probes_attempted"]) + 1,
            next_probe_at=None,
            status="accepted",
            last_error=None,
        )
        log.info("accepted submission %s (%s)", row["host"], kind.value)

    def _reject(self, row: object, reason: str) -> None:
        import sqlite3

        assert isinstance(row, sqlite3.Row)
        self.db.update_submission(
            int(row["id"]),
            probes_passed=int(row["probes_passed"]),
            probes_attempted=int(row["probes_attempted"]) + 1,
            next_probe_at=None,
            status="rejected",
            last_error=reason,
        )
        log.info("rejected submission %s: %s", row["host"], reason)
