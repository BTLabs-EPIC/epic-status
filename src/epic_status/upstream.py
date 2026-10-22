"""What upstream has released, read from GitHub's releases API and remembered.

The board compares every node's reported version with the published release, so that
number has to follow upstream without a code change. It used to be a committed
constant, and it went stale the day 4.1.0 shipped: the board kept saying 4.0.4 was
current while every node it listed already ran 4.1.0.

How this stays inside the rest of the design:

* **Server-side and off the render path.** One background task reads
  `GET /repos/{owner}/{repo}/releases/latest` for the node and the wallet every few
  hours. No page waits on it, no reader's browser contacts GitHub, and a page renders
  exactly as before when GitHub is unreachable.
* **Cheap.** Each answer's `ETag` is kept and sent back as `If-None-Match`; GitHub
  answers an unchanged release with 304, which does not count against the 60 requests
  an hour an unauthenticated client gets. Two repositories every three hours is a
  handful a day either way.
* **Last good value, never a gap.** A failure — timeout, 5xx, rate limit, a body that
  does not parse — keeps whatever was known before. The last answer is stored in
  SQLite, so a restart during a GitHub outage keeps it too. `releases.py` is only the
  seed for a fresh database.
* **Never backwards.** The published value is the highest of the seed and every
  answer GitHub has given, compared as semver. GitHub's "latest" is the most recently *created*
  non-draft, non-prerelease release, so a maintenance release cut for an older line
  after a newer one would otherwise move "latest" down and mark nodes on the newer
  release as current and everyone else wrongly.
* **Strict about tags.** `v4.1.0`, `4.1.0` and `v4.1` are releases; `v4.1.0-rc1` is
  not, whatever the prerelease flag says. Anything else is ignored rather than shown.
* **An operator's pin wins.** `EPIC_STATUS_RELEASED_NODE_VERSION`, when set, is used
  as given and the node repository is not fetched. `EPIC_STATUS_RELEASE_CHECK=false`
  turns the fetch off entirely, for an instance that must contact nothing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

import httpx

from . import releases
from .config import Settings
from .db import Database

log = logging.getLogger("epic_status.upstream")

API_BASE: Final = "https://api.github.com"
TIMEOUT_S: Final = 10.0
MAX_BODY_BYTES: Final = 1 << 20
"""A release object with its notes and asset list is tens of kilobytes; a megabyte is
room for an unusually long changelog and still a bound."""

MIN_INTERVAL_S: Final = 3600.0
MAX_INTERVAL_S: Final = 21600.0
RETRY_AFTER_FAILURE_S: Final = 900.0
"""A transient failure is retried sooner than the normal interval, but not so soon
that a GitHub outage turns into a request every sweep."""

MIN_BACKOFF_S: Final = 60.0

Source = Literal["seed", "github", "pinned"]


# ------------------------------------------------------------------------ versions

_TAG_RE = re.compile(
    r"[vV]?(?P<major>\d{1,6})\.(?P<minor>\d{1,6})(?:\.(?P<patch>\d{1,6}))?"
    r"(?:\+[0-9A-Za-z.-]{1,64})?"
)


def parse_tag(tag: object) -> str | None:
    """A release tag as a plain `major.minor.patch`, or None if it is not one.

    Build metadata (`+…`) is dropped, as semver says it carries no precedence. A
    prerelease suffix (`-rc1`, `-beta`) is refused: a node running a release candidate
    is not running the release, and a candidate must never become the number every
    node is measured against.
    """
    if not isinstance(tag, str):
        return None
    match = _TAG_RE.fullmatch(tag.strip())
    if match is None:
        return None
    patch = match["patch"] or "0"
    return f"{int(match['major'])}.{int(match['minor'])}.{int(patch)}"


def semver_key(version: str) -> tuple[int, int, int]:
    """Numeric precedence, so 4.0.10 sorts above 4.0.9. Raises on a non-version."""
    parsed = parse_tag(version)
    if parsed is None:
        raise ValueError(f"not a release version: {version!r}")
    major, minor, patch = (int(part) for part in parsed.split("."))
    return major, minor, patch


# ------------------------------------------------------------------------- repos


@dataclass(frozen=True)
class Repo:
    key: str
    owner: str
    name: str
    seed: str

    @property
    def api_url(self) -> str:
        return f"{API_BASE}/repos/{self.owner}/{self.name}/releases/latest"

    def tag_url(self, tag: str) -> str:
        # The tag has passed `parse_tag`'s pattern, so it is digits, dots, a leading
        # v and at most a build suffix: safe in a URL path and in an href.
        return f"https://github.com/{self.owner}/{self.name}/releases/tag/{tag}"


NODE: Final = Repo("node", "EpicCash", "epic", releases.NODE)
WALLET: Final = Repo("wallet", "EpicCash", "epic-wallet", releases.WALLET)
REPOS: Final = (NODE, WALLET)


@dataclass(frozen=True)
class Release:
    """The version a repository's readers should be measured against, and why."""

    version: str
    tag: str
    url: str
    source: Source
    checked_at: datetime | None = None
    """When GitHub last answered for this repository (200 or 304)."""
    error: str | None = None
    """Why the last attempt did not produce an answer, if it did not."""


@dataclass
class _Upstream:
    """What GitHub last said, which is not necessarily what is published here."""

    version: str
    tag: str
    etag: str | None
    fetched_at: datetime | None
    checked_at: datetime | None
    error: str | None = None


# ----------------------------------------------------------------------- watcher


class ReleaseWatcher:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.db = db
        self.enabled = settings.release_check
        self.interval_s = min(
            MAX_INTERVAL_S, max(MIN_INTERVAL_S, settings.release_check_interval_s)
        )
        self._clock = clock
        self._pinned: dict[str, Release] = {}
        if "released_node_version" in settings.model_fields_set:
            pinned = settings.released_node_version.strip()
            if pinned:
                tag = pinned if pinned.startswith("v") else f"v{pinned}"
                self._pinned[NODE.key] = Release(
                    version=pinned, tag=tag, url=NODE.tag_url(tag), source="pinned"
                )
        self._upstream: dict[str, _Upstream] = {}
        for key, row in db.load_upstream_releases().items():
            version = parse_tag(row["version"])
            if version is None:
                continue
            self._upstream[key] = _Upstream(
                version=version,
                tag=str(row["tag"]),
                etag=row["etag"],
                fetched_at=_parse_dt(row["fetched_at"]),
                checked_at=_parse_dt(row["checked_at"]),
                error=row["error"],
            )
        self._next_at: dict[str, float] = {}
        self._seed_errors: dict[str, str] = {}

    # ---------------------------------------------------------------- reading

    def release(self, repo: Repo) -> Release:
        """The published value: a pin, else the higher of the seed and GitHub."""
        pinned = self._pinned.get(repo.key)
        if pinned is not None:
            return pinned
        seed_version = parse_tag(repo.seed) or repo.seed
        seed_tag = f"v{seed_version}"
        seed = Release(
            version=seed_version, tag=seed_tag, url=repo.tag_url(seed_tag), source="seed"
        )
        up = self._upstream.get(repo.key)
        if up is None:
            error = self._seed_errors.get(repo.key)
            return seed if error is None else Release(
                version=seed.version, tag=seed.tag, url=seed.url, source="seed", error=error
            )
        if semver_key(up.version) < semver_key(seed_version):
            return Release(
                version=seed.version,
                tag=seed.tag,
                url=seed.url,
                source="seed",
                checked_at=up.checked_at,
                error=up.error,
            )
        return Release(
            version=up.version,
            tag=up.tag,
            url=repo.tag_url(up.tag),
            source="github",
            checked_at=up.checked_at,
            error=up.error,
        )

    @property
    def node(self) -> Release:
        return self.release(NODE)

    @property
    def wallet(self) -> Release:
        return self.release(WALLET)

    def fetched_repos(self) -> list[Repo]:
        if not self.enabled:
            return []
        return [r for r in REPOS if r.key not in self._pinned]

    # -------------------------------------------------------------- fetching

    async def run(self) -> None:
        """Refresh every repository when it is due, until cancelled."""
        repos = self.fetched_repos()
        if not repos:
            return
        async with _client() as client:
            while True:
                await self.refresh(client)
                now = self._clock()
                wake = min(self._next_at.get(r.key, now) for r in repos)
                await asyncio.sleep(max(30.0, wake - now))

    async def refresh(self, client: httpx.AsyncClient, *, force: bool = False) -> None:
        """One pass: fetch every repository that is due (or all, with `force`)."""
        for repo in self.fetched_repos():
            if not force and self._clock() < self._next_at.get(repo.key, 0.0):
                continue
            try:
                delay = await self._refresh_one(client, repo)
            except Exception:  # noqa: BLE001 - a bug here must not stop the loop
                log.exception("release check for %s/%s failed", repo.owner, repo.name)
                delay = RETRY_AFTER_FAILURE_S
            self._next_at[repo.key] = self._clock() + delay

    async def _refresh_one(self, client: httpx.AsyncClient, repo: Repo) -> float:
        """Fetch one repository's latest release. Returns seconds until the next try."""
        now = datetime.now(UTC)
        up = self._upstream.get(repo.key)
        headers = {
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
        }
        if up is not None and up.etag:
            headers["if-none-match"] = up.etag

        try:
            async with client.stream("GET", repo.api_url, headers=headers) as response:
                status = response.status_code
                if status == 304:
                    if up is not None:
                        up.checked_at, up.error = now, None
                        self._save(repo, up)
                    return self.interval_s
                if status in (403, 429) and _rate_limited(response):
                    wait = _backoff_s(response)
                    self._fail(repo, f"GitHub rate limit; next try in {int(wait)} s")
                    return wait
                if status != 200:
                    self._fail(repo, f"GitHub answered HTTP {status}")
                    return RETRY_AFTER_FAILURE_S
                body = await _read_capped(response)
                etag = response.headers.get("etag")
        except (httpx.HTTPError, TimeoutError, OSError) as exc:
            self._fail(repo, f"GitHub unreachable ({type(exc).__name__})")
            return RETRY_AFTER_FAILURE_S
        except _TooLarge:
            self._fail(repo, "GitHub's answer was larger than expected")
            return RETRY_AFTER_FAILURE_S

        try:
            data: Any = json.loads(body)
        except ValueError:
            self._fail(repo, "GitHub's answer was not JSON")
            return RETRY_AFTER_FAILURE_S
        if not isinstance(data, dict):
            self._fail(repo, "GitHub's answer was not a release")
            return RETRY_AFTER_FAILURE_S
        if data.get("draft") is not False or data.get("prerelease") is not False:
            self._fail(repo, "GitHub's latest release is a draft or a prerelease")
            return RETRY_AFTER_FAILURE_S
        tag = data.get("tag_name")
        version = parse_tag(tag)
        if version is None or not isinstance(tag, str):
            self._fail(repo, f"GitHub's latest tag is not a release version: {str(tag)[:40]!r}")
            return RETRY_AFTER_FAILURE_S

        previous = up.version if up is not None else None
        if previous is not None and semver_key(version) < semver_key(previous):
            # A newer release was already seen; GitHub's "latest" moved to an older
            # line. Keep the newer one, but take the new ETag, so the next unchanged
            # answer is a 304 rather than this same comparison every few hours.
            log.info(
                "%s/%s latest is now %s, older than %s already seen; keeping %s",
                repo.owner, repo.name, version, previous, previous,
            )
            assert up is not None
            up.etag, up.checked_at, up.error = etag, now, None
            self._save(repo, up)
            return self.interval_s
        fresh = _Upstream(
            version=version,
            tag=tag.strip(),
            etag=etag,
            fetched_at=now,
            checked_at=now,
        )
        self._upstream[repo.key] = fresh
        self._save(repo, fresh)
        if version != previous:
            log.info(
                "%s/%s latest release is %s (published here: %s)",
                repo.owner,
                repo.name,
                version,
                self.release(repo).version,
            )
        return self.interval_s

    def _fail(self, repo: Repo, message: str) -> None:
        """Record the failure and keep the last good value."""
        log.warning("release check for %s/%s: %s", repo.owner, repo.name, message)
        up = self._upstream.get(repo.key)
        if up is None:
            # Nothing from GitHub yet, so the seed stands. Not stored: a seed is not
            # something GitHub said.
            self._seed_errors[repo.key] = message
            return
        up.error = message
        self._save(repo, up)

    def last_error(self, repo: Repo) -> str | None:
        up = self._upstream.get(repo.key)
        if up is not None:
            return up.error
        return self._seed_errors.get(repo.key)

    def _save(self, repo: Repo, up: _Upstream) -> None:
        self.db.save_upstream_release(
            repo.key,
            version=up.version,
            tag=up.tag,
            etag=up.etag,
            fetched_at=up.fetched_at,
            checked_at=up.checked_at,
            error=up.error,
        )


# ------------------------------------------------------------------------ helpers


class _TooLarge(Exception):
    pass


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT_S),
        # api.github.com answers this route directly. A redirect would mean a renamed
        # repository, which is worth a log line rather than silently following.
        follow_redirects=False,
        trust_env=False,
        headers={"user-agent": "epic-status/0.1 (+https://github.com/BTLabs-EPIC/epic-status)"},
    )


async def _read_capped(response: httpx.Response) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise _TooLarge
    return bytes(body)


def _rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.headers.get("x-ratelimit-remaining") == "0" or (
        "retry-after" in response.headers
    )


def _backoff_s(response: httpx.Response) -> float:
    """How long GitHub asked us to wait, bounded to [1 min, 6 h]."""
    wait: float | None = None
    retry_after = response.headers.get("retry-after")
    if retry_after and retry_after.strip().isdigit():
        wait = float(retry_after)
    reset = response.headers.get("x-ratelimit-reset")
    if wait is None and reset and reset.strip().isdigit():
        wait = float(reset) - time.time()
    if wait is None:
        wait = RETRY_AFTER_FAILURE_S
    return min(MAX_INTERVAL_S, max(MIN_BACKOFF_S, wait))


def _parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
