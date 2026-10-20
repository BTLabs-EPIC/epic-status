"""Tell the operator, by Telegram DM, that a submission is waiting for review.

The feedback bot on aws-eu owns the Telegram token. This service holds only a scoped
token that is accepted on one route there (`POST /status/notify`) and can do one
thing: make the bot send the operator a one-line private message. The token lives in
an `EnvironmentFile` under /etc (mode 600), never in git.

The message carries the kind, the host and the time, and a link to the admin page.
Nothing about the submitter: the page stores only a salted hash, and there is nothing
here to add to it.

A notification is a courtesy. The submission is already stored when it is sent, so a
bot that is down, slow or refusing must never reach the submitter: `Notifier.submitted`
only schedules a background task, and that task retries briefly, logs, and gives up.
The retries are in memory; a restart inside the window loses them, and the submission
is still in the admin queue.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import UTC, datetime

import httpx

from .config import Settings

log = logging.getLogger("epic_status.notify")

RETRY_DELAYS_S: Sequence[float] = (0.0, 10.0, 60.0, 300.0)
"""First try immediately, then three more over about six minutes."""

_GIVE_UP_STATUSES = frozenset({400, 401, 403, 404})
"""Retrying cannot fix a refusal of the request or the token; only a person can."""


class Notifier:
    def __init__(
        self,
        settings: Settings,
        *,
        retry_delays: Sequence[float] = RETRY_DELAYS_S,
        client: httpx.AsyncClient | None = None,
    ):
        self.url = settings.notify_url.strip()
        self.token = settings.notify_token.strip()
        self.admin_url = settings.site_url.rstrip("/") + "/admin"
        self.retry_delays = tuple(retry_delays)
        self._tasks: set[asyncio.Task[None]] = set()
        self._client = client

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.token)

    def submitted(self, kind: str, host: str) -> None:
        """Queue a DM for a new submission and return at once. Never raises."""
        if not self.enabled:
            return
        try:
            task = asyncio.get_running_loop().create_task(
                self._deliver(kind, host, datetime.now(UTC)), name="notify-submission"
            )
        except RuntimeError:
            log.warning("no running loop; submission notice for %s dropped", host)
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _deliver(self, kind: str, host: str, when: datetime) -> None:
        body = {
            "kind": kind,
            "host": host,
            "received": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "link": self.admin_url,
        }
        for attempt, delay in enumerate(self.retry_delays, start=1):
            if delay:
                await asyncio.sleep(delay)
            outcome = await self._post(body)
            if outcome is None:
                log.info("submission notice for %s sent (attempt %d)", host, attempt)
                return
            retryable, reason = outcome
            log.warning(
                "submission notice for %s failed (attempt %d/%d): %s",
                host, attempt, len(self.retry_delays), reason,
            )
            if not retryable:
                return
        log.error("submission notice for %s dropped after %d attempts", host,
                  len(self.retry_delays))

    async def _post(self, body: dict[str, str]) -> tuple[bool, str] | None:
        """None on success, else (worth retrying, reason). The token is never logged."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(8.0))
        try:
            response = await self._client.post(
                self.url, json=body, headers={"Authorization": f"Bearer {self.token}"}
            )
        except httpx.HTTPError as exc:
            return True, f"{type(exc).__name__}"
        if response.status_code == 200:
            return None
        return response.status_code not in _GIVE_UP_STATUSES, f"HTTP {response.status_code}"

    async def aclose(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._client is not None:
            await self._client.aclose()
            self._client = None
