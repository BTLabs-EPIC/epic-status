"""The Telegram ping for new submissions.

The bot is stood in for by an `httpx.MockTransport`: nothing here touches the network.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from epic_status.config import Settings
from epic_status.db import Database
from epic_status.models import Kind
from epic_status.notify import Notifier
from epic_status.submit import accept

URL = "http://100.125.95.78:8790/status/notify"
TOKEN = "t" * 43


def make_settings(tmp_path: Path, **over: object) -> Settings:
    values: dict[str, object] = {
        "db": tmp_path / "status.db",
        "prober_id": "test",
        "site_url": "https://status.example.org/",
        "allow_private_targets": True,
        "notify_url": URL,
        "notify_token": TOKEN,
    }
    values.update(over)
    return Settings(**values)  # type: ignore[arg-type]


class Bot:
    """Answers with each status in turn, then the last one forever; records requests."""

    def __init__(self, *statuses: int | Exception) -> None:
        self.statuses = list(statuses) or [200]
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if isinstance(status, Exception):
            raise status
        return httpx.Response(status, json={"ok": status == 200})


def notifier(tmp_path: Path, bot: Bot, delays: tuple[float, ...] = (0.0,)) -> Notifier:
    client = httpx.AsyncClient(transport=httpx.MockTransport(bot))
    return Notifier(make_settings(tmp_path), retry_delays=delays, client=client)


async def settle(n: Notifier) -> None:
    await asyncio.gather(*n._tasks)


async def test_sends_kind_host_time_and_admin_link_only(tmp_path: Path) -> None:
    bot = Bot()
    n = notifier(tmp_path, bot)
    n.submitted("node", "epic-node.iniaku.my.id")
    await settle(n)
    [request] = bot.requests
    assert str(request.url) == URL
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    body = json.loads(request.content)
    assert set(body) == {"kind", "host", "received", "link"}
    assert body["kind"] == "node" and body["host"] == "epic-node.iniaku.my.id"
    assert body["link"] == "https://status.example.org/admin"
    assert body["received"].endswith("Z")
    await n.aclose()


async def test_disabled_without_url_or_token(tmp_path: Path) -> None:
    bot = Bot()
    for over in ({"notify_url": ""}, {"notify_token": ""}):
        client = httpx.AsyncClient(transport=httpx.MockTransport(bot))
        n = Notifier(make_settings(tmp_path, **over), client=client)
        assert not n.enabled
        n.submitted("node", "a.example.org")
        assert not n._tasks
        await n.aclose()
    assert bot.requests == []


async def test_retries_an_unreachable_bot_then_succeeds(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="epic_status.notify")
    bot = Bot(httpx.ConnectError("down"), 502, 200)
    n = notifier(tmp_path, bot, delays=(0.0, 0.0, 0.0))
    n.submitted("epicbox", "relay.example.org")
    await settle(n)
    assert len(bot.requests) == 3
    assert "attempt 1/3" in caplog.text and "sent (attempt 3)" in caplog.text
    assert TOKEN not in caplog.text
    await n.aclose()


async def test_gives_up_after_the_last_attempt_and_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bot = Bot(httpx.ConnectError("down"))
    n = notifier(tmp_path, bot, delays=(0.0, 0.0))
    n.submitted("pool", "pool.example.org")
    await settle(n)
    assert len(bot.requests) == 2
    assert "dropped after 2 attempts" in caplog.text
    await n.aclose()


@pytest.mark.parametrize("status", [400, 401, 403])
async def test_does_not_retry_a_refusal(tmp_path: Path, status: int) -> None:
    bot = Bot(status)
    n = notifier(tmp_path, bot, delays=(0.0, 0.0, 0.0))
    n.submitted("node", "a.example.org")
    await settle(n)
    assert len(bot.requests) == 1
    await n.aclose()


async def test_a_dead_bot_never_fails_the_submission(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    bot = Bot(httpx.ConnectError("down"))
    n = notifier(tmp_path, bot, delays=(0.0, 0.0))
    db = Database(settings.db, prober_id="test")
    try:
        message = await accept(
            db, settings, kind=Kind.NODE, raw_host="203.0.113.7", operator=None,
            submitter_address="198.51.100.1", salt="s", notifier=n,
        )
        assert "received" in message
        assert db.pending_submission_count() == 1
        await settle(n)
        assert len(bot.requests) == 2
        assert json.loads(bot.requests[0].content)["host"] == "203.0.113.7"
    finally:
        await n.aclose()
        db.close()


async def test_rejected_submission_sends_nothing(tmp_path: Path) -> None:
    from epic_status.submit import SubmissionError

    settings = make_settings(tmp_path)
    bot = Bot()
    n = notifier(tmp_path, bot)
    db = Database(settings.db, prober_id="test")
    try:
        with pytest.raises(SubmissionError):
            await accept(
                db, settings, kind=Kind.NODE, raw_host="not a host", operator=None,
                submitter_address="198.51.100.1", salt="s", notifier=n,
            )
        assert not n._tasks and bot.requests == []
    finally:
        await n.aclose()
        db.close()
