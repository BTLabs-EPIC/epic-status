"""The published release, read from GitHub: parsing, caching, and every fallback.

No network: api.github.com is mocked with respx. The property under test is that the
number every node is measured against follows upstream, and that nothing GitHub does —
going away, rate limiting, answering with a draft or an odd tag, or moving "latest"
to an older line — makes the board publish a wrong or missing release.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from epic_status import upstream
from epic_status.config import Settings
from epic_status.db import Database
from epic_status.poller import Poller
from epic_status.score import version_behind
from epic_status.upstream import NODE, WALLET, ReleaseWatcher, parse_tag, semver_key

NODE_API = NODE.api_url
WALLET_API = WALLET.api_url


def release_body(tag: str = "v4.1.0", **extra: Any) -> dict[str, Any]:
    return {
        "tag_name": tag,
        "name": f"Epic {tag}",
        "draft": False,
        "prerelease": False,
        "html_url": f"https://github.com/EpicCash/epic/releases/tag/{tag}",
        **extra,
    }


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def make(tmp_path: Path, clock: Clock | None = None, **overrides: Any) -> tuple[Database, ReleaseWatcher]:
    db = Database(tmp_path / "status.db", "test")
    settings = Settings(db=tmp_path / "status.db", **overrides)
    return db, ReleaseWatcher(db, settings, clock=clock or Clock())


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(follow_redirects=False)


@pytest.fixture(autouse=True)
def seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An old seed, so a GitHub answer is distinguishable from the constant."""
    monkeypatch.setattr(upstream, "NODE", upstream.Repo("node", "EpicCash", "epic", "4.0.4"))
    monkeypatch.setattr(upstream, "WALLET", upstream.Repo("wallet", "EpicCash", "epic-wallet", "4.0.0"))
    monkeypatch.setattr(upstream, "REPOS", (upstream.NODE, upstream.WALLET))


def node(w: ReleaseWatcher) -> upstream.Release:
    return w.release(upstream.NODE)


def wallet(w: ReleaseWatcher) -> upstream.Release:
    return w.release(upstream.WALLET)


# ------------------------------------------------------------------------ parsing


@pytest.mark.parametrize(
    ("tag", "version"),
    [
        ("v4.1.0", "4.1.0"),
        ("4.1.0", "4.1.0"),
        ("V4.1.0", "4.1.0"),
        (" v4.1.0\n", "4.1.0"),
        ("v4.1", "4.1.0"),
        ("v4.01.0", "4.1.0"),
        ("v4.1.0+build.7", "4.1.0"),
        ("v10.0.12", "10.0.12"),
    ],
)
def test_release_tags_parse(tag: str, version: str) -> None:
    assert parse_tag(tag) == version


@pytest.mark.parametrize(
    "tag",
    [
        "v4.1.0-rc1",  # a candidate is not the release
        "v4.1.0-beta",
        "4",
        "v4.1.0.1",
        "release-4.1.0",
        "latest",
        "",
        "v4..1",
        "v4.1.0<script>",
        None,
        410,
    ],
)
def test_non_release_tags_are_refused(tag: Any) -> None:
    assert parse_tag(tag) is None


def test_semver_precedence_is_numeric() -> None:
    assert semver_key("4.0.10") > semver_key("4.0.9")
    assert semver_key("v4.1.0") > semver_key("4.0.99")
    assert semver_key("4.1") == semver_key("4.1.0")
    with pytest.raises(ValueError):
        semver_key("4.1.0-rc1")


def test_the_board_comparison_flags_older_and_only_older() -> None:
    assert version_behind("4.0.4", "4.1.0")
    assert not version_behind("4.1.0", "4.1.0")
    assert not version_behind("4.1.1", "4.1.0")


# -------------------------------------------------------------------- fetching


@respx.mock
async def test_fetches_the_latest_release_for_node_and_wallet(tmp_path: Path) -> None:
    respx.get(NODE_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0"), headers={"etag": '"n1"'}))
    respx.get(WALLET_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0"), headers={"etag": '"w1"'}))
    _, w = make(tmp_path)
    assert node(w).version == "4.0.4" and node(w).source == "seed"
    async with client() as c:
        await w.refresh(c)
    assert node(w).version == "4.1.0" and node(w).source == "github"
    assert node(w).url == "https://github.com/EpicCash/epic/releases/tag/v4.1.0"
    assert wallet(w).version == "4.1.0"
    sent = respx.calls[0].request
    assert sent.headers["accept"] == "application/vnd.github+json"
    assert "if-none-match" not in sent.headers


@respx.mock
async def test_unchanged_release_is_a_conditional_request(tmp_path: Path) -> None:
    route = respx.get(NODE_API).mock(
        side_effect=[
            httpx.Response(200, json=release_body("v4.1.0"), headers={"etag": '"n1"'}),
            httpx.Response(304),
        ]
    )
    respx.get(WALLET_API).mock(return_value=httpx.Response(304))
    clock = Clock()
    _, w = make(tmp_path, clock)
    async with client() as c:
        await w.refresh(c)
        clock.t += w.interval_s + 1
        await w.refresh(c)
    assert route.calls[1].request.headers["if-none-match"] == '"n1"'
    assert node(w).version == "4.1.0" and node(w).error is None


@respx.mock
async def test_not_due_means_no_request(tmp_path: Path) -> None:
    route = respx.get(NODE_API).mock(return_value=httpx.Response(200, json=release_body()))
    respx.get(WALLET_API).mock(return_value=httpx.Response(200, json=release_body()))
    clock = Clock()
    _, w = make(tmp_path, clock)
    async with client() as c:
        await w.refresh(c)
        clock.t += 60
        await w.refresh(c)
    assert route.call_count == 1


def test_interval_is_clamped_to_one_to_six_hours(tmp_path: Path) -> None:
    assert make(tmp_path / "a", release_check_interval_s=5)[1].interval_s == 3600
    assert make(tmp_path / "b", release_check_interval_s=10**6)[1].interval_s == 21600


# --------------------------------------------------------------------- fallback


@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(500),
        httpx.Response(404),
        httpx.Response(301, headers={"location": "https://api.github.com/repositories/1"}),
        httpx.Response(200, content=b"<html>not json</html>"),
        httpx.Response(200, json=["not", "a", "release"]),
        httpx.Response(200, json=release_body("v9.9.9", draft=True)),
        httpx.Response(200, json=release_body("v9.9.9", prerelease=True)),
        httpx.Response(200, json=release_body("v9.9.9-rc1")),
        httpx.Response(200, json=release_body("nightly")),
        httpx.ConnectError("down"),
        httpx.ReadTimeout("slow"),
    ],
)
@respx.mock
async def test_any_failure_keeps_the_last_good_value(tmp_path: Path, failure: Any) -> None:
    clock = Clock()
    db, w = make(tmp_path, clock)
    respx.get(WALLET_API).mock(return_value=httpx.Response(304))
    route = respx.get(NODE_API)
    route.mock(return_value=httpx.Response(200, json=release_body("v4.1.0"), headers={"etag": '"n1"'}))
    async with client() as c:
        await w.refresh(c)
        if isinstance(failure, Exception):
            route.mock(side_effect=failure)
        else:
            route.mock(return_value=failure)
        clock.t += w.interval_s + 1
        await w.refresh(c)
    assert node(w).version == "4.1.0" and node(w).source == "github"
    assert node(w).error
    # And it is retried sooner than the normal interval, not hammered.
    assert w._next_at["node"] - clock.t == upstream.RETRY_AFTER_FAILURE_S
    # The value that survives is the stored one, so a restart keeps it too.
    again = ReleaseWatcher(db, Settings(db=tmp_path / "status.db"), clock=clock)
    assert node(again).version == "4.1.0"


@respx.mock
async def test_failure_before_any_answer_keeps_the_seed(tmp_path: Path) -> None:
    respx.get(NODE_API).mock(side_effect=httpx.ConnectError("no route"))
    respx.get(WALLET_API).mock(side_effect=httpx.ConnectError("no route"))
    _, w = make(tmp_path)
    async with client() as c:
        await w.refresh(c)
    assert node(w).version == "4.0.4" and node(w).source == "seed"
    assert node(w).error and "unreachable" in node(w).error


@respx.mock
async def test_rate_limit_backs_off_as_asked(tmp_path: Path) -> None:
    respx.get(NODE_API).mock(
        return_value=httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "retry-after": "1200"}, json={"message": "rate limit"}
        )
    )
    respx.get(WALLET_API).mock(return_value=httpx.Response(429, headers={"retry-after": "5"}))
    clock = Clock()
    _, w = make(tmp_path, clock)
    async with client() as c:
        await w.refresh(c)
    assert w._next_at["node"] - clock.t == 1200
    assert w._next_at["wallet"] - clock.t == upstream.MIN_BACKOFF_S
    assert node(w).version == "4.0.4"


@respx.mock
async def test_oversized_answer_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upstream, "MAX_BODY_BYTES", 1000)
    respx.get(NODE_API).mock(return_value=httpx.Response(200, json=release_body(body="x" * 5000)))
    respx.get(WALLET_API).mock(return_value=httpx.Response(304))
    _, w = make(tmp_path)
    async with client() as c:
        await w.refresh(c)
    assert node(w).source == "seed" and "larger" in (node(w).error or "")


@respx.mock
async def test_never_goes_backwards_from_a_newer_known_release(tmp_path: Path) -> None:
    """GitHub's "latest" is the most recently created release; a maintenance release
    for an older line would otherwise move it down."""
    respx.get(WALLET_API).mock(return_value=httpx.Response(304))
    route = respx.get(NODE_API)
    route.mock(return_value=httpx.Response(200, json=release_body("v4.1.0")))
    clock = Clock()
    _, w = make(tmp_path, clock)
    async with client() as c:
        await w.refresh(c)
        route.mock(return_value=httpx.Response(200, json=release_body("v4.0.5")))
        clock.t += w.interval_s + 1
        await w.refresh(c)
    assert node(w).version == "4.1.0" and node(w).source == "github"
    # The newer answer survives a restart too.
    again = ReleaseWatcher(w.db, Settings(db=tmp_path / "status.db"), clock=clock)
    assert node(again).version == "4.1.0"


@respx.mock
async def test_seed_is_a_floor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A seed bumped ahead of GitHub — a release whose GitHub page is not up yet — is
    not undone by GitHub's older answer."""
    monkeypatch.setattr(upstream, "NODE", upstream.Repo("node", "EpicCash", "epic", "4.2.0"))
    monkeypatch.setattr(upstream, "REPOS", (upstream.NODE, upstream.WALLET))
    respx.get(NODE_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0")))
    respx.get(WALLET_API).mock(return_value=httpx.Response(304))
    _, w = make(tmp_path)
    async with client() as c:
        await w.refresh(c)
    assert node(w).version == "4.2.0" and node(w).source == "seed"


# ------------------------------------------------------------------ pins, switch


@respx.mock
async def test_an_operator_pin_is_used_and_never_fetched(tmp_path: Path) -> None:
    node_route = respx.get(NODE_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0")))
    respx.get(WALLET_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0")))
    _, w = make(tmp_path, released_node_version="4.0.9")
    async with client() as c:
        await w.refresh(c)
    assert node_route.call_count == 0
    assert node(w).version == "4.0.9" and node(w).source == "pinned"
    assert wallet(w).version == "4.1.0"


@respx.mock
async def test_switched_off_contacts_nothing(tmp_path: Path) -> None:
    route = respx.get(url__startswith="https://api.github.com/").mock(return_value=httpx.Response(200))
    _, w = make(tmp_path, release_check=False)
    await w.run()  # returns at once: nothing to fetch
    async with client() as c:
        await w.refresh(c)
    assert route.call_count == 0
    assert node(w).source == "seed"


# --------------------------------------------------------------- on the board


@respx.mock
async def test_the_snapshot_carries_the_fetched_release(tmp_path: Path) -> None:
    respx.get(NODE_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0")))
    respx.get(WALLET_API).mock(return_value=httpx.Response(200, json=release_body("v4.1.0")))
    db, w = make(tmp_path)
    async with client() as c:
        await w.refresh(c)
    poller = Poller(db, Settings(db=tmp_path / "status.db"), w)
    assert poller.releases.node.version == "4.1.0"


def test_a_poller_without_a_watcher_uses_the_seed_and_fetches_nothing(tmp_path: Path) -> None:
    db = Database(tmp_path / "status.db", "test")
    poller = Poller(db, Settings(db=tmp_path / "status.db"))
    assert poller.releases.fetched_repos() == []
    assert poller.releases.node.version == "4.0.4"  # the (patched) seed
