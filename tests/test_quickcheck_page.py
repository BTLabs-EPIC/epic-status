"""The board's quick check as a page: the form route, the fragment, and the widget.

The JSON route and the checker itself are covered in test_quickcheck.py; this file is
about the HTML side — that the form works without JavaScript, that the scripted path gets
only the fragment, that another site cannot post the form, and that a busy checker never
answers 503 (which the nginx vhost would replace with the "status page is down" notice).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from epic_status import quickcheck as qc
from epic_status.api import _same_origin_post

from test_quickcheck import PUBLIC, app_for, client_for, fake_dns, fake_probes  # noqa: F401

FRAGMENT = {"x-quickcheck": "fragment", "sec-fetch-site": "same-origin"}


async def test_board_renders_the_widget_closed(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        response = await client.get("/")
    html = response.text
    assert response.status_code == 200
    assert 'id="quick-check"' in html and 'action="/check#quick-check"' in html
    # Closed: no result rendered, the region hidden, the close control hidden.
    assert 'class="qc-out' not in html
    assert 'id="qc-result" aria-live="polite" hidden' in html


async def test_board_without_quickcheck_has_no_widget(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path, quickcheck_enabled=False)) as client:
        board = await client.get("/")
        post = await client.post("/check", data={"address": "node.example.org"})
    assert 'id="quick-check"' not in board.text
    assert "has-qc" not in board.text
    assert post.status_code in (404, 405)


async def test_fragment_answer(tmp_path: Path, fake_dns: Any, fake_probes: list[Any]) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/check", data={"address": "node.example.org"}, headers=FRAGMENT)
    html = response.text
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-quickcheck"] == "result"
    assert "access-control-allow-origin" not in response.headers
    # Only the result, not a page.
    assert "<html" not in html and html.lstrip().startswith('<div class="qc-out tone-ok"')
    assert "Answering on 3413" in html
    assert "API <span class=\"qc-port\">3413</span>" in html
    assert "Peer port <span class=\"qc-port\">3414</span>" in html
    # The listed host links to its row.
    assert 'data-qc-listed="node.example.org"' in html
    # Peers are said to be unavailable, never given as a number.
    assert "not public" in html


async def test_form_post_renders_the_whole_board_open(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    """The no-JavaScript path: the board again, with the box open and the input kept."""
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post(
            "/check", data={"address": " node.example.org "}, headers={"sec-fetch-site": "same-origin"}
        )
    html = response.text
    assert response.status_code == 200
    assert "<html" in html and 'class="qc is-open"' in html
    assert 'value="node.example.org"' in html
    assert 'class="qc-out tone-ok"' in html
    assert "content-security-policy" in response.headers


async def test_input_error_marks_the_field(tmp_path: Path) -> None:
    async with client_for(app_for(tmp_path)) as client:
        page = await client.post("/check", data={"address": "node.example.org:22"},
                                 headers={"sec-fetch-site": "same-origin"})
        frag = await client.post("/check", data={"address": "node.example.org:22"}, headers=FRAGMENT)
    assert page.status_code == 200
    assert 'aria-invalid="true"' in page.text
    assert 'data-error="input"' in frag.text and "Port 22" in frag.text


async def test_offers_the_default_retry(tmp_path: Path, fake_dns: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_dns({"node.example.org": [PUBLIC]})

    async def dead_api(_clients: Any, *, port: int, **_: Any) -> qc.ApiCheck:
        return qc.ApiCheck(port=port, ok=False, outcome="timeout", error="connection timed out")

    monkeypatch.setattr(qc, "probe_api", dead_api)
    async with client_for(app_for(tmp_path)) as client:
        frag = await client.post("/check", data={"address": "node.example.org:13413"}, headers=FRAGMENT)
    assert 'class="qc-retry"' in frag.text
    assert 'name="defaults" value="1"' in frag.text
    assert 'name="address" value="node.example.org:13413"' in frag.text


async def test_defaults_field_uses_the_default_ports(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        await client.post("/check", data={"address": "node.example.org:13413", "defaults": "1"},
                          headers=FRAGMENT)
    assert sorted(fake_probes) == [("api", PUBLIC, 3413), ("p2p", PUBLIC, 3414)]


@pytest.mark.parametrize(
    "headers",
    [
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
        {"origin": "https://evil.example"},
        {"origin": "null"},
    ],
)
async def test_cross_site_form_posts_are_refused(
    tmp_path: Path, headers: dict[str, str], fake_dns: Any, fake_probes: list[Any]
) -> None:
    """Another site's page must not be able to aim this server through a visitor."""
    fake_dns({"node.example.org": [PUBLIC]})
    async with client_for(app_for(tmp_path)) as client:
        response = await client.post("/check", data={"address": "node.example.org"}, headers=headers)
    assert response.status_code == 403
    assert fake_probes == []


def test_same_origin_rules() -> None:
    class Req:
        def __init__(self, headers: dict[str, str]) -> None:
            self.headers = headers

    def ok(headers: dict[str, str]) -> bool:
        return _same_origin_post(Req(headers))  # type: ignore[arg-type]

    assert ok({"sec-fetch-site": "same-origin"})
    assert ok({"sec-fetch-site": "none"})
    assert not ok({"sec-fetch-site": "cross-site"})
    # No fetch metadata: fall back to Origin against Host.
    assert ok({"origin": "https://status.example.org", "host": "status.example.org"})
    assert not ok({"origin": "https://evil.example", "host": "status.example.org"})
    # Neither header: not a browser being steered by a page.
    assert ok({"host": "status.example.org"})


async def test_rate_limited_and_busy_are_429_never_503(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    """A 503 through the vhost becomes the branded "monitor is down" page."""
    fake_dns({"node.example.org": [PUBLIC]})
    app = app_for(tmp_path)
    async with client_for(app) as client:
        statuses = [
            (await client.post("/check", data={"address": "node.example.org"}, headers=FRAGMENT)).status_code
            for _ in range(qc.CLIENT_PER_MINUTE + 1)
        ]
        limited = await client.post("/check", data={"address": "node.example.org"}, headers=FRAGMENT)
        assert statuses[-1] == 429 and limited.status_code == 429
        assert "try again" in limited.text and int(limited.headers["retry-after"]) >= 1

        # Every slot taken: busy, and still 429.
        checker = app.state.service.quickcheck
        for _ in range(qc.MAX_CONCURRENT):
            assert checker.limiter.acquire()
        busy = await client.post("/check", data={"address": "node.example.org"},
                                 headers={**FRAGMENT, "x-forwarded-for": "9.9.9.9"})
        busy_json = await client.post("/api/v1/check", json={"address": "node.example.org"},
                                      headers={"x-forwarded-for": "9.9.9.8"})
    assert busy.status_code == 429 and 'data-error="busy"' in busy.text
    assert busy_json.status_code == 429 and busy_json.json()["error_kind"] == "busy"


async def test_form_post_keeps_the_board_it_came_from(
    tmp_path: Path, fake_dns: Any, fake_probes: list[Any]
) -> None:
    """A check from the floonet board answers on the floonet board, and its close link and
    retry form stay there too. An unknown chain falls back to mainnet rather than failing."""
    from datetime import UTC, datetime

    from epic_status.models import Chain, NetworkSummary, Snapshot

    fake_dns({"node.example.org": [PUBLIC]})
    app = app_for(tmp_path)
    app.state.service.poller.snapshots[Chain.FLOONET] = Snapshot(
        generated_at=datetime.now(UTC), prober_id="test",
        network=NetworkSummary(chain=Chain.FLOONET, tip_height=200),
    )
    async with client_for(app) as client:
        floo = await client.post("/check", data={"address": "node.example.org", "chain": "floonet"},
                                 headers={"sec-fetch-site": "same-origin"})
        odd = await client.post("/check", data={"address": "node.example.org", "chain": "nope"},
                                headers={"sec-fetch-site": "same-origin"})
    assert 'data-chain="floonet"' in floo.text
    assert 'href="/?chain=floonet" aria-label="Close' in floo.text
    assert 'name="chain" value="floonet"' in floo.text
    assert odd.status_code == 200 and 'data-chain="mainnet"' in odd.text
