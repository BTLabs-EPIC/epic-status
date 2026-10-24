"""Server icons: the upload pipeline, the review gate and what the API publishes.

The upload is a public write that ends up drawn in other people's wallets, so most of
these pin a refusal: each corresponds to a file someone could send. The rest pin the
promise that matters to a wallet — only approved icons are published, and what is
published is our own re-encoding, never the bytes that arrived.
"""

from __future__ import annotations

import io
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from PIL import Image

from epic_status.admin import hash_password
from epic_status.api import create_app
from epic_status.config import REPO_ROOT
from epic_status.models import Kind
from epic_status.server_icons import (
    IconRejected,
    IconSettings,
    UploadLimiter,
    load_icon_settings,
    normalise,
)

from test_app import client_for, install_snapshot, make_settings

# ------------------------------------------------------------------- fixtures


def image_bytes(
    fmt: str = "PNG",
    size: tuple[int, int] = (300, 300),
    colour: tuple[int, ...] = (200, 40, 40, 255),
    mode: str = "RGBA",
    **save: Any,
) -> bytes:
    img = Image.new(mode, size, colour if mode != "RGB" else colour[:3])
    out = io.BytesIO()
    img.save(out, format=fmt, **save)
    return out.getvalue()


def cfg(tmp_path: Path, **overrides: Any) -> IconSettings:
    values: dict[str, Any] = {"storage_dir": tmp_path / "icons"}
    values.update(overrides)
    return IconSettings(**values)


def icons_toml(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "icons.toml"
    path.write_text(
        f'[storage]\ndir = "{tmp_path / "icons"}"\n'
        "[limits]\nper_address_per_hour = 2\nglobal_per_hour = 20\nmax_pending = 50\n"
        + extra
    )
    return path


def decoded(data: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(data))
    img.load()
    return img


# ---------------------------------------------------------------- normalising


def test_a_good_png_becomes_square_pngs_at_every_size(tmp_path: Path) -> None:
    item = normalise(image_bytes(), cfg(tmp_path))
    assert sorted(item.renditions) == [128, 256]
    for size, data in item.renditions.items():
        img = decoded(data)
        assert img.format == "PNG"
        assert img.size == (size, size)
        assert img.mode == "RGBA"
    assert re.fullmatch(r"[0-9a-f]{20}", item.hash)
    assert (item.source_format, item.source_width, item.source_height) == ("png", 300, 300)


def test_the_same_image_gets_the_same_hash(tmp_path: Path) -> None:
    assert normalise(image_bytes(), cfg(tmp_path)).hash == normalise(image_bytes(), cfg(tmp_path)).hash


def test_a_wide_image_is_padded_not_cropped(tmp_path: Path) -> None:
    item = normalise(image_bytes(size=(400, 200)), cfg(tmp_path))
    img = decoded(item.renditions[256])
    assert img.size == (256, 256)
    # Transparent above and below the content, opaque in the middle.
    assert img.getpixel((128, 5))[3] == 0  # type: ignore[index]
    assert img.getpixel((128, 128))[3] == 255  # type: ignore[index]


@pytest.mark.parametrize("fmt", ["JPEG", "WEBP"])
def test_jpeg_and_webp_are_accepted(tmp_path: Path, fmt: str) -> None:
    item = normalise(image_bytes(fmt, mode="RGB"), cfg(tmp_path))
    assert decoded(item.renditions[128]).format == "PNG"


def test_exif_is_stripped_and_orientation_applied(tmp_path: Path) -> None:
    exif = Image.Exif()
    exif[0x0112] = 6  # Orientation: rotate 90° clockwise to display
    exif[0x010F] = "SecretCam"  # Make
    exif[0x8825] = {2: (51.0, 30.0, 0.0)}  # GPS latitude
    raw = image_bytes("JPEG", size=(200, 100), mode="RGB", exif=exif.tobytes())
    assert b"SecretCam" in raw
    item = normalise(raw, cfg(tmp_path))
    for data in item.renditions.values():
        assert b"SecretCam" not in data and b"Exif" not in data
        img = decoded(data)
        assert not img.getexif()
        assert "exif" not in img.info
    # 200×100 rotated is 100×200: padding left and right, not above and below.
    img = decoded(item.renditions[256])
    assert img.getpixel((5, 128))[3] == 0  # type: ignore[index]
    assert img.getpixel((128, 5))[3] == 255  # type: ignore[index]


def test_text_chunks_and_icc_profiles_are_dropped(tmp_path: Path) -> None:
    from PIL import ImageCms, PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "<script>alert(1)</script>")
    icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    raw = image_bytes(pnginfo=info, icc_profile=icc)
    assert b"<script>" in raw
    for data in normalise(raw, cfg(tmp_path)).renditions.values():
        assert b"<script>" not in data
        assert b"iCCP" not in data and b"tEXt" not in data
        assert "icc_profile" not in decoded(data).info


def test_a_polyglot_is_reduced_to_its_pixels(tmp_path: Path) -> None:
    """A valid PNG with an HTML page appended. Browsers that sniff would run it; our output
    is a fresh encoding and carries nothing of the original past its pixels."""
    payload = b"<html><body><script>alert(document.cookie)</script></body></html>"
    raw = image_bytes() + payload
    item = normalise(raw, cfg(tmp_path))
    for data in item.renditions.values():
        assert b"<script" not in data and b"<html" not in data
        assert data.endswith(b"IEND\xaeB`\x82")


def test_a_document_wrapping_an_image_is_refused(tmp_path: Path) -> None:
    raw = b"<html><!--" + image_bytes() + b"--><script>alert(1)</script></html>"
    with pytest.raises(IconRejected, match="not a PNG, JPEG or WebP"):
        normalise(raw, cfg(tmp_path))


def test_png_magic_with_another_format_inside_is_refused(tmp_path: Path) -> None:
    raw = b"\x89PNG\r\n\x1a\n" + image_bytes("JPEG", mode="RGB")
    with pytest.raises(IconRejected, match="could not be read"):
        normalise(raw, cfg(tmp_path))


def test_the_extension_and_declared_type_do_not_matter(tmp_path: Path) -> None:
    """Detected by content: a GIF is refused even though it decodes fine."""
    with pytest.raises(IconRejected, match="not a PNG, JPEG or WebP"):
        normalise(image_bytes("GIF", mode="RGB"), cfg(tmp_path))
    with pytest.raises(IconRejected):
        normalise(b"just text, named icon.png", cfg(tmp_path))


def test_an_svg_with_a_script_is_refused(tmp_path: Path) -> None:
    svg = (
        b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
        b"<script>alert(1)</script><rect width='64' height='64'/></svg>"
    )
    with pytest.raises(IconRejected, match="SVG is not accepted"):
        normalise(svg, cfg(tmp_path))
    with pytest.raises(IconRejected, match="SVG is not accepted"):
        normalise(b"\n  <svg onload='alert(1)'></svg>", cfg(tmp_path))


def test_oversized_upload_is_refused(tmp_path: Path) -> None:
    with pytest.raises(IconRejected, match="over 1 KB"):
        normalise(image_bytes(size=(64, 64)) + b"\0" * 2048, cfg(tmp_path, max_bytes=1024))


def test_a_decompression_bomb_is_refused_before_decoding(tmp_path: Path) -> None:
    """A few KB on disk, 64 MB once decoded. Refused from the header."""
    raw = image_bytes(size=(4096, 4096), mode="L", colour=(0,))
    assert len(raw) < 100_000
    with pytest.raises(IconRejected, match="4096×4096"):
        normalise(raw, cfg(tmp_path))


def test_the_pixel_limit_applies_as_well_as_the_side_limit(tmp_path: Path) -> None:
    raw = image_bytes(size=(1000, 1000), mode="L", colour=(0,))
    with pytest.raises(IconRejected):
        normalise(raw, cfg(tmp_path, max_pixels=500_000))


def test_a_tiny_image_is_refused(tmp_path: Path) -> None:
    with pytest.raises(IconRejected, match="at least 32×32"):
        normalise(image_bytes(size=(16, 16)), cfg(tmp_path))


def test_an_animated_png_is_refused(tmp_path: Path) -> None:
    frames = [Image.new("RGBA", (64, 64), c) for c in ((255, 0, 0, 255), (0, 255, 0, 255))]
    out = io.BytesIO()
    frames[0].save(out, format="PNG", save_all=True, append_images=frames[1:])
    with pytest.raises(IconRejected, match="Animated"):
        normalise(out.getvalue(), cfg(tmp_path))


def test_an_animated_webp_is_refused(tmp_path: Path) -> None:
    frames = [Image.new("RGB", (64, 64), c) for c in ((255, 0, 0), (0, 255, 0))]
    out = io.BytesIO()
    frames[0].save(out, format="WEBP", save_all=True, append_images=frames[1:])
    with pytest.raises(IconRejected, match="Animated"):
        normalise(out.getvalue(), cfg(tmp_path))


def test_a_truncated_file_is_refused(tmp_path: Path) -> None:
    raw = Image.effect_noise((256, 256), 64).convert("RGB")
    out = io.BytesIO()
    raw.save(out, format="PNG")
    with pytest.raises(IconRejected, match="could not be read"):
        normalise(out.getvalue()[: len(out.getvalue()) // 2], cfg(tmp_path))


def test_a_type_can_be_switched_off(tmp_path: Path) -> None:
    with pytest.raises(IconRejected, match="JPEG images are not accepted"):
        normalise(image_bytes("JPEG", mode="RGB"), cfg(tmp_path, allowed_types=("png",)))


# ------------------------------------------------------------------- settings


def test_the_shipped_config_file_loads() -> None:
    loaded = load_icon_settings(REPO_ROOT / "config" / "icons.toml")
    assert loaded.allowed_types == ("png", "jpeg", "webp")
    assert loaded.max_bytes == 1_048_576
    assert loaded.sizes == (128, 256)
    assert loaded.storage_dir == REPO_ROOT / "data" / "icons"


def test_svg_cannot_be_enabled(tmp_path: Path) -> None:
    path = tmp_path / "icons.toml"
    path.write_text('[upload]\nallowed_types = ["png", "svg"]\n')
    with pytest.raises(ValueError, match="SVG cannot be enabled"):
        load_icon_settings(path)


@pytest.mark.parametrize(
    "body",
    ["[output]\nsizes = [4]\n", "[upload]\nmax_bytes = 999999999\n", '[upload]\nallowed_types = ["gif"]\n'],
)
def test_an_out_of_range_setting_stops_the_boot(tmp_path: Path, body: str) -> None:
    path = tmp_path / "icons.toml"
    path.write_text(body)
    with pytest.raises(ValueError):
        load_icon_settings(path)


# ----------------------------------------------------------------- rate limit


def test_limiter_is_per_address_and_global() -> None:
    limiter = UploadLimiter(per_address=2, total=3)
    assert limiter.allow("a") is None
    assert limiter.allow("a") is None
    assert limiter.allow("a") is not None
    assert limiter.allow("b") is None
    assert "Too many image uploads in the last hour" in (limiter.allow("c") or "")


def test_limiter_window_slides(monkeypatch: pytest.MonkeyPatch) -> None:
    import epic_status.server_icons as mod

    now = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: now[0])
    limiter = UploadLimiter(per_address=1, total=10)
    assert limiter.allow("a") is None
    assert limiter.allow("a") is not None
    now[0] += 3601
    assert limiter.allow("a") is None


# -------------------------------------------------------------------- the app


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
    application = create_app(
        make_settings(
            tmp_path,
            admin_password_hash=hash_password("pw"),
            icons_file=icons_toml(tmp_path),
            allow_private_targets=True,
        )
    )
    install_snapshot(application.state.service)
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with client_for(app) as c:
        yield c


async def login(client: httpx.AsyncClient) -> str:
    response = await client.post("/admin/login", data={"user": "admin", "password": "pw"})
    assert response.status_code == 303
    page = (await client.get("/admin")).text
    found = re.search(r'data-csrf="([^"]+)"', page)
    assert found
    return found.group(1)


async def submit(
    client: httpx.AsyncClient, host: str, data: bytes | None, address: str = "198.51.100.1"
) -> httpx.Response:
    files = {"icon": ("logo.png", data, "image/png")} if data is not None else None
    return await client.post(
        "/api/v1/submit",
        data={"kind": "node", "host": host},
        files=files,
        headers={"x-real-ip": address},
    )


def node_row(payload: dict[str, Any], slug: str = "node.example.org") -> dict[str, Any]:
    return next(n for n in payload["nodes"] if n["id"] == slug)


async def test_status_json_has_a_null_icon_by_default(client: httpx.AsyncClient) -> None:
    body = (await client.get("/api/v1/status.json")).json()
    assert node_row(body)["icon"] is None


async def test_submission_without_an_icon_still_works(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/submit", data={"kind": "node", "host": "203.0.113.20"})
    assert response.status_code == 202, response.text


async def test_submitted_icon_is_pending_until_approved(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    service = app.state.service
    response = await submit(client, "203.0.113.21", image_bytes())
    assert response.status_code == 202, response.text
    assert "icon is reviewed separately" in response.json()["message"]
    [pending] = service.icons.pending()
    assert pending["slug"] == "203.0.113.21" and pending["origin"] == "submitted"
    name = f"{pending['hash']}-256.png"

    # Not public: neither in the API nor at its URL.
    assert (await client.get(f"/api/v1/icons/{name}")).status_code == 404

    # The admin can preview it; a stranger cannot.
    async with client_for(app) as stranger:
        assert (await stranger.get(f"/admin/icons/{name}")).status_code == 404
    csrf = await login(client)
    preview = await client.get(f"/admin/icons/{name}")
    assert preview.status_code == 200
    assert preview.headers["cache-control"] == "private, no-store"
    page = (await client.get("/admin")).text
    assert "Icons waiting" in page and f"/admin/icons/{pending['hash']}-128.png" in page

    approve = await client.post(
        "/admin/icon/review",
        data={"csrf": csrf, "icon_id": str(pending["id"]), "decision": "approve"},
    )
    assert approve.status_code == 200 and "approved and published" in approve.text
    served = await client.get(f"/api/v1/icons/{name}")
    assert served.status_code == 200
    assert served.headers["content-type"] == "image/png"
    assert served.headers["x-content-type-options"] == "nosniff"
    assert "immutable" in served.headers["cache-control"]
    assert served.content == (service.icons.dir / name).read_bytes()
    again = await client.get(f"/api/v1/icons/{name}", headers={"if-none-match": served.headers["etag"]})
    assert again.status_code == 304


async def test_icon_review_needs_a_valid_csrf_token(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    await submit(client, "203.0.113.22", image_bytes())
    [pending] = app.state.service.icons.pending()
    await login(client)
    response = await client.post(
        "/admin/icon/review", data={"csrf": "forged", "icon_id": str(pending["id"]), "decision": "approve"}
    )
    assert "stale form" in response.text
    assert app.state.service.icons.pending()


async def test_a_bad_icon_refuses_the_whole_request(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    response = await submit(client, "203.0.113.23", b"<svg><script>alert(1)</script></svg>")
    assert response.status_code == 400
    assert "SVG" in response.json()["error"]
    assert app.state.service.db.pending_submission_count() == 0
    assert not app.state.service.icons.pending()


async def test_image_uploads_are_rate_limited_per_address(client: httpx.AsyncClient) -> None:
    # icons_toml sets per_address_per_hour = 2.
    for i in range(2):
        assert (await submit(client, f"203.0.113.{30 + i}", image_bytes())).status_code == 202
    refused = await submit(client, "203.0.113.40", image_bytes())
    assert refused.status_code == 400
    assert "Too many image uploads from your address" in refused.json()["error"]
    # Another address is still allowed, and so is a request without an image.
    assert (await submit(client, "203.0.113.41", image_bytes(), address="198.51.100.9")).status_code == 202
    assert (await submit(client, "203.0.113.42", None)).status_code == 202


async def test_an_oversized_body_is_refused_before_parsing(client: httpx.AsyncClient) -> None:
    big = b"\x89PNG\r\n\x1a\n" + b"\0" * (1_048_576 + 70_000)
    response = await submit(client, "203.0.113.43", big)
    assert response.status_code == 413


async def test_the_html_form_takes_an_icon(app: FastAPI, client: httpx.AsyncClient) -> None:
    page = (await client.get("/add")).text
    assert 'enctype="multipart/form-data"' in page and 'name="icon"' in page
    response = await client.post(
        "/add",
        data={"kind": "node", "host": "203.0.113.44"},
        files={"icon": ("x.webp", image_bytes("WEBP", mode="RGB"), "image/webp")},
    )
    assert response.status_code == 200
    assert len(app.state.service.icons.pending()) == 1
    # An empty file input sends an empty part; that is "no icon", not an error.
    empty = await client.post(
        "/add",
        data={"kind": "node", "host": "203.0.113.45"},
        files={"icon": ("", b"", "application/octet-stream")},
    )
    assert empty.status_code == 200, empty.text
    assert len(app.state.service.icons.pending()) == 1


async def test_rejecting_a_request_rejects_its_icon(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    service = app.state.service
    await submit(client, "203.0.113.46", image_bytes())
    [pending] = service.icons.pending()
    csrf = await login(client)
    response = await client.post(
        "/admin/review/json",
        data={"csrf": csrf, "submission_id": str(pending["submission_id"]), "decision": "reject"},
    )
    assert response.json()["ok"]
    assert service.icons.icon(pending["id"])["status"] == "rejected"


async def test_admin_upload_replace_and_remove(app: FastAPI, client: httpx.AsyncClient) -> None:
    service = app.state.service
    target = service.db.target_by_slug(Kind.NODE, "node.example.org")
    assert target is not None
    csrf = await login(client)

    # No session, no upload.
    async with client_for(app) as stranger:
        refused = await stranger.post(
            "/admin/api/icon",
            data={"csrf": csrf, "target_id": str(target.id)},
            files={"icon": ("a.png", image_bytes(), "image/png")},
        )
        assert refused.status_code == 401

    first = await client.post(
        "/admin/api/icon",
        data={"csrf": csrf, "target_id": str(target.id)},
        files={"icon": ("a.png", image_bytes(), "image/png")},
    )
    assert first.status_code == 200, first.text
    icon = first.json()["icon"]
    assert icon["url"] == f"https://status.example.org/api/v1/icons/{icon['hash']}-256.png"
    assert set(icon["urls"]) == {"128", "256"}

    body = (await client.get("/api/v1/status.json")).json()
    assert node_row(body)["icon"]["hash"] == icon["hash"]
    assert (await client.get(icon["urls"]["128"].removeprefix("https://status.example.org"))).status_code == 200

    # Replace: a new hash, and the old URL stops being served.
    second = await client.post(
        "/admin/icon",
        data={"csrf": csrf, "target_id": str(target.id)},
        files={"icon": ("b.png", image_bytes(colour=(0, 0, 200, 255)), "image/png")},
    )
    assert "saved and published" in second.text
    body = (await client.get("/api/v1/status.json")).json()
    new_hash = node_row(body)["icon"]["hash"]
    assert new_hash != icon["hash"]
    assert (await client.get(f"/api/v1/icons/{icon['hash']}-256.png")).status_code == 404

    # A bad admin upload is refused the same way a public one is.
    bad = await client.post(
        "/admin/api/icon",
        data={"csrf": csrf, "target_id": str(target.id)},
        files={"icon": ("c.gif", image_bytes("GIF", mode="RGB"), "image/gif")},
    )
    assert bad.status_code == 400

    removed = await client.post("/admin/icon/remove", data={"csrf": csrf, "target_id": str(target.id)})
    assert "wallets show initials" in removed.text
    body = (await client.get("/api/v1/status.json")).json()
    assert node_row(body)["icon"] is None
    assert (await client.get(f"/api/v1/icons/{new_hash}-256.png")).status_code == 404


async def test_onion_requests_get_onion_icon_urls(tmp_path: Path) -> None:
    app = create_app(
        make_settings(
            tmp_path,
            icons_file=icons_toml(tmp_path),
            onion_url="http://exampleonionaddress.onion",
        )
    )
    install_snapshot(app.state.service)
    from epic_status.server_icons import IconOrigin, IconStatus

    service = app.state.service
    item = normalise(image_bytes(), service.icon_settings)
    service.icons.add(
        item, kind="node", slug="node.example.org", origin=IconOrigin.ADMIN, status=IconStatus.ACTIVE
    )
    async with client_for(app) as client:
        clear = node_row((await client.get("/api/v1/status.json")).json())["icon"]
        onion = node_row(
            (await client.get("/api/v1/status.json", headers={"x-epic-onion": "1"})).json()
        )["icon"]
    assert clear["url"].startswith("https://status.example.org/api/v1/icons/")
    assert onion["url"] == f"http://exampleonionaddress.onion/api/v1/icons/{item.hash}-256.png"


async def test_icon_route_refuses_anything_but_a_known_name(client: httpx.AsyncClient) -> None:
    for name in ("../status.db", "..%2Fstatus.db", "abc.png", "0" * 20 + "-999.png", "0" * 20 + "-256.png"):
        assert (await client.get(f"/api/v1/icons/{name}")).status_code == 404, name


def test_prune_deletes_old_rejected_files_only(tmp_path: Path) -> None:
    from epic_status.db import Database
    from epic_status.server_icons import IconOrigin, IconStatus, IconStore

    db = Database(tmp_path / "s.db", prober_id="test")
    try:
        store = IconStore(db, cfg(tmp_path))
        keep = normalise(image_bytes(), store.cfg)
        drop = normalise(image_bytes(colour=(0, 200, 0, 255)), store.cfg)
        store.add(keep, kind="node", slug="a", origin=IconOrigin.ADMIN, status=IconStatus.ACTIVE)
        icon_id = store.add(drop, kind="node", slug="b", origin=IconOrigin.SUBMITTED, status=IconStatus.PENDING)
        store.reject(icon_id)
        assert store.prune() == 0  # inside retention
        assert store.prune(datetime.now(UTC) + timedelta(days=15)) == 2
        assert sorted(p.name for p in store.dir.iterdir()) == sorted(
            f"{keep.hash}-{s}.png" for s in (128, 256)
        )
        assert store.icon(icon_id) is None
    finally:
        db.close()


# ------------------------------------------------------------------ the board


@pytest.mark.parametrize(
    ("operator", "host", "expected"),
    [
        ("BT Labs", "node.btlabs.uk", "BL"),
        ("StackWallet", "epic.stackwallet.com:3413", "SW"),
        ("epicnet", "node.epicnet.us", "EP"),
        ("Epic-Cash dev", "x", "EC"),
        (None, "node.epiccash.com", "EP"),
        ("", "epicbox.fastepic.eu", "FA"),
        ("  ", "www.node.x.org:443", "X"),
        (None, "203.0.113.7", "20"),
    ],
)
def test_initials_follow_the_wallet_rule(operator: str | None, host: str, expected: str) -> None:
    from epic_status.render import server_initials

    assert server_initials(operator, host) == expected


def test_tint_is_the_wallet_hash() -> None:
    from epic_status.render import server_tint

    # Dart: 'bt labs'.codeUnits.fold(17, (a, c) => (a * 31 + c) & 0x7fffffff) % 3
    seed = 17
    for ch in "bt labs":
        seed = (seed * 31 + ord(ch)) & 0x7FFFFFFF
    assert server_tint("BT Labs", "ignored") == seed % 3
    assert server_tint(None, "Node.Example.org") == server_tint(None, "node.example.org")


async def test_board_rows_show_icon_or_initials(app: FastAPI, client: httpx.AsyncClient) -> None:
    page = (await client.get("/")).text
    # install_snapshot's node has operator "Example" and no icon yet.
    assert 'class="srv-tile srv-tile-32 srv-tint-' in page
    assert '>EX</span>' in page
    from epic_status.server_icons import IconOrigin, IconStatus

    service = app.state.service
    item = normalise(image_bytes(), service.icon_settings)
    service.icons.add(
        item, kind="node", slug="node.example.org", origin=IconOrigin.ADMIN, status=IconStatus.ACTIVE
    )
    page = (await client.get("/")).text
    assert f'src="/api/v1/icons/{item.hash}-128.png"' in page  # the row
    assert f'src="/api/v1/icons/{item.hash}-256.png"' in page  # the detail panel
    assert '>EX</span>' not in page


async def test_notice_says_when_a_request_carries_an_icon(tmp_path: Path) -> None:
    from epic_status.notify import Notifier

    sent: list[dict[str, Any]] = []

    class Capture(Notifier):
        async def _post(self, body: dict[str, str | bool]) -> tuple[bool, str] | None:
            sent.append(body)
            return None

    settings = make_settings(
        tmp_path,
        icons_file=icons_toml(tmp_path),
        allow_private_targets=True,
        notify_url="https://bot.example.org/status/notify",
        notify_token="t" * 32,
    )
    app = create_app(settings)
    service = app.state.service
    service.notifier = Capture(settings)
    async with client_for(app) as client:
        await submit(client, "203.0.113.60", image_bytes())
        await submit(client, "203.0.113.61", None)
        import asyncio

        for _ in range(50):
            if len(sent) == 2:
                break
            await asyncio.sleep(0.01)
    assert sent[0]["icon"] is True
    assert "icon" not in sent[1]


# ------------------------------------------------------------- fetch from a URL

import asyncio  # noqa: E402
import socket  # noqa: E402

from epic_status.server_icons import fetch_image  # noqa: E402

PUBLIC = "93.184.216.34"


def resolver(table: dict[str, str]) -> Any:
    async def gai(host: str, port: int) -> list[Any]:
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        addr = table[host]
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (addr, port))]

    return gai


def transport(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


async def fetch(url: str, handler: Any, table: dict[str, str] | None = None, **kw: Any) -> bytes:
    cfg_kw = kw.pop("cfg", {})
    return await fetch_image(
        url,
        IconSettings(**cfg_kw),
        own_addresses=kw.pop("own", lambda: frozenset({"198.51.100.250"})),
        getaddrinfo=resolver(table if table is not None else {"img.example.org": PUBLIC}),
        transport=transport(handler),
        **kw,
    )


def png_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=image_bytes(), headers={"content-type": "image/png"})


async def test_fetch_downloads_from_the_vetted_address_without_cookies_or_auth() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return png_handler(request)

    data = await fetch("https://img.example.org/logo.png?v=2", handler)
    assert data == image_bytes()
    [req] = seen
    assert req.url.host == PUBLIC  # pinned to the checked address
    assert req.url.raw_path == b"/logo.png?v=2"
    assert req.headers["host"] == "img.example.org"
    assert req.extensions["sni_hostname"] == "img.example.org"
    assert "cookie" not in req.headers and "authorization" not in req.headers


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("http://img.example.org/logo.png", "Only https"),
        ("ftp://img.example.org/logo.png", "Only https"),
        ("https://user:pw@img.example.org/logo.png", "user name or password"),
        ("https:///logo.png", "no host"),
        ("https://img.example.org/" + "a" * 3000, "too long"),
    ],
)
async def test_fetch_refuses_bad_urls(url: str, message: str) -> None:
    with pytest.raises(IconRejected, match=message):
        await fetch(url, png_handler)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.1", "169.254.169.254", "100.64.0.1",
     "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"],
)
async def test_fetch_refuses_private_loopback_and_link_local(address: str) -> None:
    called: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request)
        return png_handler(request)

    with pytest.raises(IconRejected, match="non-public address"):
        await fetch("https://img.example.org/a.png", handler, {"img.example.org": address})
    assert called == []  # refused before any connection


async def test_fetch_refuses_this_servers_own_address() -> None:
    with pytest.raises(IconRejected, match="points at this server"):
        await fetch("https://img.example.org/a.png", png_handler, own=lambda: frozenset({PUBLIC}))


async def test_fetch_refuses_when_own_addresses_are_unknown() -> None:
    with pytest.raises(IconRejected, match="own addresses could not be read"):
        await fetch("https://img.example.org/a.png", png_handler, own=lambda: None)


async def test_fetch_rechecks_every_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "img.example.org":
            return httpx.Response(302, headers={"location": "https://internal.example.org/x.png"})
        raise AssertionError("must not connect to the redirect target")

    table = {"img.example.org": PUBLIC, "internal.example.org": "10.1.2.3"}
    with pytest.raises(IconRejected, match="non-public address 10.1.2.3"):
        await fetch("https://img.example.org/a.png", handler, table)


async def test_fetch_refuses_a_redirect_to_plain_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "http://img.example.org/a.png"})

    with pytest.raises(IconRejected, match="Only https"):
        await fetch("https://img.example.org/a.png", handler)


async def test_fetch_follows_at_most_three_redirects() -> None:
    hops: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(request.url.path)
        n = len(hops)
        if n <= 3:
            return httpx.Response(302, headers={"location": f"/hop{n}.png"})
        return png_handler(request)

    assert await fetch("https://img.example.org/start.png", handler) == image_bytes()
    assert hops == ["/start.png", "/hop1.png", "/hop2.png", "/hop3.png"]

    hops.clear()

    def endless(request: httpx.Request) -> httpx.Response:
        hops.append(request.url.path)
        return httpx.Response(302, headers={"location": f"/again{len(hops)}.png"})

    with pytest.raises(IconRejected, match="more than 3 redirects"):
        await fetch("https://img.example.org/start.png", endless)
    assert len(hops) == 4


async def test_fetch_caps_the_body_while_streaming() -> None:
    async def chunks() -> Any:
        for _ in range(64):
            yield b"\0" * 32_768  # 2 MB, no Content-Length

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=chunks())

    with pytest.raises(IconRejected, match="over 1024 KB"):
        await fetch("https://img.example.org/a.png", handler)

    def declared(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x", headers={"content-length": "5000000"})

    with pytest.raises(IconRejected, match="over 1024 KB"):
        await fetch("https://img.example.org/a.png", declared)


async def test_fetch_times_out() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return png_handler(request)

    with pytest.raises(IconRejected, match="within 0.2 seconds"):
        await fetch("https://img.example.org/a.png", slow, cfg={"fetch_timeout_s": 0.2})


async def test_fetch_reports_http_errors_and_dns_failures() -> None:
    with pytest.raises(IconRejected, match="HTTP 404"):
        await fetch("https://img.example.org/a.png", lambda r: httpx.Response(404))
    with pytest.raises(IconRejected, match="does not resolve"):
        await fetch("https://nowhere.example.org/a.png", png_handler)


async def test_fetched_html_is_refused_like_an_upload(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html><script>alert(1)</script></html>",
                              headers={"content-type": "image/png"})

    data = await fetch("https://img.example.org/a.png", handler)
    with pytest.raises(IconRejected, match="not a PNG, JPEG or WebP"):
        normalise(data, cfg(tmp_path))


async def test_admin_fetch_previews_before_publishing(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import epic_status.server_icons as mod

    calls: list[str] = []

    async def fake_fetch(url: str, cfg: IconSettings, **kw: Any) -> bytes:
        calls.append(url)
        return image_bytes(colour=(250, 200, 0, 255))

    monkeypatch.setattr(mod, "fetch_image", fake_fetch)
    service = app.state.service
    target = service.db.target_by_slug(Kind.NODE, "node.example.org")
    assert target is not None
    csrf = await login(client)
    page = await client.post(
        "/admin/icon/fetch",
        data={"csrf": csrf, "target_id": str(target.id), "url": "https://img.example.org/a.png"},
    )
    assert "Check the preview" in page.text
    assert calls == ["https://img.example.org/a.png"]
    staged = service.icons.staged()[("node", "node.example.org")]
    assert f"/admin/icons/{staged['hash']}-128.png" in page.text and "Use this icon" in page.text
    # A preview is neither public nor in the public review queue.
    assert node_row((await client.get("/api/v1/status.json")).json())["icon"] is None
    assert service.icons.pending() == []

    used = await client.post(
        "/admin/icon/review", data={"csrf": csrf, "icon_id": str(staged["id"]), "decision": "approve"}
    )
    assert "approved and published" in used.text
    assert node_row((await client.get("/api/v1/status.json")).json())["icon"]["hash"] == staged["hash"]


async def test_admin_fetch_needs_a_session_and_token(app: FastAPI, client: httpx.AsyncClient) -> None:
    target = app.state.service.db.target_by_slug(Kind.NODE, "node.example.org")
    assert target is not None
    async with client_for(app) as stranger:
        r = await stranger.post(
            "/admin/icon/fetch", data={"csrf": "x", "target_id": str(target.id), "url": "https://a.example/x.png"}
        )
        assert r.status_code == 401
    await login(client)
    r = await client.post(
        "/admin/icon/fetch", data={"csrf": "forged", "target_id": str(target.id), "url": "https://a.example/x.png"}
    )
    assert "stale form" in r.text
