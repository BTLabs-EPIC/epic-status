"""Server icons: the optional picture a wallet shows beside a node, relay or pool.

Not to be confused with `icons`, the vendored Lucide marks this site draws itself. These
come from strangers, through a public form, which decides every choice below.

**Nothing uploaded is ever served.** An upload is decoded with Pillow and drawn onto a new
square canvas, and only that canvas is encoded — as PNG, at the sizes in
`config/icons.toml`. The bytes that arrived are discarded once decoded, so a polyglot (a
PNG that is also HTML, a JPEG with a ZIP appended), an EXIF block with GPS coordinates or a
text chunk with a script in it has nowhere to survive: none of it is pixels.

**The type is read from the content.** The first bytes decide PNG, JPEG or WebP, and Pillow
is then told to use that decoder and no other — so a file cannot be sniffed as one format
and parsed as another. The filename and the submitted Content-Type are not consulted.

**Size is checked before decoding.** Width and height come from the header; anything over
`max_side` or `max_pixels` is refused before a pixel is allocated, which is the defence
against a small file that decodes to gigabytes. Animated images are refused: a wallet tile
is a still, and a frame count is one more thing a decoder has to walk.

**SVG is refused**, not sanitised. See `config/icons.toml`.

**Approved is the only public state.** A submitted icon is `pending` until someone accepts
it at /admin; the public route serves a file only while its hash belongs to an `active`
icon. File names are the content hash, so a replaced icon gets a new URL and a wallet's
cache never shows the old picture under the new name.

The queries live here rather than in `db.Database`, which already carries every other
table: the icons table is self-contained, and this module is the only writer.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import ipaddress
import logging
import os
import re
import sqlite3
import threading
import time
import tomllib
import warnings
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

import httpx

from fastapi import Request, UploadFile
from fastapi.responses import Response
from PIL import Image, ImageOps, UnidentifiedImageError
from starlette.concurrency import run_in_threadpool

from .config import REPO_ROOT
from .db import Database
from .net import Resolver, TargetRejected, pinned_url, resolve_endpoint
from .web import cors

log = logging.getLogger("epic_status.server_icons")

#: The public route's file name: twenty hex digits of SHA-256, a size, `.png`. Anything
#: else is a 404 before the filesystem is touched, so no path from a URL reaches `open`.
ICON_NAME_RE: Final = re.compile(r"^([0-9a-f]{20})-([0-9]{2,4})\.png$")

#: Where approved icons are served. Under /api/ so nginx applies the API's rate limit and
#: its IP-less access log, and so the onion mirror serves it with no change.
PUBLIC_PREFIX: Final = "/api/v1/icons/"

#: The decoders that exist, keyed by the name used in the config file.
_PIL_FORMAT: Final = {"png": "PNG", "jpeg": "JPEG", "webp": "WEBP"}
SUPPORTED_TYPES: Final = frozenset(_PIL_FORMAT)

#: Allowed ranges for the config file. A typo should stop the service, not publish 4 px icons.
_SIZE_RANGE: Final = (16, 1024)
_MAX_BYTES_CEILING: Final = 8 * 1024 * 1024
_MAX_SIDE_CEILING: Final = 8192


class IconStatus(StrEnum):
    PENDING = "pending"
    """Submitted through the public form. Not served; waiting for /admin."""
    ACTIVE = "active"
    """Approved, or uploaded by an admin. At most one per target; the only state served."""
    REJECTED = "rejected"
    """Declined. Kept `rejected_retention_days`, then its files are deleted."""
    RETIRED = "retired"
    """Was active, then replaced or removed. Kept `retired_retention_days`."""


class IconOrigin(StrEnum):
    SUBMITTED = "submitted"
    ADMIN = "admin"


class IconRejected(Exception):
    """The upload is refused, with a reason fit to show the person who sent it."""


# ------------------------------------------------------------------------- settings


@dataclass(frozen=True)
class IconSettings:
    """`config/icons.toml`, validated. The defaults are the shipped file's values."""

    allowed_types: tuple[str, ...] = ("png", "jpeg", "webp")
    max_bytes: int = 1_048_576
    max_side: int = 2048
    max_pixels: int = 4_194_304
    min_side: int = 32
    sizes: tuple[int, ...] = (128, 256)
    storage_dir: Path = REPO_ROOT / "data" / "icons"
    rejected_retention_days: int = 14
    retired_retention_days: int = 30
    per_address_per_hour: int = 3
    global_per_hour: int = 20
    max_pending: int = 50
    fetch_timeout_s: float = 10.0
    fetch_max_redirects: int = 3

    @property
    def largest(self) -> int:
        return max(self.sizes)

    @property
    def max_body(self) -> int:
        """The request body the upload routes accept: the image plus the form around it."""
        return self.max_bytes + 64 * 1024


def _int(section: dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = section.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f"icons: {key} must be an integer from {low} to {high}, got {value!r}")
    return value


def load_icon_settings(path: Path) -> IconSettings:
    """Read the config file. Absent means the defaults; malformed means no boot."""
    if not path.exists():
        log.warning("icon settings %s not found; using the defaults", path)
        return IconSettings()
    with path.open("rb") as fh:
        doc = tomllib.load(fh)
    upload = doc.get("upload", {})
    output = doc.get("output", {})
    storage = doc.get("storage", {})
    limits = doc.get("limits", {})
    fetch = doc.get("fetch", {})

    types = upload.get("allowed_types", ["png", "jpeg", "webp"])
    if not isinstance(types, list) or not types:
        raise ValueError("icons: allowed_types must be a non-empty list")
    lowered = [str(t).lower() for t in types]
    if "svg" in lowered:
        raise ValueError(
            "icons: SVG cannot be enabled. It is a document format with scripting, and it "
            "is not sanitised here; convert it to PNG first."
        )
    unknown = [t for t in lowered if t not in SUPPORTED_TYPES]
    if unknown:
        raise ValueError(f"icons: unknown types {unknown}; known: {sorted(SUPPORTED_TYPES)}")

    sizes = output.get("sizes", [128, 256])
    if (
        not isinstance(sizes, list)
        or not sizes
        or not all(isinstance(s, int) and _SIZE_RANGE[0] <= s <= _SIZE_RANGE[1] for s in sizes)
    ):
        raise ValueError(f"icons: sizes must be integers from {_SIZE_RANGE[0]} to {_SIZE_RANGE[1]}")

    raw_dir = Path(str(storage.get("dir", "data/icons")))
    storage_dir = raw_dir if raw_dir.is_absolute() else REPO_ROOT / raw_dir

    max_side = _int(upload, "max_side", 2048, 64, _MAX_SIDE_CEILING)
    return IconSettings(
        allowed_types=tuple(dict.fromkeys(lowered)),
        max_bytes=_int(upload, "max_bytes", 1_048_576, 1024, _MAX_BYTES_CEILING),
        max_side=max_side,
        max_pixels=_int(upload, "max_pixels", 4_194_304, 64 * 64, max_side * max_side),
        min_side=_int(upload, "min_side", 32, 1, 512),
        sizes=tuple(sorted(set(sizes))),
        storage_dir=storage_dir,
        rejected_retention_days=_int(storage, "rejected_retention_days", 14, 0, 3650),
        retired_retention_days=_int(storage, "retired_retention_days", 30, 0, 3650),
        per_address_per_hour=_int(limits, "per_address_per_hour", 3, 0, 1000),
        global_per_hour=_int(limits, "global_per_hour", 20, 0, 100_000),
        max_pending=_int(limits, "max_pending", 50, 0, 10_000),
        fetch_timeout_s=float(_int(fetch, "timeout_s", 10, 1, 60)),
        fetch_max_redirects=_int(fetch, "max_redirects", 3, 0, 10),
    )


# -------------------------------------------------------------------- normalising


@dataclass(frozen=True)
class Normalised:
    """What an upload became. `renditions` are the only bytes that are ever stored."""

    hash: str
    renditions: dict[int, bytes]
    source_format: str
    source_width: int
    source_height: int
    source_bytes: int


def sniff(data: bytes) -> str | None:
    """The image type, from magic bytes alone."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _looks_like_svg(data: bytes) -> bool:
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return head.startswith((b"<?xml", b"<svg", b"<!doctype svg")) or b"<svg" in head


#: One decode at a time. Each can hold `max_pixels` × 4 bytes, and this process shares a
#: 256 MB cgroup with the poller; two concurrent bombs at the limit must not add up.
_decode_lock = threading.Lock()


def normalise(data: bytes, cfg: IconSettings) -> Normalised:
    """Decode, check and re-encode one upload, or raise IconRejected.

    Blocking and CPU-bound: call it through a thread (`run_in_threadpool`), not on the
    event loop.
    """
    if not data:
        raise IconRejected("The image file is empty.")
    if len(data) > cfg.max_bytes:
        raise IconRejected(f"The image is over {cfg.max_bytes // 1024} KB.")
    kind = sniff(data)
    if kind is None:
        if _looks_like_svg(data):
            raise IconRejected("SVG is not accepted. Upload a PNG, JPEG or WebP.")
        raise IconRejected(
            "That is not a PNG, JPEG or WebP image. The type is read from the file's "
            "content, not its name."
        )
    if kind not in cfg.allowed_types:
        raise IconRejected(f"{kind.upper()} images are not accepted here.")

    with _decode_lock, warnings.catch_warnings():
        # Pillow's own bomb check warns at MAX_IMAGE_PIXELS; ours below is tighter, and
        # this turns the warning into a refusal if it is ever reached first.
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            return _decode_and_encode(data, kind, cfg)
        except IconRejected:
            raise
        except (Image.DecompressionBombError, Image.DecompressionBombWarning):
            raise IconRejected("The image is too large once decoded.") from None
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError, EOFError) as exc:
            log.info("icon upload failed to decode as %s: %s", kind, exc)
            raise IconRejected(
                f"The file starts like a {kind.upper()} but could not be read as one."
            ) from None


def _decode_and_encode(data: bytes, kind: str, cfg: IconSettings) -> Normalised:
    # `formats=` pins the decoder to the sniffed type: the content cannot pick another.
    with Image.open(io.BytesIO(data), formats=[_PIL_FORMAT[kind]]) as img:
        width, height = img.size
        if width > cfg.max_side or height > cfg.max_side or width * height > cfg.max_pixels:
            raise IconRejected(
                f"The image is {width}×{height}. The limit is {cfg.max_side}×{cfg.max_side}."
            )
        if width < cfg.min_side or height < cfg.min_side:
            raise IconRejected(
                f"The image is {width}×{height}. It must be at least "
                f"{cfg.min_side}×{cfg.min_side}."
            )
        if getattr(img, "is_animated", False) or getattr(img, "n_frames", 1) > 1:
            raise IconRejected("Animated images are not accepted. Upload a still image.")
        if kind == "jpeg":
            # Lets libjpeg decode at a fraction of the size when the original is large.
            img.draft("RGB", (cfg.largest * 2, cfg.largest * 2))
        img.load()
        # Orientation is the one piece of metadata worth honouring: a phone photo of a
        # logo would otherwise arrive on its side. Everything else in EXIF is dropped.
        upright = ImageOps.exif_transpose(img)
        try:
            rgba = upright.convert("RGBA")
        except ValueError:
            raise IconRejected("The image's colour format is not supported.") from None

    rgba.thumbnail((cfg.largest, cfg.largest), Image.Resampling.LANCZOS)
    side = max(rgba.size)
    # A new image, so nothing from the original's `info` (ICC, text, EXIF) comes along.
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(rgba, ((side - rgba.width) // 2, (side - rgba.height) // 2))

    renditions: dict[int, bytes] = {}
    for size in cfg.sizes:
        frame = canvas if size == side else canvas.resize((size, size), Image.Resampling.LANCZOS)
        frame.info = {}
        out = io.BytesIO()
        frame.save(out, format="PNG", optimize=True)
        renditions[size] = out.getvalue()
    digest = hashlib.sha256(b"".join(renditions[s] for s in cfg.sizes)).hexdigest()[:20]
    return Normalised(
        hash=digest,
        renditions=renditions,
        source_format=kind,
        source_width=width,
        source_height=height,
        source_bytes=len(data),
    )


async def read_upload(upload: UploadFile, cfg: IconSettings) -> Normalised:
    """Read at most one byte past the limit, then decode off the event loop."""
    data = await upload.read(cfg.max_bytes + 1)
    if len(data) > cfg.max_bytes:
        raise IconRejected(f"The image is over {cfg.max_bytes // 1024} KB.")
    return await run_in_threadpool(normalise, data, cfg)


# --------------------------------------------------------------------- from a URL


_REDIRECTS: Final = frozenset({301, 302, 303, 307, 308})
_MAX_URL: Final = 2048


async def fetch_image(
    url: str,
    cfg: IconSettings,
    *,
    own_addresses: Callable[[], frozenset[str] | None],
    allow_private: bool = False,
    getaddrinfo: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bytes:
    """Download an image for an admin, or raise IconRejected. Admin-only: the public form
    never fetches anything.

    This makes the server open a connection to an address someone typed, so it carries the
    same guard as the submit probes (`net`), plus what a download needs:

    * **https only**, no credentials in the URL, and the request carries no cookies, no
      auth and no proxy settings from the environment (`trust_env=False`).
    * **Every hop is vetted.** The host is resolved here and refused if any address is
      private, loopback, link-local, reserved or one of this server's own; the request then
      goes to the vetted address, with the name only as Host and TLS SNI, so DNS cannot be
      changed between the check and the connection. Redirects are not followed by the
      client: each Location is checked as a new URL, at most `fetch_max_redirects` times.
    * **Bounded.** One deadline (`fetch_timeout_s`) over the whole chain, and the body is
      read as a stream and abandoned past `max_bytes`, whatever Content-Length claims.

    What comes back is only bytes. The type is decided by `normalise`, from magic bytes,
    exactly as for an upload.
    """
    try:
        async with asyncio.timeout(cfg.fetch_timeout_s):
            return await _fetch(url, cfg, own_addresses, allow_private, getaddrinfo, transport)
    except TimeoutError:
        raise IconRejected(
            f"The image did not arrive within {cfg.fetch_timeout_s:g} seconds."
        ) from None
    except httpx.HTTPError as exc:
        log.info("icon fetch failed: %s", type(exc).__name__)
        raise IconRejected(f"Could not download the image ({type(exc).__name__}).") from None


def _vet_url(url: str) -> None:
    if len(url) > _MAX_URL:
        raise IconRejected("That URL is too long.")
    try:
        parts = urlsplit(url)
    except ValueError:
        raise IconRejected("That is not a valid URL.") from None
    if parts.scheme.lower() != "https":
        raise IconRejected("Only https:// image URLs are fetched.")
    if parts.username or parts.password:
        raise IconRejected("URLs with a user name or password are not fetched.")
    if not parts.hostname:
        raise IconRejected("That URL has no host.")


async def _fetch(
    url: str,
    cfg: IconSettings,
    own_addresses: Callable[[], frozenset[str] | None],
    allow_private: bool,
    getaddrinfo: Resolver | None,
    transport: httpx.AsyncBaseTransport | None,
) -> bytes:
    async with httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        verify=True,
        timeout=httpx.Timeout(cfg.fetch_timeout_s),
        transport=transport,
        headers={"user-agent": "epic-status/0.1 (+https://github.com/BTLabs-EPIC/epic-status)"},
    ) as client:
        current = url.strip()
        for hop in range(cfg.fetch_max_redirects + 1):
            _vet_url(current)
            try:
                resolved = await resolve_endpoint(
                    current, allow_private=allow_private, getaddrinfo=getaddrinfo
                )
            except TargetRejected as exc:
                raise IconRejected(f"Refused: {exc.message}.") from None
            if not allow_private:
                own = own_addresses()
                if own is None:
                    raise IconRejected("Refused: this server's own addresses could not be read.")
                for addr in resolved.addresses:
                    if str(ipaddress.ip_address(addr.split("%", 1)[0])) in own:
                        raise IconRejected(
                            f"Refused: {resolved.hostname} points at this server ({addr})."
                        )
            parts = urlsplit(current)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            host = resolved.hostname if resolved.port == 443 else f"{resolved.hostname}:{resolved.port}"
            async with client.stream(
                "GET",
                pinned_url(resolved, path),
                headers={"host": host, "accept": "image/png, image/jpeg, image/webp"},
                extensions={"sni_hostname": resolved.hostname},
            ) as response:
                if response.status_code in _REDIRECTS:
                    location = response.headers.get("location")
                    if not location:
                        raise IconRejected("The server redirected without saying where.")
                    if hop == cfg.fetch_max_redirects:
                        raise IconRejected(
                            f"Refused: more than {cfg.fetch_max_redirects} redirects."
                        )
                    current = urljoin(current, location)
                    continue
                if response.status_code != 200:
                    raise IconRejected(f"The server answered HTTP {response.status_code}.")
                declared = response.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > cfg.max_bytes:
                    raise IconRejected(f"The image is over {cfg.max_bytes // 1024} KB.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > cfg.max_bytes:
                        raise IconRejected(f"The image is over {cfg.max_bytes // 1024} KB.")
                return bytes(body)
    raise IconRejected("Refused: too many redirects.")  # unreachable; the loop returns or raises


# --------------------------------------------------------------------- rate limit


@dataclass
class UploadLimiter:
    """Image-bearing submissions per address and in total, over a sliding hour.

    In memory, like the login limiter in `admin`: it resets on restart, which costs at most
    one extra hour's allowance, and the durable bound is `max_pending` in the database.
    Counted on every attempt, accepted or not, because decoding is the expensive part and a
    refused file still had to be decoded to be refused.
    """

    per_address: int
    total: int
    window_s: float = 3600.0
    _by_address: dict[str, deque[float]] = field(default_factory=dict)
    _all: deque[float] = field(default_factory=deque)

    def _trim(self, times: deque[float], now: float) -> None:
        while times and now - times[0] >= self.window_s:
            times.popleft()

    def allow(self, address: str) -> str | None:
        """None when allowed (and counted), else the refusal to show."""
        now = time.monotonic()
        self._trim(self._all, now)
        mine = self._by_address.setdefault(address, deque())
        self._trim(mine, now)
        if len(mine) >= self.per_address:
            return "Too many image uploads from your address in the last hour. Try later, or send the request without an image."
        if len(self._all) >= self.total:
            return "Too many image uploads in the last hour. Try later, or send the request without an image."
        mine.append(now)
        self._all.append(now)
        # Forget idle addresses, so the dict is bounded by the window rather than by time.
        if len(self._by_address) > 4096:
            for key in [k for k, v in self._by_address.items() if not v]:
                del self._by_address[key]
        return None


# -------------------------------------------------------------------------- store


ICONS_SCHEMA: Final = f"""
-- Server icons. One row per uploaded picture, keyed by the target's (kind, slug) rather
-- than its id: a seed row can be deleted and recreated from config/targets.toml, and a
-- submission's host becomes its slug when approved, so the key survives both.
-- `hash` names the files in the icon directory. New table, so reversible by
-- `DROP TABLE icons` plus deleting that directory.
CREATE TABLE IF NOT EXISTS icons (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,
    slug          TEXT NOT NULL,
    hash          TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ({",".join(f"'{s.value}'" for s in IconStatus)})),
    origin        TEXT NOT NULL CHECK (origin IN ({",".join(f"'{o.value}'" for o in IconOrigin)})),
    submission_id INTEGER,
    source_format TEXT,
    source_width  INTEGER,
    source_height INTEGER,
    source_bytes  INTEGER,
    created_at    TEXT NOT NULL,
    decided_at    TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_icons_one_active
    ON icons (kind, slug) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_icons_status ON icons (status, decided_at);
CREATE INDEX IF NOT EXISTS idx_icons_hash ON icons (hash);
"""


@dataclass(frozen=True)
class IconRef:
    """An active icon, as the API publishes it."""

    hash: str
    updated_at: str


_ACTIVE_TTL_S: Final = 30.0


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class IconStore:
    """The icons table and the directory of renditions beside it.

    Every method is synchronous and runs on the event loop thread, which is what keeps
    `prune` from deleting a file between `add` writing it and inserting the row naming it.
    """

    def __init__(self, db: Database, cfg: IconSettings) -> None:
        self.db = db
        self.cfg = cfg
        self.dir = cfg.storage_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        db.conn.executescript(ICONS_SCHEMA)
        self._active: dict[tuple[str, str], IconRef] | None = None
        self._active_at = 0.0

    # ------------------------------------------------------------------ reading

    def active(self) -> dict[tuple[str, str], IconRef]:
        """(kind, slug) → the approved icon.

        Cached; every write below clears it, and it expires after `_ACTIVE_TTL_S` so that a
        change made from the command line (`epic-status icon-set`, another process) shows
        up without a restart.
        """
        if self._active is None or time.monotonic() - self._active_at > _ACTIVE_TTL_S:
            self._active_at = time.monotonic()
            rows = self.db.conn.execute(
                "SELECT kind, slug, hash, COALESCE(decided_at, created_at) AS at"
                "  FROM icons WHERE status = 'active'"
            ).fetchall()
            self._active = {
                (str(r["kind"]), str(r["slug"])): IconRef(hash=str(r["hash"]), updated_at=str(r["at"]))
                for r in rows
            }
        return self._active

    def icon(self, icon_id: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.db.conn.execute(
            "SELECT * FROM icons WHERE id = ?", (icon_id,)
        ).fetchone()
        return row

    def pending(self) -> list[sqlite3.Row]:
        return list(
            self.db.conn.execute(
                "SELECT * FROM icons WHERE status = 'pending' AND origin = 'submitted'"
                " ORDER BY created_at DESC, id DESC"
            ).fetchall()
        )

    def pending_count(self) -> int:
        row = self.db.conn.execute(
            "SELECT COUNT(*) AS n FROM icons WHERE status = 'pending' AND origin = 'submitted'"
        ).fetchone()
        return int(row["n"])

    def pending_by_submission(self) -> dict[int, sqlite3.Row]:
        return {
            int(r["submission_id"]): r
            for r in self.pending()
            if r["submission_id"] is not None
        }

    def path_for(self, name: str, *, public: bool) -> Path | None:
        """The file behind a route name, or None.

        Public: only an active icon's renditions. Admin: any icon still on record, so a
        pending one can be previewed. The name is matched against a strict pattern and the
        size against the config before a path is built from it.
        """
        match = ICON_NAME_RE.match(name)
        if match is None or int(match.group(2)) not in self.cfg.sizes:
            return None
        digest = match.group(1)
        if public:
            if digest not in {ref.hash for ref in self.active().values()}:
                return None
        else:
            known = self.db.conn.execute(
                "SELECT 1 FROM icons WHERE hash = ? LIMIT 1", (digest,)
            ).fetchone()
            if known is None:
                return None
        path = self.dir / name
        return path if path.is_file() else None

    # ------------------------------------------------------------------ writing

    def _write_files(self, item: Normalised) -> None:
        for size, data in item.renditions.items():
            final = self.dir / f"{item.hash}-{size}.png"
            if final.exists():
                continue
            # Write then rename, so a reader never sees half a file under the final name.
            partial = final.with_suffix(".part")
            partial.write_bytes(data)
            os.replace(partial, final)

    def add(
        self,
        item: Normalised,
        *,
        kind: str,
        slug: str,
        origin: IconOrigin,
        status: IconStatus,
        submission_id: int | None = None,
    ) -> int:
        """Store the renditions and record them. An active icon replaces the current one."""
        self._write_files(item)
        now = _now_iso()
        with self.db.tx() as conn:
            if status is IconStatus.ACTIVE:
                conn.execute(
                    "UPDATE icons SET status = 'retired', decided_at = ?"
                    " WHERE kind = ? AND slug = ? AND status = 'active'",
                    (now, kind, slug),
                )
            cur = conn.execute(
                """
                INSERT INTO icons (kind, slug, hash, status, origin, submission_id,
                                   source_format, source_width, source_height, source_bytes,
                                   created_at, decided_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    kind,
                    slug,
                    item.hash,
                    status.value,
                    origin.value,
                    submission_id,
                    item.source_format,
                    item.source_width,
                    item.source_height,
                    item.source_bytes,
                    now,
                    now if status is IconStatus.ACTIVE else None,
                ),
            )
        self._active = None
        return int(cur.lastrowid or 0)

    def approve(self, icon_id: int) -> sqlite3.Row | None:
        """Make a pending icon the target's icon. None if it is not pending."""
        row = self.icon(icon_id)
        if row is None or row["status"] != IconStatus.PENDING:
            return None
        now = _now_iso()
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE icons SET status = 'retired', decided_at = ?"
                " WHERE kind = ? AND slug = ? AND status = 'active'",
                (now, row["kind"], row["slug"]),
            )
            conn.execute(
                "UPDATE icons SET status = 'active', decided_at = ? WHERE id = ?",
                (now, icon_id),
            )
            # Any other preview fetched for this target is moot once one is chosen.
            conn.execute(
                "UPDATE icons SET status = 'rejected', decided_at = ?"
                " WHERE kind = ? AND slug = ? AND status = 'pending' AND origin = 'admin'",
                (now, row["kind"], row["slug"]),
            )
        self._active = None
        return self.icon(icon_id)

    def stage(self, item: Normalised, *, kind: str, slug: str) -> int:
        """Keep an admin's fetched image as a preview: pending, origin admin, not public.
        Replaces any earlier preview for the same target."""
        self.db.conn.execute(
            "UPDATE icons SET status = 'rejected', decided_at = ?"
            " WHERE kind = ? AND slug = ? AND status = 'pending' AND origin = 'admin'",
            (_now_iso(), kind, slug),
        )
        return self.add(
            item, kind=kind, slug=slug, origin=IconOrigin.ADMIN, status=IconStatus.PENDING
        )

    def staged(self) -> dict[tuple[str, str], sqlite3.Row]:
        """(kind, slug) → an admin's fetched preview awaiting Use or Discard."""
        return {
            (str(r["kind"]), str(r["slug"])): r
            for r in self.db.conn.execute(
                "SELECT * FROM icons WHERE status = 'pending' AND origin = 'admin'"
                " ORDER BY id"
            ).fetchall()
        }

    def reject(self, icon_id: int) -> sqlite3.Row | None:
        row = self.icon(icon_id)
        if row is None or row["status"] != IconStatus.PENDING:
            return None
        self.db.conn.execute(
            "UPDATE icons SET status = 'rejected', decided_at = ? WHERE id = ?",
            (_now_iso(), icon_id),
        )
        return self.icon(icon_id)

    def reject_for_submission(self, submission_id: int) -> int:
        """A declined or deleted request takes its pending icon with it."""
        cur = self.db.conn.execute(
            "UPDATE icons SET status = 'rejected', decided_at = ?"
            " WHERE submission_id = ? AND status = 'pending'",
            (_now_iso(), submission_id),
        )
        return cur.rowcount

    def remove(self, kind: str, slug: str) -> bool:
        """Take the target's icon down; the wallet falls back to initials."""
        cur = self.db.conn.execute(
            "UPDATE icons SET status = 'retired', decided_at = ?"
            " WHERE kind = ? AND slug = ? AND status = 'active'",
            (_now_iso(), kind, slug),
        )
        self._active = None
        return cur.rowcount > 0

    def prune(self, now: datetime | None = None) -> int:
        """Forget rejected and retired icons past retention, and delete unused files.

        A file is deleted only when no remaining row names its hash, so two servers sharing
        one picture keep it while either uses it. Returns the number of files deleted.
        """
        now = now or datetime.now(UTC)
        stamp = "%Y-%m-%dT%H:%M:%SZ"
        rejected_before = (now - timedelta(days=self.cfg.rejected_retention_days)).strftime(stamp)
        retired_before = (now - timedelta(days=self.cfg.retired_retention_days)).strftime(stamp)
        self.db.conn.execute(
            "DELETE FROM icons WHERE (status = 'rejected' AND decided_at < ?)"
            " OR (status = 'retired' AND decided_at < ?)",
            (rejected_before, retired_before),
        )
        keep = {str(r["hash"]) for r in self.db.conn.execute("SELECT DISTINCT hash FROM icons")}
        removed = 0
        for path in self.dir.iterdir():
            match = ICON_NAME_RE.match(path.name)
            stale_part = path.suffix == ".part" and time.time() - path.stat().st_mtime > 3600
            if (match and match.group(1) not in keep) or stale_part:
                path.unlink(missing_ok=True)
                removed += 1
        if removed:
            log.info("pruned %d icon files", removed)
        return removed


def public_icon(ref: IconRef | None, base_url: str, sizes: tuple[int, ...]) -> dict[str, Any] | None:
    """The `icon` object in the API, or None — which the wallet shows as initials."""
    if ref is None:
        return None
    base = base_url.rstrip("/")
    urls = {str(s): f"{base}{PUBLIC_PREFIX}{ref.hash}-{s}.png" for s in sizes}
    return {
        "url": urls[str(max(sizes))],
        "urls": urls,
        "hash": ref.hash,
        "updated_at": ref.updated_at,
    }


#: Content-addressed: the bytes behind a public icon's name never change.
PUBLIC_CACHE: Final = "public, max-age=31536000, immutable"


def icon_response(
    request: Request, name: str, path: Path | None, *, cache: str = PUBLIC_CACHE
) -> Response:
    """An icon file, or a 404. Shared by the public route and the admin preview, which
    passes a private `cache`: a pending icon must not land in a shared cache."""
    headers = {
        "x-content-type-options": "nosniff",
        # An image needs no policy to render, and `sandbox` keeps it inert if a browser is
        # ever talked into treating one as a document.
        "content-security-policy": "default-src 'none'; sandbox",
        "cross-origin-resource-policy": "cross-origin",
        **cors(),
    }
    if path is None:
        return Response(status_code=404, headers={"cache-control": "no-store", **headers})
    etag = f'"{name.removesuffix(".png")}"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"etag": etag, **headers})
    return Response(
        path.read_bytes(),
        media_type="image/png",
        headers={
            "etag": etag,
            "cache-control": cache,
            **headers,
        },
    )
