"""Command line.

`serve` is what the systemd unit runs. The rest exists because the first thing
anyone self-hosting this will want is to check their own node from a terminal before
trusting a web page about it, and because debugging a probe should not require
starting a web server.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated

import typer

from .config import Settings, load_seed_targets, pool_adapters
from .config import settings as get_settings
from .db import Database
from .models import Kind
from .net import TargetRejected, build_client, peer_certificate_expiry, resolve_endpoint
from .probes.epicbox import probe_relay
from .probes.node import probe_tip, probe_version
from .probes.pool import probe_pool
from .submit import normalise

app = typer.Typer(
    add_completion=False,
    help="Health monitoring for Epic Cash public nodes, Epicbox relays and pools.",
    no_args_is_help=True,
)


@app.command()
def serve(
    bind: Annotated[str | None, typer.Option(help="Interface to bind.")] = None,
    port: Annotated[int | None, typer.Option(help="Port to bind.")] = None,
    reload: Annotated[bool, typer.Option(help="Reload on source change.")] = False,
) -> None:
    """Run the web service and the poller in one process."""
    import uvicorn

    settings = get_settings()
    host = bind or settings.bind
    if host not in {"127.0.0.1", "::1", "localhost"}:
        # Not blocked, because someone may genuinely be running this inside a private
        # network with no proxy. But it is said out loud, because the submit endpoint
        # accepts unauthenticated writes and the rate limit trusts a header that only
        # a proxy can be relied on to set.
        typer.secho(
            f"Binding {host} rather than loopback. The submit endpoint is "
            "unauthenticated and its rate limit trusts x-forwarded-for, so put a "
            "reverse proxy in front of this or disable submissions.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    uvicorn.run(
        "epic_status.api:create_app",
        factory=True,
        host=host,
        port=port or settings.port,
        reload=reload,
        access_log=False,
        # The reverse proxy already logs every request; a second copy in the journal
        # is noise that makes the poller's own messages hard to find.
    )


@app.command("check")
def check(
    host: Annotated[str, typer.Argument(help="Hostname, host:port, or full URL.")],
    kind: Annotated[str, typer.Option(help="node, epicbox or pool.")] = "node",
    adapter: Annotated[
        str | None,
        typer.Option(help="Pool response shape. Defaults to the registry entry."),
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Probe one target now and print the result.

    Runs exactly the same code the poller runs, including the SSRF checks, so a
    result here is the result the board would show.
    """
    try:
        parsed_kind = Kind(kind.lower())
    except ValueError:
        raise typer.BadParameter(
            "kind must be 'node', 'epicbox' or 'pool'"
        ) from None

    result = asyncio.run(_check(parsed_kind, host, adapter))
    if json_out:
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
        raise typer.Exit(0 if result.get("ok") else 1)

    ok = result.get("ok")
    typer.secho(
        f"{result['endpoint']}  {'OK' if ok else 'FAIL'}",
        fg=typer.colors.GREEN if ok else typer.colors.RED,
        bold=True,
    )
    for key, value in result.items():
        if key in {"ok", "endpoint"} or value is None:
            continue
        typer.echo(f"  {key:22} {value}")
    raise typer.Exit(0 if ok else 1)


async def _check(kind: Kind, raw: str, adapter: str | None = None) -> dict[str, object]:
    settings = get_settings()
    try:
        _, endpoint = normalise(kind, raw)
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim to the operator
        return {"ok": False, "endpoint": raw, "error": str(exc)}

    if kind is Kind.POOL:
        # Resolved from the registry before any network work, because both facts a
        # pool probe needs are configuration rather than DNS: which adapter to use,
        # and which host the API is actually on. `normalise` can only produce the
        # submitted hostname, and for epicmine that is the website — the stats live
        # on api.epicmine.io. Probing the normalised host returns HTML and reads as
        # a broken pool.
        entry = next(
            (
                t
                for t in load_seed_targets()
                if t.kind is Kind.POOL
                and raw in {t.slug, t.display_host, t.endpoint}
            ),
            None,
        )
        if entry is not None:
            endpoint = entry.endpoint
            adapter = adapter or entry.adapter
        if adapter is None:
            return {
                "ok": False,
                "endpoint": endpoint,
                "error": (
                    f"{raw} is not a pool in the registry, so its response shape is "
                    f"unknown. Pass --adapter, one of: {sorted(pool_adapters())}"
                ),
            }

    try:
        resolved = await resolve_endpoint(
            endpoint, allow_private=settings.allow_private_targets
        )
    except TargetRejected as exc:
        return {"ok": False, "endpoint": endpoint, "error": exc.message}

    out: dict[str, object] = {
        "endpoint": endpoint,
        "resolved": ", ".join(resolved.addresses),
    }

    if kind is Kind.POOL:
        assert adapter is not None
        async with build_client(timeout=settings.http_timeout_s) as client:
            pool = await probe_pool(client, resolved, adapter)
        out.update(
            ok=pool.ok,
            adapter=adapter,
            reason=pool.reason.value,
            latency_ms=pool.latency_ms,
            miners=pool.miners,
            workers=pool.workers,
            fee_percent=pool.fee_percent,
            last_block_height=pool.last_block_height,
            last_block_at=(
                pool.last_block_at.isoformat() if pool.last_block_at else None
            ),
            error=pool.error,
        )
        return out

    if kind is Kind.NODE:
        async with (
            build_client(timeout=settings.http_timeout_s) as client,
            build_client(timeout=settings.http_timeout_s, verify=False) as insecure,
        ):
            node = await probe_tip(client, insecure, resolved)
            out.update(
                ok=node.ok,
                reason=node.reason.value,
                latency_ms=node.latency_ms,
                height=node.height,
                tip_hash=node.tip_hash,
                error=node.error,
            )
            if node.ok:
                version = await probe_version(client, resolved)
                out["node_version"] = version.node_version
        return out

    relay = await probe_relay(resolved, timeout=settings.ws_timeout_s)
    days = await peer_certificate_expiry(resolved, settings.ws_timeout_s)
    out.update(
        ok=relay.ok,
        reason=relay.reason.value,
        latency_ms=relay.latency_ms,
        challenge_seen=relay.challenge_seen,
        protocol_version=relay.protocol_version,
        cert_expires_in_days=days,
        error=relay.error,
    )
    return out


@app.command("targets")
def list_targets(
    targets_file: Annotated[Path | None, typer.Option(help="Override the registry path.")] = None,
) -> None:
    """Show the committed seed registry, without touching the database."""
    settings = get_settings()
    for target in load_seed_targets(targets_file or settings.targets_file):
        ours = " [verified]" if target.verified else ""
        typer.echo(
            f"{target.kind.value:8} {target.display_host:28} {target.endpoint}{ours}"
        )


@app.command("init-db")
def init_db() -> None:
    """Create or migrate the database and load the seed registry.

    Not normally needed — `serve` does both at boot — but useful for checking a path
    and permissions before installing the unit.
    """
    settings = get_settings()
    db = Database(settings.db, settings.prober_id)
    db.reconcile_seeds(load_seed_targets(settings.targets_file))
    count = db.conn.execute(
        "SELECT COUNT(*) AS n FROM targets WHERE enabled = 1"
    ).fetchone()["n"]
    db.close()
    typer.echo(f"{settings.db}: {count} targets enabled")


@app.command("prune")
def prune(
    days: Annotated[int | None, typer.Option(help="Keep successes newer than this.")] = None,
) -> None:
    """Drop old successful checks. Failures are never pruned, deliberately.

    Nobody ever needs to prove a node was up; everybody eventually needs to prove it
    was down.
    """
    settings = get_settings()
    db = Database(settings.db, settings.prober_id)
    removed = db.prune(days if days is not None else settings.keep_success_days)
    db.conn.execute("VACUUM")
    db.close()
    typer.echo(f"removed {removed} successful checks")


@app.command("admin-password")
def admin_password(
    show: Annotated[
        bool, typer.Option(help="Print the generated password. It is not stored anywhere.")
    ] = True,
) -> None:
    """Generate a password for the review dashboard and print its hash.

    The password is generated here rather than accepted as an argument, because a password
    passed on the command line lands in the shell history of the machine it was typed on.
    It is shown once and never written down; only the hash is, and the hash is what goes in
    the unit file.

    Nothing is persisted by this command. Run it, copy the two lines it prints into the
    service environment, restart, and log in.
    """
    import secrets

    from .admin import hash_password

    # 40 base32-ish characters from `token_urlsafe(24)`: ~192 bits, which makes the
    # password itself a non-target and leaves scrypt guarding only against a stolen hash.
    password = secrets.token_urlsafe(24)
    digest = hash_password(password)

    typer.echo("")
    typer.echo("Add these to the service environment, then restart:")
    typer.echo("")
    typer.echo("  EPIC_STATUS_ADMIN_USER=admin")
    typer.echo(f"  EPIC_STATUS_ADMIN_PASSWORD_HASH='{digest}'")
    typer.echo("")
    if show:
        typer.echo("Password (shown once, not stored):")
        typer.echo("")
        typer.echo(f"  {password}")
        typer.echo("")
    typer.echo("With no hash configured, /admin is a 404 rather than a login form.")
    typer.echo("")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
