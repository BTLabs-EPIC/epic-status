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

from .config import Settings, load_seed_targets
from .config import settings as get_settings
from .db import Database
from .models import Kind
from .net import TargetRejected, build_client, peer_certificate_expiry, resolve_endpoint
from .probes.epicbox import probe_relay
from .probes.node import probe_tip, probe_version
from .submit import normalise

app = typer.Typer(
    add_completion=False,
    help="Health monitoring for Epic Cash public nodes and Epicbox relays.",
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
    kind: Annotated[str, typer.Option(help="node or epicbox.")] = "node",
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Probe one target now and print the result.

    Runs exactly the same code the poller runs, including the SSRF checks, so a
    result here is the result the board would show.
    """
    try:
        parsed_kind = Kind(kind.lower())
    except ValueError:
        raise typer.BadParameter("kind must be 'node' or 'epicbox'") from None

    result = asyncio.run(_check(parsed_kind, host))
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


async def _check(kind: Kind, raw: str) -> dict[str, object]:
    settings = get_settings()
    try:
        _, endpoint = normalise(kind, raw)
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim to the operator
        return {"ok": False, "endpoint": raw, "error": str(exc)}

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
        ours = " [ours]" if target.ours else ""
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
