"""Settings and the committed seed registry.

`config/targets.toml` is real deployment data under test, not a fixture. It is the
canonical list of Epic Cash mainnet servers this instance monitors, so a typo in it
is a production defect and belongs in CI rather than in a boot log.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import pytest

from epic_status.config import Settings, load_seed_targets
from epic_status.models import Kind, Source
from epic_status.probes.epicbox import domain_is_addressable

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "targets.toml"


@pytest.fixture(scope="module")
def seeds() -> list:
    return load_seed_targets(REGISTRY)


def test_committed_registry_parses(seeds: list) -> None:
    assert len(seeds) > 0
    assert any(t.kind is Kind.NODE for t in seeds)
    assert any(t.kind is Kind.EPICBOX for t in seeds)


def test_every_entry_is_a_seed(seeds: list) -> None:
    """Seeds are exempt from auto-removal. A submitted-source row loaded from the
    committed file would delete itself after a sustained outage — which is exactly
    when it most needs to be on the board."""
    assert all(t.source is Source.SEED for t in seeds)
    assert all(t.enabled for t in seeds)


def test_no_duplicate_slugs(seeds: list) -> None:
    """The slug is the public API's `id` and appears in URLs, so a collision is
    ambiguous to every consumer."""
    slugs = [(t.kind, t.slug) for t in seeds]
    assert len(slugs) == len(set(slugs))


def test_node_endpoints_are_urls_with_a_scheme(seeds: list) -> None:
    """`endpoint` is a URL, not host:port, because both deployment shapes exist: the
    node's listener exposed directly on 3413, or kept on loopback behind nginx on
    443. A bare host:port cannot express the second, which is the better one.
    """
    for t in (t for t in seeds if t.kind is Kind.NODE):
        parts = urlsplit(t.endpoint)
        assert parts.scheme in {"http", "https"}, t.slug
        assert parts.hostname, t.slug
        assert not t.endpoint.endswith("/"), f"{t.slug}: probe appends /v2/foreign"


def test_epicbox_endpoints_are_wss(seeds: list) -> None:
    """Every relay in the wild speaks wss on 443. A ws:// entry would send an
    epicbox address and its challenge response over plaintext."""
    for t in (t for t in seeds if t.kind is Kind.EPICBOX):
        assert t.endpoint.startswith("wss://"), t.slug
        assert urlsplit(t.endpoint).port == 443, t.slug


def test_epicbox_hostnames_are_addressable(seeds: list) -> None:
    """A hyphen or underscore in a relay hostname makes every epicbox address on it
    unparseable while the relay still handshakes green. Listing one would publish a
    permanently broken endpoint as healthy."""
    for t in (t for t in seeds if t.kind is Kind.EPICBOX):
        assert domain_is_addressable(t.display_host), t.slug


def test_our_own_node_is_flagged_as_ours(seeds: list) -> None:
    """Listing your own infrastructure on a page you control without saying so reads
    as promotion."""
    mine = [t for t in seeds if t.ours]
    assert [t.slug for t in mine] == ["node.btlabs.uk"]


def test_country_codes_are_uppercase_alpha2(seeds: list) -> None:
    for t in seeds:
        if t.geo.country is not None:
            assert len(t.geo.country) == 2, t.slug
            assert t.geo.country.isupper(), t.slug


def test_display_host_is_set_for_every_entry(seeds: list) -> None:
    """It is what a human reads on the board, and it is not derivable from the
    endpoint — node.btlabs.uk deliberately shows no port."""
    assert all(t.display_host for t in seeds)


# ----------------------------------------------------------------------- failures


def test_duplicate_slugs_raise(tmp_path: Path) -> None:
    doc = """
[[node]]
slug = "same"
display_host = "a.example.com:3413"
endpoint = "https://a.example.com:3413"

[[node]]
slug = "same"
display_host = "b.example.com:3413"
endpoint = "https://b.example.com:3413"
"""
    path = tmp_path / "targets.toml"
    path.write_text(doc)

    with pytest.raises(ValueError, match="duplicate slugs"):
        load_seed_targets(path)


def test_a_slug_shared_between_a_node_and_a_relay_raises(tmp_path: Path) -> None:
    """The slug is the API's public id across both groups, so uniqueness is global
    even though the database's UNIQUE constraint is per kind."""
    doc = """
[[node]]
slug = "epiccash.com"
display_host = "epiccash.com"
endpoint = "https://epiccash.com:3413"

[[epicbox]]
slug = "epiccash.com"
display_host = "epiccash.com"
endpoint = "wss://epiccash.com:443/"
"""
    path = tmp_path / "targets.toml"
    path.write_text(doc)

    with pytest.raises(ValueError, match="duplicate slugs"):
        load_seed_targets(path)


def test_a_malformed_entry_is_a_startup_failure(tmp_path: Path) -> None:
    """Not a silently skipped row. A status page that quietly stops monitoring
    something is worse than one that refuses to boot."""
    path = tmp_path / "targets.toml"
    path.write_text('[[node]]\nslug = "x"\nendpoint = "https://x:3413"\n')

    with pytest.raises(KeyError):
        load_seed_targets(path)


# ----------------------------------------------------------------------- settings


def test_private_targets_are_off_by_default() -> None:
    """Flipping this on a public instance turns the submit form into a port scanner
    aimed at your own network, so the default is the safe one and the test fixture
    has to opt in explicitly."""
    assert Settings(_env_file=None).allow_private_targets is False


def test_settings_fixture_opts_into_private_targets(settings: Settings) -> None:
    assert settings.allow_private_targets is True
    assert settings.bind == "127.0.0.1"
    assert settings.port == 13431


def test_default_targets_file_is_the_committed_registry() -> None:
    """Resolved from the package location, not the working directory, so the unit's
    WorkingDirectory is not load-bearing for finding the registry."""
    assert Settings(_env_file=None).targets_file == REGISTRY
