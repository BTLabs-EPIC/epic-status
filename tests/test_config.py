"""Settings and the committed seed registry.

`config/targets.toml` is real deployment data under test, not a fixture. It is the
canonical list of Epic Cash mainnet servers this instance monitors, so a typo in it
is a production defect and belongs in CI rather than in a boot log.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import pytest

from epic_status.config import Settings, load_seed_targets, pool_adapters
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
    assert any(t.kind is Kind.POOL for t in seeds)


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


def test_a_seed_is_flagged_as_verified(seeds: list) -> None:
    """Listing your own infrastructure on a page you control without saying so reads
    as promotion.

    The floonet pair is ours too, and on the same host as the mainnet node, so the same
    rule applies to it. The assertion is a sorted comparison rather than file order
    because order here is an artefact of which section of the TOML an entry sits in, not
    a fact worth pinning.
    """
    mine = sorted(t.slug for t in seeds if t.verified)
    assert mine == [
        "floo-node.btlabs.uk",
        "flooepicbox.btlabs.uk",
        "node.btlabs.uk",
    ]


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


# -------------------------------------------------------------------------- pools


def test_every_pool_names_a_real_adapter(seeds: list) -> None:
    """A pool's response shape cannot be inferred, so the registry names it. An
    adapter that does not exist would probe and fail forever, reported as the pool
    being down rather than as our configuration being wrong."""
    known = pool_adapters()
    pools = [t for t in seeds if t.kind is Kind.POOL]
    assert pools
    for t in pools:
        assert t.adapter in known, f"{t.slug} names unknown adapter {t.adapter!r}"


def test_only_pools_carry_an_adapter(seeds: list) -> None:
    for t in seeds:
        if t.kind is not Kind.POOL:
            assert t.adapter is None, f"{t.slug} is a {t.kind.value} with an adapter"


def test_pool_endpoints_are_https_without_a_trailing_slash(seeds: list) -> None:
    """The adapter appends a rooted path, so a trailing slash would produce a double
    slash and a 404 on some frameworks. Plain HTTP would put a stats request on the
    wire in clear, and these are all public web APIs with certificates."""
    for t in (t for t in seeds if t.kind is Kind.POOL):
        assert t.endpoint.startswith("https://"), t.slug
        assert not t.endpoint.endswith("/"), t.slug


def test_a_pool_endpoint_may_differ_from_its_display_host(seeds: list) -> None:
    """Not a typo when it happens: epicmine's site is epicmine.io and its API is on
    api.epicmine.io, so these two fields are independent for pools."""
    pools = {t.slug: t for t in seeds if t.kind is Kind.POOL}
    assert "epicmine.io" in pools
    assert urlsplit(pools["epicmine.io"].endpoint).hostname == "api.epicmine.io"


def test_an_unknown_adapter_is_a_startup_failure(tmp_path: Path) -> None:
    """Loud at boot rather than a permanently red row on the board."""
    bad = tmp_path / "targets.toml"
    bad.write_text(
        '[[pool]]\n'
        'slug = "p.example"\n'
        'display_host = "p.example"\n'
        'endpoint = "https://p.example"\n'
        'adapter = "does-not-exist"\n'
    )
    with pytest.raises(ValueError, match="does-not-exist"):
        load_seed_targets(bad)


def test_a_pool_without_an_adapter_is_a_startup_failure(tmp_path: Path) -> None:
    bad = tmp_path / "targets.toml"
    bad.write_text(
        '[[pool]]\n'
        'slug = "p.example"\n'
        'display_host = "p.example"\n'
        'endpoint = "https://p.example"\n'
    )
    with pytest.raises(KeyError):
        load_seed_targets(bad)


def test_dead_entries_are_gone_from_the_registry(seeds: list) -> None:
    """These seven never answered once across thousands of probes. The four node
    addresses came from a commented-out example in the Epic node's config generator
    rather than from any seed list, and three relays did not resolve. Four permanent
    failures beside three permanent successes makes the board's own red mean less."""
    slugs = {t.slug for t in seeds}
    assert not slugs & {
        "95.217.197.180",
        "5.161.127.56",
        "5.75.242.4",
        "5.78.71.29",
        "epicbox.fastepic.eu",
        "epicbox.btlabs.tech",
        "epicbox.51pool.online",
    }


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
