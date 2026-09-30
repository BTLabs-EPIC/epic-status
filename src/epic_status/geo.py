"""Provider and location lookup, via RDAP.

Two deliberate choices.

**RDAP rather than a geolocation API.** It is the registries' own data, served
over plain HTTPS with no key, no account and no rate-limit agreement to violate.
What it returns reliably is the *provider* — and for this network the provider is
the more interesting field by some distance. Probing the known targets while this
was written showed every public Epic node and relay sitting on exactly two
companies: five on Hetzner, two on Vultr. A Hetzner event in Finland takes out a
documented seed node and two relays simultaneously. No flag next to a hostname
conveys that; a provider tally does.

**Country is treated as low-confidence.** RDAP records carry a country
inconsistently: Hetzner allocations name the datacentre (CLOUD-FSN1, CLOUD-ASH),
while Vultr blocks carry no country at all. Anycast and proxied hosts report the
proxy. So the page labels it "registry location", an operator may override it at
submission, and it never overrides a measurement.

Lookups are cached in the database and refreshed weekly. This runs once per target
per week, not on the probe path.

An optional MMDB file (DB-IP Lite: CC-BY, monthly, no signup) can fill in country
and city where RDAP is silent. It is optional on purpose — requiring a downloaded
data file would put a step between `uv sync` and a working install.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from .models import GeoInfo

RDAP_BOOTSTRAP = "https://rdap.org/ip/"

# RDAP entity names are legal-registry strings. These are the ones this network
# actually sits on, mapped to what an operator would recognise. Anything not
# listed falls through to the registry string, truncated — never to "Unknown",
# which would hide real information.
_PROVIDER_ALIASES = {
    "hetzner online gmbh": "Hetzner",
    "hetzner online ag": "Hetzner",
    "vultr holdings, llc": "Vultr",
    "vultr holdings llc": "Vultr",
    "choopa, llc": "Vultr",
    "amazon technologies inc.": "AWS",
    "amazon data services": "AWS",
    "google llc": "Google Cloud",
    "digitalocean, llc": "DigitalOcean",
    "ovh sas": "OVH",
    "contabo gmbh": "Contabo",
    "linode": "Akamai/Linode",
    "oracle corporation": "Oracle Cloud",
    "microsoft corporation": "Azure",
    "cloudflare, inc.": "Cloudflare",
}

# Hetzner names its allocations after the datacentre, which is more precise than
# the country field and is the only location signal available for some blocks.
_NETWORK_CITIES = {
    "CLOUD-FSN1": ("DE", "Falkenstein"),
    "CLOUD-NBG1": ("DE", "Nuremberg"),
    "CLOUD-HEL1": ("FI", "Helsinki"),
    "CLOUD-ASH": ("US", "Ashburn"),
    "CLOUD-HIL": ("US", "Hillsboro"),
    "CLOUD-SIN": ("SG", "Singapore"),
}


def normalise_provider(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = " ".join(raw.split())
    alias = _PROVIDER_ALIASES.get(cleaned.lower())
    if alias:
        return alias
    # Strip the registry's contact-role suffix, which is noise: "Hetzner Online
    # GmbH - Contact Role" is the same company as "Hetzner Online GmbH".
    for separator in (" - Contact Role", " - Network Administrator"):
        if cleaned.endswith(separator):
            cleaned = cleaned[: -len(separator)]
            alias = _PROVIDER_ALIASES.get(cleaned.lower())
            if alias:
                return alias
    return cleaned[:48]


def _entity_name(doc: dict[str, Any]) -> str | None:
    """Pull the organisation name out of the jCard mess RDAP returns.

    The vcardArray is `["vcard", [[name, params, type, value], ...]]`, and the
    field wanted is `fn`. Written defensively because five registries produce five
    shapes and a malformed one must not break enrichment for every other target.
    """
    for entity in doc.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if (
                    isinstance(field, list)
                    and len(field) >= 4
                    and field[0] == "fn"
                    and isinstance(field[3], str)
                ):
                    return field[3]
    return None


def parse_rdap(doc: dict[str, Any]) -> GeoInfo:
    network_name = doc.get("name") if isinstance(doc.get("name"), str) else None
    country = doc.get("country") if isinstance(doc.get("country"), str) else None
    city: str | None = None

    if network_name:
        mapped = _NETWORK_CITIES.get(network_name.upper())
        if mapped:
            country = country or mapped[0]
            city = mapped[1]

    return GeoInfo(
        provider=normalise_provider(_entity_name(doc)),
        country=country.upper() if country else None,
        city=city,
        network_name=network_name,
        looked_up_at=datetime.now(UTC),
    )


async def lookup(client: httpx.AsyncClient, address: str) -> GeoInfo | None:
    """Look up one address.

    Never raises — enrichment is a nicety and a failed lookup must not affect a
    target's health or hold up a sweep. Returns None to mean "ask again soon"
    rather than an empty GeoInfo, because the caller caches results for a week and
    caching a rate-limited failure for a week loses the data entirely.
    """
    try:
        response = await client.get(
            f"{RDAP_BOOTSTRAP}{address}",
            follow_redirects=True,
            headers={"accept": "application/rdap+json, application/json"},
        )
        if response.status_code == 429:
            return None
        if response.status_code >= 400:
            # A genuine "no record" answer. Cache it, so a target in unallocated
            # space is not looked up every hour forever.
            return GeoInfo(looked_up_at=datetime.now(UTC))
        doc = response.json()
        if not isinstance(doc, dict):
            return GeoInfo(looked_up_at=datetime.now(UTC))
        return parse_rdap(doc)
    except Exception:  # noqa: BLE001 - see docstring
        return None


def merge(existing: GeoInfo, fresh: GeoInfo) -> GeoInfo:
    """Fresh registry data wins; every hand-set value is untouchable.

    The `*_manual` fields are carried straight through rather than being one input among
    several, because the registry is wrong often enough to matter and a weekly refresh
    would otherwise keep putting the wrong answer back. An admin correcting a country, a
    provider or a city corrects it once.
    """
    return GeoInfo(
        provider=fresh.provider or existing.provider,
        provider_manual=existing.provider_manual,
        country=fresh.country or existing.country,
        country_manual=existing.country_manual,
        city=fresh.city or existing.city,
        city_manual=existing.city_manual,
        network_name=fresh.network_name or existing.network_name,
        asn=fresh.asn or existing.asn,
        looked_up_at=fresh.looked_up_at or existing.looked_up_at,
    )
