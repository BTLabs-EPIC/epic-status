"""What Epic has released, as committed seeds.

The board needs two different facts about versions and an earlier version of this
code conflated them:

* **newest seen** — the highest version string any monitored node reported. Derived
  from the fleet, and wrong as a target: if every node were a release behind, the
  highest laggard would be nominated as "newest" and the board would report perfect
  version agreement while the whole fleet was stale.
* **released** — what upstream has actually published. Not derivable from probing
  nodes at all, because a release nobody has installed yet is invisible to the fleet.

The node and wallet values here are **seeds**, not the source of truth. `upstream.py`
reads the latest releases from GitHub in the background and remembers the last good
answer in SQLite; these constants are only what a fresh database starts from, and a
floor the published value never drops below. They used to be the source of truth,
mirrored by hand from devhub's `versions.js`, and went stale the day 4.1.0 shipped.
Bumping them on release is still good hygiene, not a requirement.

`EPICBOX_PROTOCOL` is still a constant: the relay repository publishes no GitHub
releases, so there is nothing to read.
"""

from __future__ import annotations

from typing import Final

#: Current released node version. Compared against what each node reports.
NODE: Final = "4.1.0"

#: Current released wallet version. Not probed — shown so the board can answer
#: "what should I be running" without sending the reader elsewhere.
WALLET: Final = "4.1.0"

#: Epicbox protocol version the relays should be speaking. Relays report their own
#: protocol version in the handshake, so this is comparable in the same way.
EPICBOX_PROTOCOL: Final = "3.0.1"

_NODE_REPO: Final = "https://github.com/EpicCash/epic"
_WALLET_REPO: Final = "https://github.com/EpicCash/epic-wallet"
#: The relay. Mirrors devhub's `repos.epicbox`. It publishes no GitHub *releases*, but it does
#: tag, so the protocol version deep-links to the tag matching the number beside it rather
#: than to the default branch — the same rule the node link follows.
_EPICBOX_REPO: Final = "https://github.com/EpicCash/epic-epicbox-docker"

#: Release tag pages. Deep-linked to the exact tag rather than `/releases/latest`,
#: so the link and the number next to it can never disagree.
NODE_URL: Final = f"{_NODE_REPO}/releases/tag/v{NODE}"
WALLET_URL: Final = f"{_WALLET_REPO}/releases/tag/v{WALLET}"
NODE_RELEASES_URL: Final = f"{_NODE_REPO}/releases"
EPICBOX_URL: Final = f"{_EPICBOX_REPO}/tree/{EPICBOX_PROTOCOL}"
