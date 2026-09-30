"""What Epic has actually released.

The board needs two different facts about versions and an earlier version of this
code conflated them:

* **newest seen** — the highest version string any monitored node reported. Derived
  from the fleet, and wrong as a target: if every node were a release behind, the
  highest laggard would be nominated as "newest" and the board would report perfect
  version agreement while the whole fleet was stale.
* **released** — what upstream has actually published. Not derivable from probing
  nodes at all, because a release nobody has installed yet is invisible to the fleet.

This module is the second one, and it is a committed constant on purpose. Fetching
the GitHub releases API at runtime would make a page whose entire claim is "no
external services" depend on one, and a status page that cannot render because
api.github.com is rate-limiting is a worse failure than a version string going stale.

Mirrored by hand from `epic-devhub/site/src/data/versions.js`, which is the developer
documentation's single source of truth for the same values. Keep the two in step: bump
this on release, in the same commit that bumps devhub, and nothing else here changes.
`EPIC_STATUS_RELEASED_NODE_VERSION` overrides the node value for an operator tracking
a different line, so a fork does not have to patch the source.

`NODE` mirrors devhub's `node`, not its `nodeBinaries`. Those two differ whenever a
release ships without attached binaries, as v4.0.4 did — its release job failed to
create the assets. That distinction matters to a downloads page and not at all here,
because this value is only ever compared against what a running node reports, and a
node built from the v4.0.4 tag reports 4.0.4 whether or not a tarball exists for it.

A stale constant degrades honestly. `nodes_current` simply reports 0 of N on the new
release until this is bumped, which reads as "nobody has upgraded yet" — true, and the
same thing the board would say on the day a release actually lands.
"""

from __future__ import annotations

from typing import Final

#: Current released node version. Compared against what each node reports.
NODE: Final = "4.0.4"

#: Current released wallet version. Not probed — shown so the board can answer
#: "what should I be running" without sending the reader elsewhere.
WALLET: Final = "4.0.0"

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
