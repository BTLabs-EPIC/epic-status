# epic-status

Health and uptime monitoring for Epic Cash public nodes, Epicbox relays and mining
pools, on mainnet and floonet.
One process: an asyncio poller, SQLite, and a server-rendered board. No build step,
no framework on the client, no external services.

Live instance: <https://status.btlabs.uk>

Runs as a systemd unit, behind nginx, on one small VPS alongside a live mainnet node.

## What it measures, and what it cannot

Per node, one unauthenticated JSON-RPC call every 5 seconds:

```
POST {endpoint}/v2/foreign
{"jsonrpc":"2.0","method":"get_tip","params":[],"id":1}
```

468 bytes of response. From it: reachability, latency, tip height, tip hash, total
difficulty. Derived across the fleet: **tip lag against the highest tip seen**, and
**fork detection** — two nodes reporting the same height with different tip hashes.
`get_version` runs every 5 minutes.

Per chain, one `get_header` per new block, from one node that agrees on the tip,
because "is the chain moving" is a property of the chain rather than of a node. The
last day of canonical headers is kept, and that record is what three things come from:

- **Tip age** — when the newest block was mined, from its own timestamp.
- **Reorgs.** A reorg is invisible in any single snapshot; afterwards every node agrees
  again. It is only visible as a difference from what was seen before. When the tip
  changes, the new chain is walked back until it rejoins a stored block, and every
  stored block passed on the way was replaced. The count is the depth. All of this
  is the public foreign API: `get_tip` names the tip hash, `get_header` returns each
  block's hash and parent. No owner API and no node of our own are needed.
  Two limits, stated: a block replaced and replaced back between two sweeps was never
  seen, and anything deeper than the 30-block walk is reported as "at least 30".
- **The chain panel** on `/history`: median and longest block interval, the
  algorithm mix, and each algorithm's current difficulty — the step in its cumulative
  `total_difficulty` counter between consecutive headers.

Every 30 minutes, per node and relay: **IPv6** — the same probe repeated against the
AAAA address alone, because an AAAA record that does not answer is a fault a client
preferring IPv6 hits first — and, for nodes, **browser access**: the CORS preflight a
web wallet sends before its first call.

Per relay, every 30 seconds: a WebSocket connection, one frame read, close. The relay
pushes `{"type":"Challenge","str":...}` unprompted before the client writes anything,
so a single frame proves TLS, the reverse proxy's upgrade path, the relay process and
a responsive event loop. Certificate expiry comes from a separate handshake every 6
hours.

**Peer counts and sync status are not obtainable.** They live on the owner API, which
requires an `api_secret`. No status page can publish them for someone else's node,
and this one does not pretend to.

Three things it deliberately does not do:

- **No HTTP `GET` against a relay.** Rendering a relay's own status page fires three
  outbound TLS connections to other relays. Polling it would make this an amplifier
  aimed at the hosts it exists to help.
- **No `Subscribe` or `PostSlate`.** Subscribing registers a throwaway key in a
  stranger's datastore; posting writes a row in their database.
- **No automatic probing from the reader's browser.** Timing requests from a visitor to
  every listed server would put their address in every operator's logs because they
  opened a status page. Latency shown is measured server-side, and the page says from
  where. The "Check connection" button in an expanded row is the one exception: opt-in,
  per host, per press — see [Security](#security).

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone <this repo> epic-status && cd epic-status
uv sync
uv run epic-status serve
```

<http://127.0.0.1:13431>. The database is created on first run and the seed registry
is loaded from `config/targets.toml` at every boot.

Probe one target without starting anything:

```sh
uv run epic-status check node.epiccash.com:3413
uv run epic-status check epicbox.epiccash.com --kind epicbox
uv run epic-status check epicmine.io --kind pool
uv run epic-status check node.example.org --json
```

Exit status is 0 if the target answered, 1 if not, so it works in a shell pipeline.
It runs the same code the poller runs, including the address checks.

## Configuration

Environment, prefix `EPIC_STATUS_`. A `.env` file in the working directory is read if
present.

| Variable | Default | Notes |
| --- | --- | --- |
| `BIND` | `127.0.0.1` | Leave it. See [Security](#security). |
| `PORT` | `13431` | |
| `DB` | `./data/status.db` | Use an absolute path in a unit file. |
| `TARGETS_FILE` | `./config/targets.toml` | |
| `SITE_NAME` | `Epic Cash Status` | |
| `SITE_URL` | `http://127.0.0.1:13431` | Only used to print the `curl` example. |
| `PROBER_ID` | `local` | Stamped on every stored check. |
| `PROBER_REGION` | `unknown` | Shown in the footer. |
| `RELEASED_NODE_VERSION` | from `releases.py` | What upstream published. Not the highest version seen. |
| `SUBMISSIONS_ENABLED` | `true` | `false` removes the form and the endpoint. |
| `ALLOW_PRIVATE_TARGETS` | `false` | Development only. Read [Security](#security) first. |
| `KEEP_SUCCESS_DAYS` | `7` | Failures are never pruned. |
| `MAX_CONCURRENCY` | `16` | Concurrent in-flight probes. |
| `HTTP_TIMEOUT_S` | `4.0` | Also the floor on sweep duration when a node is dead. |
| `WS_TIMEOUT_S` | `8.0` | |
| `ADMIN_USER` | `admin` | |
| `ADMIN_PASSWORD_HASH` | empty | From `epic-status admin-password`. Empty means `/admin` does not exist. |
| `ADMIN_COOKIE_SECURE` | `true` | `false` only for plain-HTTP development. |
| `OWN_NODE_URL` | unset | A node you run, which the board may time from the reader's browser. |
| `PROBER_KEYS` | empty | `id:secret,…` for remote probers. Empty means no push endpoint. See [Second vantage point](#second-vantage-point). |

Nothing hardcodes a hostname. Moving an instance to a different domain is a DNS
record and `SITE_URL`.

### The target registry

`config/targets.toml` is the canonical list, in git so adding a community server is a
reviewable commit. Public submissions live in SQLite instead. Seed entries are exempt
from auto-removal, because `node.epiccash.com` being down is the most important thing
this page can report and it must not vanish for being down.

```toml
[[node]]
slug = "node.example.org"
display_host = "node.example.org:3413"
endpoint = "https://node.example.org:3413"
p2p = "node.example.org:3414"     # optional, TCP fallback when the API is closed
operator = "Example Pool"
country = "DE"                    # optional, and authoritative — see below
ours = false

[[epicbox]]
slug = "epicbox.example.org"
display_host = "epicbox.example.org"
endpoint = "wss://epicbox.example.org:443/"
operator = "Example Pool"

[[pool]]
slug = "pool.example.org"
display_host = "pool.example.org"       # the pool as a miner knows it
endpoint = "https://api.pool.example.org"   # base of its API, often a different host
adapter = "examplepool"                 # must exist in probes/pool.py — see below
operator = "Example Pool"
```

**A pool needs an `adapter`, and adding one is a code change.** Nodes and relays each
speak a single protocol, so one probe covers every host of that kind. Pools do not:
each exposes a hand-rolled JSON endpoint at its own path, with its own envelope, and
its own units — one of the two listed here reports a 2% fee as the string `"0.02"`
while the other reports 2.5% as the number `2.5`. Each shape is therefore a named
entry in `ADAPTERS` in `src/epic_status/probes/pool.py`, and the registry names which
one to use. An adapter that does not exist is a startup failure rather than a
permanently red row. Submitting a pool through the form records a request for manual
integration; it is not probed and not auto-promoted.

`endpoint` is a **URL, not host:port**, because both deployment shapes exist in the
wild: the node's own listener exposed directly on 3413, or the listener kept on
loopback with nginx terminating TLS on 443. The second is the better deployment and a
host:port model cannot express it.

Reconciliation updates seed rows in place. Editing a label never deletes history.
A seed removed from the file is disabled, not deleted.

## The health model

Three states, not two:

| State | Meaning |
| --- | --- |
| **healthy** | Answered, and within `tip_lag_healthy` (10) blocks of the highest tip. |
| **degraded** | Up but not fully usable, or not yet confirmed down. |
| **down** | Failed `down_after_failures` (3) consecutive checks. |

A two-state light is wrong in three common cases, all visible to the operators being
reported on: a node whose foreign API returns 401 is up and in consensus but
unpollable; a node 5,000 blocks behind answers `get_tip` flawlessly; and a probe that
failed from *our* host proves nothing about theirs. `degraded` is the honest bucket
for those, not a hedge.

**Fork detection waits for confirmation.** Two nodes at the same height with
different tip hashes genuinely hold different blocks — but that is also what a normal
orphan race looks like for a few seconds on any proof-of-work chain. A conflict must
persist across three consecutive sweeps before it is called a fork; below that it is
reported as a reorg in progress. A status page for a small PoW coin that announced a
fork on every orphan would cause the panic it exists to detect.

**The score, 0–100, covers nodes only.** Reachability 40% (degraded counts as a
half), tip agreement 35%, latency 15% on a curve that flattens past a second, version
spread 10%, and a flat −25 if forked. Epicbox and pools are excluded on purpose: a
dead relay breaks one transport for the wallets configured to use it and a dead pool
costs its own miners, while a forked chain breaks everything. Averaging failure
domains with different blast radii produces a number that means nothing in any of
them.

**A pool's block height is not compared to the chain tip, and this is deliberate.**
The pool APIs' `currentHeight` is not their node's tip — it is identical to
`lastFound`, the last block the pool won. Since a pool finds blocks in proportion to
its share of the network, the gap measures pool size, not health: an early version of
this code compared the two and marked a perfectly healthy nine-miner pool as lagging
next to a hundred-miner one. No threshold is applied to the age of the last block for
the same reason. Green on a pool row means its API answered with valid stats.

Version spread is in there because it is a security metric on a MimbleWimble chain,
not trivia — after Litecoin's 2026 MWEB peg-out exploit roughly 70% of nodes were
still unpatched weeks later.

**Version spread is measured against the published release, not against the fleet.**
An earlier version compared each node to the highest version *seen*, which scores a
fleet that is uniformly one release behind as unanimous — the metric goes quiet
exactly when it matters. The released version is a committed constant in
`releases.py`, mirrored by hand from the developer documentation's `versions.js`, and
overridable with `RELEASED_NODE_VERSION`. Fetching it from the GitHub API at runtime
would make a page whose whole claim is "no external services" depend on one. A stale
constant degrades honestly: the board reports 0 of N on the new release until it is
bumped, which is what it would say on release day anyway. Only a version *strictly
older* than the release is marked — a relay answering a protocol newer than the
published number is ahead of it, not behind, and a marker that fires on a healthy
state teaches readers to ignore it.

## Incident log

A snapshot says what is true now; a reader arriving after an outage wants to know when
it started and whether it is over. Each condition — a target down, a confirmed fork, a
mainnet stall of 15 minutes without a block, a relay certificate inside 14 days — opens
**one** row when it starts and closes the same row when it ends, so every incident has a
duration and a feed reader shows it once. A condition must stay clear for a minute before
it closes, so a flapping host is one incident rather than a dozen. Open incidents are
reloaded at boot, so a restart during an outage does not duplicate it. Reorgs are
instants, logged with their depth: one and two blocks are `info` (orphan races every PoW
chain has), three or more are `warn`. A floonet stall is `info`; a test network is mined
when someone is testing.

**One line per source per day.** Settling merges a flap inside a minute; it does not help
a pool that drops out for three minutes every hour, or a test network that orphans a block
every few hours. So a repeat of the same kind for the same host — or, for chain-level
events, the same chain — within 24 hours of that entry's *first* occurrence is folded into
it: the entry counts it ("7 outages in 24 h · 14m 05s down in total · latest 12:13 UTC"),
reads as ongoing again while the repeat lasts, and takes the worse severity and the deeper
reorg. Anchoring on the first occurrence means two entries for one source always start a
day apart, so no rolling 24 hours shows more than one. Every occurrence is still stored, in
`event_occurrences`, with its own start, end and detail; the count is a summary, not a
deletion. A database from before this change is compacted into the same shape once, at
boot, keeping the earliest id of each folded group so feed entries stay stable — back the
file up first, because that step is not undone by any migration.

Shown on `/history`, published at `/api/v1/events.json` and `/feed.atom`. Never pruned,
for the same reason failures are not.

## Locations

Two sources, both free, both offline after the lookup.

**RDAP** (`rdap.org`, no key, no account) gives the hosting provider and often the
datacentre code, from the registries themselves. It is refreshed weekly, two targets
per sweep so the bootstrap service does not answer 429.

**Country is low-confidence and labelled as such.** RDAP records carry it
inconsistently — Hetzner allocations name the datacentre, Vultr blocks carry no
country at all — and proxied hosts report the proxy. A `country` in `targets.toml` is
stored as an override and is never overwritten by a lookup. That is load-bearing: the
reference instance is a London VPS whose RDAP record says India, because the
allocation is registered to the provider's NOC.

Flags are inline SVG, self-hosted, no font dependency. Regional-indicator flag emoji
do not render at all in Chrome on Windows and fall back to boxes on minimal font
sets. A known country with no drawing gets a two-letter chip; an unknown country gets
the word `unknown`, occupying the same slot so the column never looks broken.

**Provider concentration is on the history page, not the board.** It is a real and
alarming fact — at the time of writing every public Epic node and relay is on two
companies — but it is a property of the fleet rather than an answer to "can I transact
right now", and an earlier version put both the vendor name on every row and a
provider card in the summary strip. That spent the most valuable space on the page on
the fact fewest readers arrived for. It now has a section of its own under
`/history`, where someone is already reading about the fleet, and the summary slot it
vacated states the released node version once instead.

## API

Read-only routes send `access-control-allow-origin: *`, so a browser can consume them
directly. CORS is set per-route rather than globally, so the submit endpoint is not
open to cross-origin POSTs.

| Route | |
| --- | --- |
| `GET /api/v1/status.json` | Everything. Carries an `ETag`; send `If-None-Match` and a poller costs nothing when nothing changed. |
| `GET /api/v1/nodes.json?healthy=true` | Bare endpoint list, for a wallet or a failover config. |
| `GET /api/v1/epicbox.json?healthy=true` | Same, for relays. |
| `GET /api/v1/pools.json?healthy=true` | Same, for mining pools. |
| `GET /api/v1/health` | Liveness of **this service**, not of the network. 503 when the snapshot is stale. |
| `POST /api/v1/submit` | `kind` (`node`, `epicbox` or `pool`), `host`, `operator`. |
| `GET /api/v1/events.json?min=warn` | The incident log. One entry per source per 24 h; `occurrences` counts repeats, `occurrence_times` lists up to 50, `ended_at` is null while the latest lasts. |
| `GET /feed.atom?chain=floonet&min=info` | The same log as Atom. Defaults to `warn`, which leaves out one-block reorgs. |
| `GET /badge/{id}.svg` | Embeddable badge: state and 30-day uptime. Drawn here, not by shields.io. |
| `GET /api` | Reference. The OpenAPI document is `/api/openapi.json`. |

Per-target fields follow [grin.fail](https://grin.fail/nodes.json)'s shape where they
overlap, since that is already the de-facto schema in this ecosystem. Two are borrowed
from [cosmos.directory](https://cosmos.directory) instead: `last_error`, so an
operator can diagnose their own endpoint without contacting anyone, and `operator`, so
credit is attributed.

```sh
curl -s https://status.btlabs.uk/api/v1/status.json | jq '.network'
curl -s 'https://status.btlabs.uk/api/v1/nodes.json?healthy=true' | jq -r '.nodes[]'
```

`/api/v1/health` returning 503 means this monitor is not working. It is deliberately
distinguishable from the network being unhealthy — point your own alerting at it, not
at `/`.

## Submissions

Open `POST`, following monero.fail and grin.fail, with automated checks first and a
human decision last. Nothing reaches the board without an operator approving it in
`/admin`: publishing a stranger's host to every consumer of the API is a decision, and
the checks exist so the reviewer is reading evidence rather than a claim.

```sh
curl -X POST https://status.btlabs.uk/api/v1/submit \
  -d kind=node -d host=node.example.org:3413 -d operator="Example Pool"
```

What happens:

1. The host is parsed and normalised; duplicates are rejected against slug, display
   host and endpoint.
2. It must resolve to a public address. Rejection happens **before** anything is
   stored or contacted.
3. It lands in a `submissions` table. The main poller never touches it — so a
   submission cannot make the sweep fan out to an attacker-chosen host.
4. A separate validator probes it three times, 60 seconds apart. For a node, the
   chain is **detected** from the tip and compared to the fleet; a submitter's claim
   about which network they serve is not evidence. For a relay, the handshake must
   yield a `Challenge`.
5. On three passes it is marked `verified` and waits in the review queue at `/admin`.
   Approving it creates the target; rejecting it keeps the record, so the same host
   cannot simply be resubmitted.
6. A submitted target that has never once succeeded and has failed 500 consecutive
   checks deletes itself. Seeds never do.

**Epicbox hostnames may contain only letters, digits and dots.** A hyphen or
underscore is rejected, and that is not pedantry: a hyphenated relay completes the
WebSocket handshake perfectly and would show green, while no wallet can parse an
address on it, so no transaction could ever complete. Listing it would publish a
permanently broken endpoint as healthy.

What is stored about a submitter: a salted hash of their IP, used only to rate limit.
The salt is generated at process start and never written down, so the hashes cannot be
reversed or linked across restarts even by the instance operator.

## Security

Read this before exposing an instance.

**The submit endpoint is unauthenticated and turns a request into outbound
connections to a host the requester chose.** That is a server-side request forgery
primitive by construction. Three separate protections, because each alone has a hole:

1. The name is resolved here and the target is refused if **any** returned address is
   non-public — private, loopback, link-local, multicast, reserved, carrier-grade NAT
   (which includes Tailscale space). Checking only the first address is defeated by a
   name resolving to one public and one private address.
2. The connection goes to the address that was validated, with the hostname carried
   only as `Host` and TLS SNI. Re-resolving at connect time reopens a DNS-rebinding
   window between check and request.
3. Redirects are never followed. A 302 to `http://169.254.169.254/` is the oldest
   trick in this category and a liveness probe has no use for one.

`ALLOW_PRIVATE_TARGETS=true` disables all of that. It exists for tests and local
development. On a reachable instance it turns the form into a port scanner aimed at
your own network.

**Bind loopback and put a reverse proxy in front.** The rate limit trusts
`x-forwarded-for`, which is only trustworthy when the service cannot be reached
directly. If you must bind publicly, set `SUBMISSIONS_ENABLED=false`.

The application sets its own CSP, `referrer-policy: no-referrer` and
`x-content-type-options`, so a self-hoster behind any proxy gets them. Templates are
autoescaped: hostnames and operator names come from the public form.

`connect-src` is `'self'` on every route except the board, where it also names the
origins of the hosts currently listed. That is what allows the expanded row's **Query
from here** button to measure a node from the reader's own browser instead of from the
prober. It is opt-in per host and per press — nothing is contacted on page load — and the
list shrinks by itself when a target is removed. A host whose API sends no
`access-control-allow-origin` is reported as unreachable from the browser, which is what
it is.

## Self-hosting behind nginx

Files in `ops/` are the source of truth and carry install commands in their headers.

```sh
# 1. Dependencies and database
uv sync
uv run epic-status init-db

# 2. Service — reads its port, database path and prober id from the unit
sudo install -o root -g root -m 0644 ops/systemd/epic-status.service \
  /etc/systemd/system/epic-status.service
sudo systemctl daemon-reload && sudo systemctl enable --now epic-status
systemctl status epic-status

# 3. A port-80-only bootstrap vhost, so the ACME challenge is reachable.
#    This step is not optional and not obvious: the full vhost below names
#    certificate files that do not exist yet, and nginx fails closed on a missing
#    ssl_certificate — so the cert cannot be issued until something serves port 80
#    for this name, and the vhost that does that cannot load until the cert exists.
sudo tee /etc/nginx/sites-available/epic-status >/dev/null <<'BOOTSTRAP'
server {
    listen 80;
    listen [::]:80;
    server_name status.example.org;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://$host$request_uri; }
}
BOOTSTRAP
sudo ln -sfn /etc/nginx/sites-available/epic-status /etc/nginx/sites-enabled/epic-status
sudo nginx -t && sudo systemctl reload nginx

# 4. Certificate. DNS must already point here.
sudo certbot certonly --webroot -w /var/www/html -d status.example.org

# 5. The real vhost. Zones first — one naming an undeclared zone fails nginx -t.
sudo install -o root -g root -m 0644 ops/nginx/status-ratelimit.conf \
  /etc/nginx/conf.d/status-ratelimit.conf
sudo install -o root -g root -m 0644 ops/nginx/status.btlabs.uk.conf \
  /etc/nginx/sites-available/epic-status
sudo nginx -t && sudo systemctl reload nginx   # read the -t output
```

Edit `server_name`, the certificate paths and the port in the vhost. Four things in
it are not incidental:

- `listen 443 ssl http2` as a **listen flag**. On nginx 1.24 the `http2 on;`
  directive is a hard config error.
- The port-80 ACME location stays on plain HTTP, so a renewal never depends on the
  certificate it is renewing.
- `proxy_intercept_errors on` with a branded `@down` page. For a status page a bare
  nginx 502 is the worst possible failure mode — the one thing it must never do is
  fail in a way that looks like the network failed. `/static/` deliberately does
  *not* intercept, because an HTML error body served as a stylesheet is worse than
  a 502.
- `limit_req_status` and `limit_conn_status` are **not** set in
  `status-ratelimit.conf`. They are http-context directives, and if any other file
  in `conf.d/` already sets them a second declaration is `directive is duplicate` —
  a hard error that refuses the reload. Check with
  `grep -rn limit_req_status /etc/nginx/conf.d/` before adding them.

Rate limits are declared **per location, never at server level**: neither `limit_req`
nor `limit_conn` accepts `off`, so a server-level limit cannot be lifted where it must
not apply.

## Operations

```sh
uv run epic-status targets            # what the committed registry says
uv run epic-status check <host>       # probe one target now
uv run epic-status prune --days 7     # drop old successes, then VACUUM
journalctl -u epic-status -f
```

**Back up `data/status.db`.** Uptime history, the incident log and `last_ok_at` cannot be reconstructed
from anything — no node reports when it was last up. Everything else in the database
is derived and rebuilt at boot. SQLite runs in WAL mode; `sqlite3 status.db ".backup
out.db"` is safe against a running service.

Successful checks are pruned after 7 days; **failures are kept indefinitely.** Nobody
ever needs to prove a node was up, and everybody eventually needs to prove it was
down. Uptime beyond 7 days comes from hourly rollups, which are not pruned.

Steady-state sweep cost is roughly `HTTP_TIMEOUT_S` when any node is unreachable,
since the sweep waits for the slowest timeout. Version, tip-age, P2P, certificate and
RDAP refreshes run as background tasks and do not extend it — an earlier version
awaited them and a cold start against four dead seeds took twenty seconds.

Resident memory is about 70 MB. The unit sets `MemoryHigh=192M` / `MemoryMax=256M`
and `OOMScoreAdjust=600`, so on a small box this process loses to anything that
matters more.

## Development

```sh
uv sync --extra dev
uv run pytest -q
uv run mypy src/epic_status
```

`mypy --strict`. The test suite does not touch the network: node probes are mocked
with `respx` against a recorded mainnet response, and the Epicbox test runs a real
WebSocket server on loopback because the relay's contract is that it sends a frame
before the client writes anything, and only a real socket demonstrates that.

The address-guard tests in `tests/test_net.py` are the ones to keep green. They are
the reason the submit form is not a proxy.

Layout:

```
src/epic_status/
  models.py      typed boundary — probe results, targets, events, snapshot
  config.py      settings, and the committed seed registry
  db.py          SQLite; checks, rollups and events are the irreplaceable state
  net.py         address validation, pinned-IP connections, cert expiry
  probes/        node.py (get_tip, get_version, get_header, CORS preflight)
                 epicbox.py (Challenge) · pool.py (per-pool stats adapters)
  geo.py         RDAP provider and location
  releases.py    the published node/wallet/protocol versions, a committed constant
  score.py       three states, fork detection, the 0–100 score
  chain.py       recent canonical headers, reorg detection, the chain panel
  events.py      the incident log: open, settle, close
  poller.py      the sweep loop and the in-memory snapshot
  submit.py      submission validation
  vantage.py     remote probers: signing, ingest, and the push loop
  api.py         public routes and JSON serialisation
  admin_routes.py  the /admin dashboard's routes
  admin.py       passwords, sessions, CSRF and login rate limiting
  web.py         response helpers shared by both route modules: CSP, CORS, JSON
  schemas.py     the published OpenAPI response shapes
  render.py      Jinja environment and filters
  badges.py      embeddable SVG badges
  flags.py · icons.py   inline SVG flags and icons
  templates/ static/
ops/             systemd unit and nginx vhost, with install commands
config/          targets.toml
```

## Deliberate non-goals

- **No push alerting.** The incident log is published as Atom at `/feed.atom`, which a
  feed reader or a feed-to-chat bot can turn into notifications; this service sends
  nothing itself. For Discord or Telegram notifications with escalation, run
  [Gatus](https://github.com/TwiN/gatus) alongside and push to its external-endpoints
  API. Reimplementing that here would be worse than it.
- **Floonet is a second board, not a filter.** `/?chain=floonet` is scored against
  floonet's own tip and never mixed into mainnet's numbers, lists or score. Public
  submissions are mainnet-only; floonet hosts belong in the committed registry.
- **Remote probers are evidence, not votes.** See below: a second vantage point is shown
  beside each verdict and never averaged into it.

## Second vantage point

`prober_id` has been on every stored check since the first schema, so a second prober is
additive rather than a migration. Another machine runs `epic-status push`, probes the
hub's nodes and relays with the same code every 30 seconds, and posts signed batches to
`POST /api/v1/probes`.

```sh
# on the hub: generate a key, add the printed line to the unit's environment, restart
uv run epic-status prober-key btlabs-fra

# on the remote
EPIC_STATUS_PUSH_SECRET=… uv run epic-status push --hub https://status.btlabs.uk --id btlabs-fra
```

- **Authentication** is an HMAC-SHA256 over the prober id, a timestamp and the exact body,
  with a per-prober secret. The hub refuses a timestamp more than five minutes off or not
  newer than the last one accepted, so a captured request cannot be replayed.
- **The pusher needs no target config.** It reads the list from the hub's public
  `status.json` and applies the same address checks before connecting anywhere.
- **Remote checks never change a row's state, failure count or uptime.** Those are the
  hub's own. They appear in the expanded row as "from btlabs-fra: answered · 41 ms" and in
  the API as `vantages`. "Down from London, fine from Frankfurt" is the answer a second
  vantage point exists to give, and averaging would erase it.
- Uptime and the recent-checks strip are per prober. Changing `PROBER_ID` starts a new
  series rather than relabelling the old one, because it is a different vantage point.

## Review dashboard

`/admin`, registered only when `ADMIN_PASSWORD_HASH` is set; otherwise it is a 404 rather
than a login form. Approve or reject submissions, edit operator, label, notes and location
per target, and disable a host without deleting its history. An edit made here is pinned
against `config/targets.toml`, so the next restart does not revert it. scrypt from the
standard library, in-memory sessions, CSRF on every mutation, and failed logins
rate-limited per address; `src/epic_status/admin.py` explains each choice.

## Prior art

[grin.fail](https://grin.fail) is the closest analogue and its JSON schema is followed
closely; it is not open source. [monero.fail](https://github.com/lalanza808/monero.fail)
supplied the submission model, the self-deleting-dead-node rule and the
keep-failures-forever retention policy. [cosmos.directory](https://github.com/eco-stake/cosmos-directory)
supplied `last_error` and `provider`. [j01tz/grin-health](https://github.com/j01tz/grin-health)
is where the idea of a single chain-safety number comes from. Atlassian Statuspage is
where the component groups and the 90-day bar come from.

## Licence

MIT. See `LICENSE`.

Montserrat is bundled under the SIL Open Font License 1.1 and served from this host
rather than a font CDN, so no reader's address is disclosed to a third party for the
sake of a typeface.
