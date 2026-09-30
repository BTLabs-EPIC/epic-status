# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Three co-primary audiences, all technical. The ordering between them is deliberately
not narrowed — no one of them wins a layout tradeoff by default:

- **Third-party node, relay and pool operators.** Come to diagnose their own host:
  is my endpoint reachable from somewhere that is not my own network, is my tip
  lagging, is my certificate about to expire, what exactly did the probe see. The
  `last_error` field exists so they can answer that without contacting anyone.
- **Developers.** Consume the board and the JSON API while building wallets, pool
  software and tooling: pick a healthy endpoint, wire a failover list, poll
  `status.json` with an `ETag`. They read the page and the API as one product.
- **Community members.** Come to answer "is the network fine right now", usually
  because something already looks wrong to them.

All three arrive in the moment something is suspected broken. That is the design
situation: a reader who is already slightly alarmed, scanning for whether the problem
is the chain, one host, or their own setup.

## Product Purpose

Health and uptime monitoring for Epic Cash public nodes, Epicbox relays and mining
pools, on mainnet and floonet. One process — asyncio poller, SQLite, server-rendered board — reporting
reachability, latency, tip height and hash, tip lag against the highest tip seen,
fork detection, version spread, certificate expiry and hosting location, plus a
read-only JSON API over the same data.

Success is being the page an operator or dev trusts during an incident: correct at
the moment it was served, explicit about what it cannot know, and never failing in a
way that looks like the network failed.

## Positioning

Independent, not official. Not endorsed by the Epic Cash project; the naming and
config anticipate becoming the canonical instance (`SITE_NAME` is "Epic Cash Status",
and `config.py` is written so a move to `status.epiccash.com` is a DNS record plus an
env var) without claiming that status today.

What a neighboring status page could not truthfully copy is the honesty model:

- **Three states, not two.** `degraded` is a real bucket for up-but-not-usable — a
  401 foreign API, a node 5,000 blocks behind, a probe that failed from our host and
  therefore proves nothing about theirs.
- **Forks are confirmed, not announced.** A tip-hash conflict must persist three
  consecutive sweeps before it is called a fork; below that it is a reorg in
  progress. Announcing a fork on every orphan would cause the panic the page exists
  to detect.
- **The score covers nodes only**, because averaging failure domains with different
  blast radii produces a number that means nothing in any of them.
- **It publishes what it cannot measure.** Peer counts and sync status need an
  `api_secret` and are absent rather than faked. Country is labelled low-confidence
  because RDAP is inconsistent. Latency is stated per vantage point, and a remote
  prober's view is shown beside the verdict rather than averaged into it.
- **It refuses to become a weapon.** No HTTP GET against a relay, no `Subscribe` or
  `PostSlate`, no probing from the reader's browser, and a submit path built as three
  independent SSRF guards.

## Operating Context

Read during or just before an incident, on whatever device is to hand. Consumed three
ways over the same data: the HTML board, the JSON API, and `GET /api/v1/health` as an
alerting target for this service specifically (distinguishable from the network being
unhealthy).

Runs as a systemd unit behind nginx on one small VPS alongside a live mainnet node.
The committed registry (`config/targets.toml`) makes adding a community server a
reviewable commit; public submissions go to SQLite and are promoted only after three
independent probe passes 60 seconds apart.

## Capabilities and Constraints

Confirmed and load-bearing. Future work preserves all of these:

- **No build step, no client framework, no external services.** Server-rendered
  Jinja, hand-written CSS and vanilla JS (about 1,100 lines in `app.js`, 330 in the
  admin-only `admin.js`).
- **No CDNs of any kind.** Montserrat is bundled and served from this host so no
  reader's address is disclosed to a third party for a typeface. The application sets
  its own CSP, `referrer-policy: no-referrer` and `x-content-type-options`, so a
  self-hoster behind any proxy gets them. Any new asset must be local.
- **The board must be correct at serve time with JavaScript blocked or broken.** JS
  restores the theme choice, ticks timestamps, patches numbers from the API every 5s,
  sorts columns, and runs the opt-in "Check connection" probe. None of it is required. Every value has a correct initial
  state in the HTML. The day the page matters most is the worst day to discover a
  client-side render is broken.
- **Nothing in the client contacts a node or a relay on its own.** Reader-side probing
  on page load would put their address in every operator's logs because they opened a
  status page. The one exception is the "Check connection" button: opt-in, per host,
  per press.
- **Light and dark are both first-class**, persisted to `localStorage`, applied via
  `data-theme` on the root element.
- **Inline SVG for iconography and flags.** Regional-indicator flag emoji do not
  render at all in Chrome on Windows and fall back to boxes on minimal font sets. A
  known country with no drawing gets a two-letter chip; an unknown one gets the word
  `unknown` in the same slot, so the column never looks broken.
- **~70 MB resident under `MemoryHigh=192M` / `MemoryMax=256M`**, `OOMScoreAdjust=600`.
  This process loses to anything that matters more on the box.
- **No push alerting.** The incident log is published as Atom; nothing is sent. Floonet
  is a separate board, never mixed into mainnet's numbers. Remote probers push signed
  evidence and never change a verdict.
- Templates are autoescaped: hostnames and operator names come from a public form.

## Brand Commitments

Deliberately thin, by the user's explicit instruction: **UI and design quality is the
priority, branding and marketing are not.** Do not invent a brand programme.

- Name on the page is Epic-forward: "Epic Cash Status" via `SITE_NAME`.
- btlabs is credited in the footer only.
- Montserrat is the incumbent display face, bundled under OFL 1.1. Self-hosting is
  binding; the choice of face is incumbent, not declared binding.
- Voice: plain, technical, unhedged. The README is the reference register — it states
  limits and reasons rather than reassuring.

## Evidence on Hand

Real, and usable as content:

- A live instance at <https://status.btlabs.uk> with real mainnet data.
- The committed target registry, real operator names, real RDAP provider and
  datacentre data. Provider concentration is a genuine finding worth surfacing: at
  time of writing every public Epic node and relay sits on two companies.
- A real API with an OpenAPI document at `/api/docs`, and working `curl` examples.
- Version-spread data, which is a security metric on a MimbleWimble chain — after
  Litecoin's 2026 MWEB peg-out exploit roughly 70% of nodes were still unpatched
  weeks later.

Absent, and not to be fabricated: no endorsement from the Epic Cash project, no
testimonials, no user or traffic numbers, no uptime SLA, no second prober region, no
peer counts or sync status.

## Product Principles

1. **Correct beats live.** Served-complete and honest outranks continuously updating.
   Never fail in a way that looks like the network failed.
2. **Publish the limits.** What cannot be measured is stated, not omitted or
   approximated. Confidence is labelled where it is low.
3. **Built for the alarmed reader.** Everything is scanned under mild stress by
   someone deciding whether the problem is the chain, one host, or themselves.
4. **Design quality over brand.** It must look good, feel great, and carry no AI
   slop. Effort goes into hierarchy, legibility and craft — not into marketing
   surface.
5. **Never become an amplifier.** No action on a reader's behalf, and no probe that
   costs a third party anything.

## Accessibility & Inclusion

No formal standard was mandated. Two product-specific needs are established:

- Glyph robustness is a real requirement, not a preference — the flag-emoji failure
  on Windows Chrome and minimal font sets is why iconography is inline SVG. Anything
  depending on a rare Unicode glyph is fragile here.
- Both colour schemes must be legible, since theme is a persisted reader choice
  rather than a single canonical rendering.

Status state must never be carried by colour alone: red/amber/green on a page read by
someone already alarmed has to survive colour-vision deficiency and monochrome
rendering. (Inferred from the audience and the three-state model, not stated by the
user — treat as the working floor until confirmed.)
