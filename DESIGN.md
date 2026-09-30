# Design

<!-- impeccable:design-schema 1 -->

The visual system for status.btlabs.uk. Product truth lives in `PRODUCT.md`; this file is
only about how the thing looks and why.

## The situation this is designed for

Everyone who opens this page is already slightly alarmed. They are a third-party operator
checking whether their own host is reachable from somewhere that is not their network, a
developer choosing an endpoint to point a wallet at, or a community member who noticed
something looked wrong. Nobody browses a status page.

That produces one governing rule, and most decisions below follow from it:

> **Calm when fine, unmistakable when not.** A healthy page must be quiet enough that a
> single fault is the only thing on screen competing for attention.

The board failed this before the redesign. Green was spent on every dot, every state word
and every history bar, so the all-fine page was the most colourful thing on the site and a
single dead node had to compete with forty green ticks to be noticed. Colour had one job
and did it everywhere.

## Composition

Three directions were considered and two were adopted, split by surface.

**The first screen is editorial.** The service already computes a judgement — can a reader
transact right now — and used to render it as a bold 16px line inside a tinted callout.
That judgement is now the page's hero at display size, as a sentence with one accented
word: *The chain is **healthy**.* Below it, the specific fact; below that, the consequence
for the reader, and only when there is one. There is no box around it. A border drawn
around the most important sentence on a page is the interface apologising for it.

**Desktop tables are an operator console.** One line per host, dense enough that three
groups fit a laptop screen without scrolling, every column on a shared track list, latency
drawn as a comparable bar beside its number, and sortable headers. A reader comparing eight
hosts should not have to read eight numbers to find the slow one.

**Mobile rows are an instrument.** Hairlines and type, no card per host, no surface tint. A
rounded bordered panel around every row spends a phone's entire width on a container that
says nothing; one rule between hosts says the same thing in one pixel.

Direction C was rejected for mobile specifically: density is the hardest thing to keep
honest on a phone, and the phone is the case this page is actually read in.

## Colour

| Token | Job |
| --- | --- |
| `--rest-*` | Healthy. Desaturated grey-green. Dots, state words, history bars. |
| `--ok-*` | Reserved for the single accented word in the verdict. |
| `--warn-*` | Degraded, a certificate inside 14 days, a version behind the release, a slow latency bar. |
| `--danger-*` | Down, failed checks, an unreachable host. |
| `--primary` / `--mark` | Gold. Brand and focus, never state. |

Healthy is deliberately dull. Saturated hues are a budget, and spending them on the
common case leaves nothing for the exceptional one.

**State is never carried by colour alone.** Every light has a word beside it in the visible
text and in its `aria-label`; an out-of-date version carries a dotted underline as well as
a hue. A board read under stress has to survive colour-vision deficiency and a monochrome
screenshot pasted into a chat.

## Type

- **Display:** Montserrat, self-hosted, OFL 1.1. **This is the known weak point of the
  system** — it is one of the most-served faces on the web and the geometric sans every
  model reaches for. It is anonymous rather than bad, and replacing it is the one
  outstanding design decision. Self-hosting is binding whatever replaces it: no reader's
  address is disclosed to a third party for a typeface.
- **UI:** system stack. Nothing is gained by shipping a second webfont for body copy.
- **Mono:** JetBrains Mono ahead of a system fallback, for every measurement — heights,
  hashes, latencies, versions, uptimes. Unambiguous zero and distinguishable `l/1/I` matter
  when most of the page is numbers. Monospace here is data, not costume.
- **Labels are sentence case.** They used to be uppercase and letterspaced, twenty-seven of
  them on one screen, which became a texture the eye slid off and spent the one treatment
  that could have marked something as important.
- Tabular numerals everywhere a column of figures appears, so a changing digit does not
  shift the column.

## Layout

- Wide tables are one CSS grid per group, declared on the `<ul>`, with every row and the
  header on `grid-template-columns: subgrid`. Alignment is structural, not coincidental.
  Before this each `.row` was its own grid computing its own `auto` widths, so no column
  ever aligned across rows — measured, not assumed.
- The three groups are not equal weight. Public nodes is primary; relays and pools are
  secondary, with smaller dimmer headings. A forked chain breaks everything, a dead relay
  breaks one transport, a dead pool costs its own miners — and the health score already
  excludes relays and pools for exactly that reason.
- Facts are weighted, not tiled. Chain tip is set large and first; node, relay and pool
  counts are supporting figures beside it. Five equal cells was the hero-metric template
  and left the reader to work out which number mattered.

## Motion

One authored moment: a slow pulse on the healthy traffic light, so a live page is
distinguishable from a screenshot or a frozen tab. Everything else is a colour or width
transition at `--dur`. `prefers-reduced-motion` removes all of it.

## Constraints that shape all of the above

- **No build step, no client framework, no CDN.** Hand-written CSS, vanilla JS, every
  asset local.
- **The page must be correct at serve time with JavaScript blocked.** JS ticks timestamps,
  patches numbers from the API, restores the theme, sorts columns and runs the opt-in
  connection check. All are enhancements; none is required for the board to be right.
- **No inline styles.** The CSP has `style-src 'self'` with no `unsafe-inline`, so a
  `style=` attribute is silently dropped. Anything dynamic ships as a class — which is why
  latency bar widths are quantised to twenty 5% steps.
- **No rare Unicode as iconography.** Flags and icons are inline SVG. Regional-indicator
  emoji do not render at all in Chrome on Windows and fall back to boxes on minimal font
  sets, and a sort arrow is drawn with borders rather than a glyph for the same reason.
- Both themes are first-class; theme is a persisted reader choice, not a canonical
  rendering.

## Known open items

1. **The display face.** Montserrat should be replaced by something chosen, self-hosted,
   with a usable licence. This is the last remaining finding from the deterministic
   detector and the single largest thing still making the page look generic.
2. Latency bars appear on desktop only. On a phone the number stands alone, which is
   acceptable but not equivalent.
