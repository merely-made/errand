# Smolweb Home Decision — spec-accurate to smolweb, enrichment to genet/cambium

**Date**: 2026-08-03
**Status**: decided (Mark, 2026-08-03). Records the split rule; extraction work
is not scheduled here.

## The rule

Spec-accurate implementations of smolweb protocols and their document grammars
belong in the [smolweb workspace](https://github.com/mark-ik/smolweb) as
general-use crates. The implementation-specific parts stay with us: what we do
to enrich the smolweb browsing experience, how we implement and render the
parsed content, and anything non-spec lives in genet or moves to the cambium
view layer.

This extends the movement already made on 2026-07-23, when `misfin`,
`spartan-protocol`, `nex-protocol`, and `guppy-protocol` moved to the smolweb
workspace and genet's errand went back to consuming them from crates.io. The
reasoning recorded then ("their names belong to the protocols' communities, not
to the engine that speaks them") is the same rule, stated for wire crates; this
decision applies it to everything spec-shaped still inside genet/components.

## Current state (verified 2026-08-03)

- **smolweb workspace**: misfin, spartan-protocol, nex-protocol,
  guppy-protocol. Wire layer only, per its README.
- **genet/components/errand**: the scheme-routed client integration. Delegates
  spartan/nex/guppy/misfin to the smolweb crates, but still carries in-tree
  spec implementations of gemini (gemini.rs, tls.rs, tofu.rs, titan.rs),
  gopher, and finger, plus the `errand::parse` grammars (gemtext, gopher
  menus, nex listings, RSS/Atom feed).
- **genet/components/nematic**: the AST-to-Block lowerings (capture and card
  lane). Implementation-specific by design.
- **genet/components/cambium/cambium-nematic**: the native smolweb views
  (gemtext/gopher/feed views, theming, per-site palettes). This is the
  "cambium-views" home.
- **genet/components/smolweb-views**: an empty husk; its contents became
  cambium-nematic. Delete it.

## What the rule sorts where

Extraction candidates (spec-accurate, general-use):

- Gemini transport with TLS/TOFU and titan upload, as a gemini protocol crate.
- Gopher and finger transports.
- The parse grammars: gemtext lines, gophermap items, nex listings. These are
  the protocols' document specs, so they follow the wire crates out. The
  earlier plans folded parse into errand for lockstep reasons; lockstep now
  argues the other way, since grammar and wire for one protocol belong to one
  spec crate, and errand composes them.

Stays in genet or cambium (implementation-specific):

- errand itself: scheme routing, the unified `fetch`, Status/MIME
  normalization, trust descriptors. Composition choices, not spec.
- nematic's lowerings, feed sniffing, JSON Feed handling, knot capture.
- cambium-nematic: all rendering, theming, focus/navigation affordances,
  regime-B presentation work (gopher grids, type-7 search inputs).

Open call, recorded rather than decided: RSS/Atom feed parsing is spec-accurate
but not a smolweb protocol, and it carries the quick-xml dep. It stays in
errand until an external audience or a second consumer argues for its own
crate.

## Effect on the existing plans

- Native smolweb rendering plan (`genet/design_docs/nematic_docs/implementation_strategy/2026-06-27_native_smolweb_rendering_plan.md`):
  its §5 crate-home diagram ("parse folds into errand", errand as a sibling
  repo) predates both the genet adoption and this decision. The two-family
  model and the render architecture stand; the crate homes read through this
  note now.
- Smolweb fidelity plan (`genet/design_docs/nematic_docs/implementation_strategy/2026-07-01_smolweb_fidelity_plan.md`):
  WS1's AST enrichment lands wherever the grammar lives at the time; if a
  grammar has moved to a smolweb crate, the enrichment goes there. WS2 (trust)
  and WS3 (regime B) are implementation-side and unaffected.
- Both plans name pelt and meerkat as consumers. Meerkat is deleted; the app
  is Turnstone. Consumer references read as Turnstone/mere hosts.

## Findings from the first extraction (2026-08-03)

Four facts the `gopher-protocol` move established, each of which changes the
plan above.

**1. The publish gate is the real constraint.** errand is itself a published
crate (`publish = true`, 0.1.3), and a published crate may not carry git
dependencies. So errand cannot consume an extracted crate until that crate is
on crates.io. Every extraction is therefore a three-step chain with an
irreversible middle: stage the crate in the smolweb workspace, **publish it**,
then re-point errand and bump it. Staging is free and reversible; the publish
is Mark's call and gates everything downstream of it.

**2. `gemtext` is taken on crates.io** (v0.2.1, "A gemini client and server for
Rust", last published October 2020), so the shared grammar cannot have the
obvious name. It does not need one: gemtext and gemini are defined by the same
spec document, so the grammar bundles into `gemini-protocol` behind a
dependency-free feature, and consumers that only parse bodies (spartan, guppy,
scroll, misfin) take it with `default-features = false`. `gemini-protocol` and
`gopher-protocol` are both available.

**3. The nex grammar is duplicated, not missing.** `nex-protocol` already ships
a listing parser (`listing.rs`, `parse_listing` into `ListingLine`), and errand
independently implements the same grammar in `parse/nex.rs` with directory
detection and base-URL resolution on top. That move is a de-duplication:
upstream errand's extras into `nex-protocol` and delete the copy. Decide which
implementation is the survivor by reading both, rather than assuming errand's
is richer because it is longer.

**4. Feature-gate the transport, not the grammar.** Verified on gopher: with
`default-features = false` the dependency tree is the crate alone, zero
dependencies, while the client pulls tokio and url. This matters because the
consumers of these grammars are *renderers* (cambium-nematic parses gophermaps
to draw them) that have no business pulling an async runtime. Every extracted
crate should follow this shape.

**Blast radius is small and shieldable.** Only genet consumes `errand::parse`:
four nematic engines (`gemtext.rs`, `gopher.rs`, `nex.rs`, `feed.rs`) and
`cambium-nematic/src/views.rs`. mere and turnstone reference it nowhere. errand
can re-export each extracted grammar under its existing `errand::parse::*` path,
so those five files need no change at all and the moves stay invisible
downstream.

## Sequencing

Extraction is deliberate, not urgent, and now has a fixed shape per protocol:
stage in the smolweb workspace (free, reversible), publish (Mark), re-point
errand behind a re-export (invisible downstream), bump errand.

Do it protocol-by-protocol when a lane is next touched, not as a sweep. One
ordering correction: doing a move **before** the fidelity plan's WS1 touches a
grammar is better than after, because WS1's enrichment then lands in the
grammar's final home instead of needing a second move. WS1 has not started.

## Progress

- **2026-08-03**: Decision recorded. `gopher-protocol` staged in the smolweb
  workspace as the first move and the template for the rest: `menu` (the RFC
  1436 parser, dependency-free, always compiled) plus `client` (TCP fetch,
  default feature), with its own `Response`/`ClientError` mapped by errand the
  way `spartan-protocol` already is. 11 tests plus doctests green, 7 of them
  under `--no-default-features` with an empty dependency tree; the smolweb
  workspace is green. Not published, so errand still carries its own copy and
  nothing downstream has changed yet.
- **2026-08-03 (later)**: **The first two moves are complete, end to end.**
  Mark authorised publishing and asked that the successors be supported in the
  same crates, so both went out carrying them:
  - **`gopher-protocol` 0.1.0**, published, now with **Gopher+**: the
    fifth-field marker, the response header (`+<count>`, `+-1`, `+-2`, `--1`),
    attribute blocks, `+VIEWS` alternates, and `+ASK` forms. Gopher+ is a
    superset, so it is modelled as one: a plain RFC 1436 menu is simply a menu
    with no markers. Gopher-II is left unimplemented and said so.
  - **`finger-protocol` 0.1.0**, published, with **WebFinger** (RFC 7033)
    beside RFC 1288. WebFinger ships as request construction plus JRD parsing
    and *no HTTP client*: the GET belongs to the caller, which keeps the crate
    light and lets errand take the classic protocol alone.
  - **errand 0.2.0** consumes both. `gopher.rs`, `finger.rs`,
    `parse/gopher.rs` and `plain.rs` fell from roughly 500 lines to 89 of
    mapping. `parse::gopher` re-exports the grammar, so nematic and
    cambium-nematic needed **no edits**, which is the re-export shield working
    as designed.

  Two things worth keeping. The successor support was landed *before*
  publishing rather than after, because Gopher+ adds a field to `GopherItem`
  and shipping 0.1.0 without it would have meant breaking the API within the
  day. And the ordering rule above held: the grammar reached its final home
  before anything enriched it.

  **A silent bypass surfaced during the re-point.** `cambium-nematic` declared
  `errand = "0.1.3"` as a bare version rather than `workspace = true`, so it
  resolved to the *published* errand instead of this workspace's copy: local
  errand changes never reached those views, and its tests were quietly
  exercising crates.io. Fixed, and the lock now holds one errand instead of
  two. Worth a sweep for other bare-version declarations of workspace members.

  errand is not republished; genet builds it by path, so only an external
  consumer would need that.
- **2026-08-03 (third move)**: **`gemini-protocol` 0.1.0**, published, carrying
  gemini, the gemtext grammar, TOFU pinning, and titan. errand's `gemini.rs`,
  `tls.rs`, `tofu.rs`, `titan.rs` and `parse/gemtext.rs` left; the crate is
  down from 2786 lines to 1612. Downstream needed no edits again: the grammar
  re-exports under `errand::parse::gemtext` and the TOFU types under
  `errand::`, so the hosts that install a trust store still call
  `errand::set_trust_store(errand::InMemoryTofu::new())`.

  Two fidelity gains. Gemini's temporary (`4x`) and permanent (`5x`) failure
  are now **distinct** in the spec crate, since retrying one is reasonable and
  retrying the other is not; errand still flattens them to its cross-protocol
  `Failure`, but that flattening is now an explicit, tested mapping rather than
  a silent one, and the exact code survives on `raw_status`. An undefined
  status class is refused rather than passed along.

## The grouping rule (Mark, 2026-08-03)

Group associated protocols and formats in one crate; keep the architectural
boundary at *intent*, not at *artifact count*. Three shapes have come up, and
they resolve differently:

- **A successor that is a superset** lives in the same crate as its ancestor,
  because splitting them would make every consumer reassemble one protocol
  from two dependencies. Gopher and Gopher+ are one crate; a plain RFC 1436
  menu is simply a Gopher+ menu with no markers.
- **A format its protocol defines** lives with that protocol. Gemtext is not a
  format that happens to travel over gemini; it is the format gemini's spec
  defines, and titan is the write half of the same document space. One spec,
  one crate.
- **A successor that is a different protocol answering the same question**
  gets its own feature in the same crate. WebFinger is HTTP and JSON where
  finger is a line of text over TCP, so it ships beside finger but behind
  `webfinger`, and errand takes the crate without it.

  **Amended 2026-10-01.** The `webfinger` feature gains its first consumer.
  Mark ruled that mere's gazette port adopts it for the request URL and the
  JRD in both directions, replacing gazette's own blocking-`reqwest` parser.
  That parser was older than this crate, kept a link's `rel`, `type` and
  `href` only, and cannot compile for wasm32, while this feature can. The
  same ruling moves gazette's resource normalization upstream into this
  crate: a bare `user@host`, an `acct:` URI, or a URL with its origin and
  port, resolved to the request URL. That keeps all of the wire in the spec
  crate and leaves gazette its endpoint classification and contact intake.
  Unbuilt. The record and the comparison are in dramatis's
  `repos/dramatis/design_docs/2026-09-30_dramatis_tier_architecture.md`.

What makes the grouping safe is that **the cost is feature-gated, not
crate-gated**. Every grammar is dependency-free and always compiled; every
transport rides a feature. So `gemini-protocol` with
`default-features = false` is a zero-dependency gemtext parser, which matters
because **five other smolweb formats serve `text/gemini` bodies** (spartan,
guppy, scroll, misfin, titan) and none of them should pull a TLS stack to
read one. Verified per crate, not assumed: the dependency tree in that
configuration is the crate alone.

The corollary for our side: fifteen nematic engines is not fifteen crates.
Most of those fifteen are *lanes over shared grammars*, and the lane is ours
while the grammar is the spec's.

## Serving: already in scope, and no `smolnet` sibling (2026-08-04)

Mark asked whether serving capsules belongs in `smolweb` or in a sibling
`smolnet`. The workspace has already answered the first half: **four of its
seven crates ship a server and a CLI** (misfin, spartan-protocol,
nex-protocol, guppy-protocol), and the README's stated shape is "an embeddable
library plus, where it makes sense, a CLI". Serving is the wire layer spoken
in the other direction, so it was never out of scope.

**The three client-only crates are the anomaly, not the rule.**
`gopher-protocol`, `finger-protocol` and `gemini-protocol` are new, and they
are client-only for an accidental reason: they were extracted from errand,
which is a *client* integration, so only the client half existed to move.
That is a gap to close, not a boundary to defend.

**Do not create a `smolnet` sibling.** "Smolnet" is the community's name for
the *whole space* — the [Gemini FAQ](https://geminiprotocol.net/docs/faq-section-6.gmi)
and ArchiveTeam both use it as a synonym for the small internet, not as a
layer within it. Two sibling repos called `smolweb` and `smolnet` would be
indistinguishable to anyone outside this workspace, and a name nobody can
resolve from the outside is worse than no split.

### Terminology, since it varies by protocol

| Protocol | What a served collection is called |
|---|---|
| Gemini | **capsule** |
| Gopher | **gopherhole** (in gopherspace) |
| Spartan, nex, text, scroll | no established term; too young and too small |
| Misfin | **mailbox** |
| Finger | the served content is a **`.plan`** |

The Gemini FAQ puts it plainly: a capsule is "the same thing as a 'website' on
the web, or a 'gopherhole' in Gopherspace". There is no umbrella word for
"served collection" across the family, so anything we build to serve several
at once has to bring its own noun rather than borrow one.

### Where the second thing does live

There *is* a real second concern, and it is not the protocol servers: the
**multi-protocol self-serve application** that takes content and serves it
over several protocols at once, with certificates, configuration and logging.
That is **composition**, and the home rule already says composition is ours.
It is the server-side twin of errand: errand goes out and fetches by scheme,
its twin stays home and serves by scheme.

**Not to be minted speculatively.** Per the module/crate/publish rule, a crate
wants an enforced wall, a portability subset, a real consumer, or an external
audience. The real consumer here is the moot-projection work
(moots as publishers (`mere/design_docs/mere_docs/technical_architecture/2026-08-04_moots_as_smolweb_publishers.md`)),
so the ordering is: protocol servers first, in the crates that lack them,
because that is where the community value is and it is spec work; then the
composition layer when something actually needs to serve two protocols at
once.

### And that composition layer is errand (Mark, 2026-08-04)

**Settled: errand takes both halves, exactly as each protocol crate does.** If
the spec crates hold client and server per protocol, the layer above holds
client and server per *scheme*, and inventing a second crate to sit beside
errand would split one routing table across two homes.

**First, three directions, because two of them are already built and calling
them all "write" would muddle this.**

| | What it is | errand today |
|---|---|---|
| **Fetch** | get a document from someone's server | `fetch`, scheme-routed |
| **Send** | push a document to someone *else's* server | `titan_upload`, `misfin_send` |
| **Serve** | *be* the server, and answer others' requests | absent |

So errand is already bidirectional in the send sense. What is missing is the
third thing, and it is genuinely different: send reaches out, serve stays home
and answers the door.

**Why it belongs here rather than beside here.** The serving half is the exact
mirror of what errand already does, and the symmetry is not decorative:

> errand takes N protocols and **normalizes** them into one `Response`.
> A server takes one source and **denormalizes** it into N protocol shapes.

Same table, same vocabulary, opposite direction. Adding a protocol should be
one change in one crate that teaches errand to both speak and answer it, not
two changes in two places that can drift.

**Two conditions, and the first is not optional.**

1. **Feature-gate it.** A browser must never carry listeners, server TLS
   config, or certificate handling it will never run. errand is deliberately
   light and most of its consumers only fetch. The crate is the layer; the
   *feature* names the direction, which is exactly how `gemini-protocol`
   already works (`client`, `tls`) and keeps one convention across both
   levels.
2. **The content source is a trait, not a path.** The interesting half of
   serving is projecting one source into each protocol's native format, and
   there are at least two sources already in view: a directory of files, and
   a moot projection. Assuming the filesystem would mean bolting the moot case
   on afterwards, which is the harder order.

**A naming tension, recorded rather than acted on.** An errand is something you
go out and run; minding the shop is a different activity, and the crate is
published under that name already. The feature-names-the-direction convention
absorbs most of it (`errand` with `serve` reads fine), so this is not blocking.
Worth settling before the serving half exists rather than after, since renaming
a published crate only gets more expensive.

## Expansion: what else is out there (surveyed 2026-08-03)

From [dbohdan's small-internet roundup](http://dbohdan.sdf.org/smolnet/) and
the [ArchiveTeam SmolNet page](https://wiki.archiveteam.org/index.php/SmolNet),
the protocol set is: gemini, gopher, Gopher+, gophers, finger, spartan, text,
SuperText, nex, scorpion, mercury, titan, guppy, scroll, molerat, terse, fsp.

**We have nine**: gemini, gopher, Gopher+, finger, spartan, nex, titan, guppy,
plus misfin for mail.

**Completing the set is the goal, and it is not expansion for its own sake**
(Mark, 2026-08-04, correcting a framing of mine). A browser with a ragged,
partial set of protocols is annoying to use and annoying to reason about;
finishing the set is what removes that. This is also not a new position: the
2026-05-08 commit that first ported these engines titled its slice **"smolweb
completionist"**. The working order below is therefore about *sequencing* the
finish, not about deciding which ones are worth doing.

**Sequence by spec availability, not by appeal.** The one hard constraint this
session established three times is that a wire format is never guessed. So the
order is: protocols whose specification is in hand, then those whose
specification is reachable, then the blocked ones. `kepler`'s spec was read in
full this session; `dict` is RFC 2229; `fsp`, `molerat` and `demarkus` have
reachable specs; `scroll` is blocked on a dead host and waits.

**Not yet spoken**, with the shape each would take under the grouping rule:

| Protocol | Shape | Note |
|---|---|---|
| `gophers` | a feature on `gopher-protocol` | gopher over TLS; the successor-is-a-superset case again |
| `mercury` | its own crate, or a feature beside spartan | gemini without TLS, so it is close kin to spartan |
| `scorpion` | its own crate, protocol **and** format | richer document format than gemtext, and does not mandate encryption |
| `scroll` | its own crate, protocol **and** format | see the gap below |
| `text`, SuperText | one small crate | simpler than gemini, no interactivity |
| `molerat`, `terse`, `fsp` | unsurveyed | read the specs before committing |

**A fidelity gap this survey exposes.** Scroll and scorpion each define a
document format *richer than gemtext*, and nematic's `scroll` engine currently
delegates to `GemtextEngine`. So scroll content is being flattened into
gemtext's line model, which is exactly the collapse the
fidelity plan (`genet/design_docs/nematic_docs/implementation_strategy/2026-07-01_smolweb_fidelity_plan.md`)
exists to catch, and it is a parse-layer loss of the kind that plan's §1
identifies. Note also that scroll has a nematic engine but **no errand
transport**, so it is currently a format we half-read and cannot fetch.

### Scroll, investigated 2026-08-04: half confirmed, half was invented

Going to fix the flattening turned up something worse than the flattening.

**Confirmed.** `text/scroll` is real, and the engine did silently read it as
gemtext, because its dispatch sent everything that was not markdown to
`GemtextEngine`. That is now explicit: a `text/scroll` body still renders
through gemtext, since a degraded document beats a blank one, but it carries a
`DegradedRendering` diagnostic naming what was lost.

**Wrong, but inherited rather than invented** (this entry corrected again,
2026-08-04, after Mark pushed back on the first diagnosis). The engine's module
documentation described a scroll response as "a binary envelope (sender /
signature / timestamp / content-type)" and emitted a diagnostic that signature
verification had not been performed. No reachable source supports that, and a
test asserted the diagnostic, so the wrong claim was load-bearing. Both are
removed, and a test now forbids any diagnostic from mentioning signatures or
envelopes.

But calling it invented was itself an over-claim. Git history says where it
came from: the 2026-05-08 commit that introduced the file describes its slice
as porting **"the donor's smolweb stub formats (scroll, misfin, nex, guppy) as
protocol-spec-faithful body engines"**. So the description was inherited from
graphbrowserapp's `middlenet-core`, and note which format sits beside scroll in
that list: **misfin**, whose sender identity genuinely *is* a client
certificate. Contamination from an adjacent format during a stub port explains
it far better than fabrication does.

Two lessons, and the second is the sharper one. Wrong detail in a doc comment
outlives wrong detail in prose, because tests grow around it. And a confident
verdict about *how* something got wrong is itself a claim needing evidence:
"invented" was reached without checking the history that was sitting right
there.

**What is actually known** (zzo38computer.org's catalogue, the only reachable
source with wire detail):

- port 5699, TLS mandatory, client certificates usable;
- the request is the full URL, a space, then acceptable languages in BCP47
  separated by commas;
- the first four lines of the response are metadata;
- the document format is "a bit more complicated than Gemini, and the inline
  formatting means that escaping will be required";
- document abstracts (Gopher+-like) and Universal Decimal Classification;
- URL fragments are meaningful.

**Blocked, and deliberately not worked around** *(superseded 2026-08-06, next
entry)*. `scrollprotocol.us.to` refuses connections and `web.archive.org` is
unreachable from here, so the exact metadata lines, status codes, and inline
grammar are unknown. That is not enough to write a spec-accurate parser, and
this workspace has now declined to guess a wire format three times (gopher's
introductory page, terse, and this), which is the standard rather than an
exception. Revisit when the spec host is up.

### Scroll, unblocked (2026-08-06)

Mark surfaced [michael-lazar/smolnet-portal](https://github.com/michael-lazar/smolnet-portal),
which settles it two ways at once: the repo **vendors the spec text itself**
(`docs/scroll_spec.txt`, by Christian Lee Seibold, modification date
2024-08-03), and it carries a **working proxy implementation** that
interoperates with live scroll servers, which is the cross-check a lone spec
cannot give. The DeepWiki page layered on top of that repo is an AI-generated
summary and got the usual grain of salt; the repo underneath is primary
source. Worth generalising: for a smolweb protocol, the durable copy of a
spec is as likely to live in an interoperating client's repo as on the
author's host.

The spec confirms both earlier corrections in full: a success response is a
mimetype line then **author, publish date, modification date** (no envelope,
no signatures), and `text/scroll` is a real format richer than gemtext
(five heading levels with numbered sections, nested lists with verbatim
ordered markers, tagged code blocks, input links, link relations, inline
markup with precise toggle rules, linetype escaping).

**`scroll-protocol` 0.1.0 is published**: dep-free wire grammar and
scrolltext parser (the spec's own examples are tests), client with language
negotiation, metadata/abstract requests, and UDC classification. The TLS
half rides `gemini_protocol::tofu_connect` (new in gemini-protocol 0.1.2),
since scroll's spec declares gemini's trust posture in so many words, so one
installed trust store covers both protocols. Provenance is stated plainly in
the crate, including that the spec titles itself *speculative*.

**Still open on the genet side**: nematic's scroll engine still reads
`text/scroll` as gemtext with a `DegradedRendering` diagnostic; it can now be
rewired onto `scroll_protocol::scrolltext` (and errand can gain the scroll
scheme), which retires the last knowingly-degraded lane.

**Still open**: the nex de-duplication. `nex-protocol` already ships a listing
parser (`listing.rs`, `ListingLine`) and errand independently implements the
same grammar with directory detection and base-URL resolution on top
(`parse/nex.rs`). Unlike the moves so far this is not a lift-and-shift: it
needs a decision about which shape is the survivor on an already-published
crate, so it wants a deliberate read of both rather than a rushed unification.
