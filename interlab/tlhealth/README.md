# Trusted-List Health

A transport-layer probe over the endpoints that published trust infrastructure points at.
It measures one thing nobody is assigned to check: **can a strict TLS client actually reach
the artefact the trust chain depends on?**

## What it is not

Not signature validation, not supervision, not legal-status determination, not a conformity
assessment, and not a vulnerability assessment. A failure here means an endpoint could not be
retrieved by a strict client at a moment in time — nothing more.

## Design rules

- **The classifier is declared in code before any percentage is published.** See `classify()`.
  Changing what counts as reachable changes the headline number, so the rule ships first.
- **Populations are never merged.** EU List of Trusted Lists pointers, global root-programme
  inventories, and other jurisdictions are counted separately; a single blended number would
  hide which world it describes.
- **The instrument must not manufacture its own failures.** Three workers, and one retry
  before a transport failure is believed. The attempt count is published per row.
- **Runs are append-only and dated.** Nothing is ever rewritten; a corrected method opens a
  new schema version rather than editing history.
- **Redirects are followed**, because a pointer that redirects into a dead end is unreachable
  in the only sense that matters to a client.

## Why the retry rule exists

The very first run reported two Hungarian endpoints as timing out. They were not down —
eight parallel workers were. That failure is recorded here rather than quietly fixed,
because an instrument that invents outages is worse than no instrument at all.

## Running

    python3 probe.py            # writes runs/<timestamp>.json and runs/latest.json

Each run records the SHA-256 of the List of Trusted Lists it read, so a later reader can tell
whether a change in the numbers came from the world or from the source document.

## Second dimension: freshness

`freshness.py` reads what each list says about its own currency — `ListIssueDateTime`, and
`NextUpdate`, where an **empty** `NextUpdate` element is the standard's way of saying "this
list will not be updated again".

First measurement, 2026-08-25, 30 XML pointers in the EU List of Trusted Lists:

| state | n |
|---|---|
| current, with a declared next update | 28 |
| terminal, correctly declared | 1 |
| unfetchable | 1 |

The terminal one is the United Kingdom, frozen at `2020-12-31T22:59:59Z` — one second before
the end of the Brexit transition — and marked terminal exactly as the standard intends. The
unfetchable one is the TLS case already reported.

This is a healthy picture, and saying so matters: an instrument that only ever reports
problems is not measuring, it is campaigning. What remains unmeasured, and is the real
question behind this dimension, is whether anything downstream honours these signals — a
consumer that ignores an empty `NextUpdate` still sees 46 UK services as current, five years
on.

## This instrument's own defects, kept in public

Two in the first hour, both found by us, both recorded rather than quietly patched:

1. **It manufactured outages.** Eight parallel workers made two Hungarian endpoints look like
   timeouts. Now three workers, one retry, attempts published per row.
2. **It was blind to namespaces.** The first freshness pass matched unprefixed element names
   only, so every list serialised as `tsl:TrustServiceStatusList` was misread — Hungary's was
   classified "not a trusted list" while serving a perfectly good one. A detector that assumes
   one serialisation of a standard produces confident, wrong counts. Now namespace-agnostic.

Both defects would have produced publishable-looking numbers. That is the argument for
keeping the corpus, the classifier and the failures in the open.
