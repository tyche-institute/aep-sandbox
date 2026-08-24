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
