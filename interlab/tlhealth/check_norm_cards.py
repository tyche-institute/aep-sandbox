#!/usr/bin/env python3
"""check_norm_cards.py — refuse to publish a check that has no declared authority.

The norm rule says no check's only authority is our opinion: each either cites a
versioned normative clause and inherits its RFC 2119 level, or it declares in writing
that it has no normative anchor and why. Until this gate existed the rule was an
intention, and nothing distinguishes an intention from a control except that a control
refuses.

Three things are enforced, and each exists because of something that actually went wrong:

  1. Every card carries an anchor or an explicit, reasoned no_normative_anchor. Without
     this a transport observation can drift into sounding like a non-conformance finding.
  2. Every card carries does_not_establish. Every published count in this project has been
     misread at least once, and the sentence that prevents the misreading has to travel
     with the number rather than sit in a footnote.
  3. Every card carries a reproduction command, because a claim a stranger cannot re-run
     is not a measurement.

Exit 0 if the cards are sound, 1 otherwise. Wired into the site build.
"""
from __future__ import annotations
import pathlib, sys

try:
    import yaml
except ImportError:
    print("check_norm_cards: pyyaml not installed; cannot verify cards", file=sys.stderr)
    sys.exit(1)

CARDS = pathlib.Path(__file__).resolve().parent / "checks.yaml"
REQUIRED = ("id", "observable", "reproduce", "does_not_establish")


def main() -> int:
    if not CARDS.exists():
        print(f"check_norm_cards: {CARDS} missing", file=sys.stderr)
        return 1
    doc = yaml.safe_load(CARDS.read_text(encoding="utf-8")) or {}
    cards = doc.get("checks") or []
    if not cards:
        print("check_norm_cards: no cards defined", file=sys.stderr)
        return 1

    problems: list[str] = []
    seen: set[str] = set()
    for i, c in enumerate(cards):
        cid = c.get("id") or f"<card {i}>"
        if cid in seen:
            problems.append(f"{cid}: duplicate id")
        seen.add(cid)
        for field in REQUIRED:
            if not str(c.get(field) or "").strip():
                problems.append(f"{cid}: missing {field}")
        anchored = bool(str(c.get("clause") or "").strip())
        declared_unanchored = bool(c.get("no_normative_anchor"))
        if anchored and declared_unanchored:
            problems.append(f"{cid}: claims both a clause and no_normative_anchor")
        if not anchored and not declared_unanchored:
            problems.append(f"{cid}: no clause cited and no_normative_anchor not declared")
        if declared_unanchored and not str(c.get("why_no_anchor") or "").strip():
            problems.append(f"{cid}: declares no anchor without saying why")
        if anchored and not str(c.get("document") or "").strip():
            problems.append(f"{cid}: cites a clause without naming the document")

    for p in problems:
        print(f"  NORM CARD: {p}", file=sys.stderr)
    anchored_n = sum(1 for c in cards if str(c.get("clause") or "").strip())
    print(f"check_norm_cards: {len(cards)} cards, {anchored_n} anchored to a clause, "
          f"{len(cards)-anchored_n} declaring no anchor — "
          f"{'OK' if not problems else str(len(problems)) + ' PROBLEM(S)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
