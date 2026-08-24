#!/usr/bin/env python3
"""run_reference.py — appraise every Round-0 vector with the PYTHON reference verifier.

Same call path as verify.py: package.verify_aep(aep, trust, now, consumed), wrapped in the
same fail-closed guard verify.py uses (any traceback on a hostile document -> malformed_aep).
Per-case `now` and `consumed` come from vectors/cases.json.

Writes verdicts-python.json: a list of {file, now, consumed, verdict, reason, canonical_core}.
`canonical_core` is THIS implementation's canonical serialisation of the receipt core — the
exact bytes it signs/hashes over — so compare.py can show where two impls disagree.

  python3 interlab/round0/run_reference.py
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from aep import mandate, package                      # noqa: E402
from aep.canonical import canonical_bytes             # noqa: E402

VEC = os.path.join(HERE, "vectors")
TRUST_PATH = os.path.join(HERE, "trusted_issuers.json")
OUT = os.path.join(HERE, "verdicts-python.json")


def load_trust() -> mandate.TrustStore:
    with open(TRUST_PATH, encoding="utf-8") as fh:
        return mandate.TrustStore.from_dict(json.load(fh))


def canonical_core(aep) -> str | None:
    """This verifier's canonical bytes for the receipt core, as a string (or None if the
    document is not even a dict). Uses surrogatepass so any byte sequence round-trips."""
    try:
        core = package._receipt_core(aep)
        return canonical_bytes(core).decode("utf-8", "surrogatepass")
    except Exception:  # noqa: BLE001
        return None


def appraise(aep, trust, now, consumed) -> dict:
    # Mirror verify.py's guard exactly.
    try:
        return package.verify_aep(aep, trust, now=now, consumed=consumed)
    except Exception:  # noqa: BLE001
        return {"verdict": "DENY", "reason": "malformed_aep",
                "checks": [("structure", False)]}


def main() -> int:
    trust = load_trust()
    with open(os.path.join(VEC, "cases.json"), encoding="utf-8") as fh:
        cases = json.load(fh)

    results = []
    for c in cases:
        path = os.path.join(VEC, c["file"])
        # package.load == json.load; a genuinely unparseable file would raise here, which is
        # a corpus defect, not a verdict — we let it surface loudly rather than mask it.
        aep = package.load(path)
        now = c["now"]
        consumed = set(c["consumed"])
        res = appraise(aep, trust, now, consumed)
        results.append({
            "file": c["file"],
            "now": now,
            "consumed": sorted(consumed),
            "verdict": res["verdict"],
            "reason": res["reason"],
            "canonical_core": canonical_core(aep),
        })
        tag = res["verdict"] + (f":{res['reason']}" if res["reason"] else "")
        print(f"  {c['file']:<42} -> {tag}")

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"[run_reference] wrote {OUT} ({len(results)} verdicts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
