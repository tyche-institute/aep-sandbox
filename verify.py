#!/usr/bin/env python3
"""verify.py — the single appraiser you are trying to defeat.

    python3 verify.py samples/good.aep.json        # -> ALLOW (exit 0)
    python3 verify.py path/to/your-attack.aep.json # -> DENY:<reason> (exit 2)
    python3 verify.py --ledger samples/ledger.jsonl # verify the unsigned hash-chain
    python3 verify.py --consume samples/good.aep.json  # mark the one-shot nonce used (replay demo)
    python3 verify.py --now 2100000000 samples/good.aep.json  # appraise at a later time (expiry demo)

Exit codes: 0 = ALLOW / chain intact, 2 = DENY / chain broken, 1 = usage/load error.
The verdict reason is the name of the first guarantee that failed — that is the scoreboard
for ../attacks/ and did_you_break_it.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from aep import ledger, mandate, package

ROOT = os.path.dirname(os.path.abspath(__file__))
TRUST_PATH = os.path.join(ROOT, "keys", "trusted_issuers.json")
CONSUMED_PATH = os.path.join(ROOT, "state", "consumed_nonces.txt")
NOW_DEFAULT = 1_750_000_100


def load_trust() -> mandate.TrustStore:
    if not os.path.exists(TRUST_PATH):
        raise SystemExit(f"no trust store at {TRUST_PATH} — run: python3 mint.py init")
    with open(TRUST_PATH, encoding="utf-8") as fh:
        return mandate.TrustStore.from_dict(json.load(fh))


def load_consumed() -> set:
    if not os.path.exists(CONSUMED_PATH):
        return set()
    with open(CONSUMED_PATH, encoding="utf-8") as fh:
        return {line.strip() for line in fh if line.strip()}


def add_consumed(nonce: str) -> None:
    os.makedirs(os.path.dirname(CONSUMED_PATH), exist_ok=True)
    with open(CONSUMED_PATH, "a", encoding="utf-8") as fh:
        fh.write(nonce + "\n")


def verify_governed(path: str, now: int, consume: bool) -> int:
    aep = package.load(path)
    trust = load_trust()
    consumed = load_consumed()
    try:
        result = package.verify_aep(aep, trust, now=now, consumed=consumed)
    except Exception:  # noqa: BLE001 — no attacker-shaped document may yield a traceback
        result = {"verdict": "DENY", "reason": "malformed_aep",
                  "checks": [("structure", False)]}

    for name, ok in result["checks"]:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if result["verdict"] == "ALLOW":
        print(f"VERDICT: ALLOW  ({os.path.basename(path)})")
        if consume:
            nonce = aep.get("nonce")
            if nonce:
                add_consumed(nonce)
                print(f"  one-shot nonce consumed: {nonce}")
        return 0
    print(f"VERDICT: DENY  reason={result['reason']}  ({os.path.basename(path)})")
    return 2


def verify_ledger(path: str) -> int:
    chain = ledger.load(path)
    ok, problems = ledger.verify(chain)
    if ok:
        print(f"VERDICT: chain intact across {len(chain)} receipts  "
              f"({os.path.basename(path)})")
        return 0
    for p in problems:
        print(f"  [FAIL] {p}")
    print(f"VERDICT: BROKEN  {len(problems)} problem(s)  ({os.path.basename(path)})")
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="path to a governed .aep.json (or a ledger with --ledger)")
    ap.add_argument("--ledger", action="store_true", help="verify an unsigned hash-chain ledger")
    ap.add_argument("--consume", action="store_true", help="record the one-shot nonce on ALLOW")
    ap.add_argument("--now", type=int, default=NOW_DEFAULT, help="logical appraisal time")
    args = ap.parse_args()

    if not os.path.exists(args.target):
        print(f"no such file: {args.target}", file=sys.stderr)
        return 1
    try:
        if args.ledger:
            return verify_ledger(args.target)
        return verify_governed(args.target, now=args.now, consume=args.consume)
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"could not parse {args.target}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
