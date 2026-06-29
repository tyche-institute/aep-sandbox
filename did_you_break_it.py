#!/usr/bin/env python3
"""did_you_break_it.py — the CTF judge.

Scores every governed AEP it can find (the fixtures + anything under attacks/out/) and a
player-supplied challenge file, then tells you whether the verifier held or you broke it.

THE WIN CONDITION
-----------------
You "break it" when you make verify.py return **ALLOW** for an AEP that authorises something
the reference mandate does NOT — a refund over 1000, a method outside the allow-list, a
different issuer/agent than the listed trust anchor. In other words: get the appraiser to
bless an action outside the granted scope. Tampering that the verifier already DENYs does
not count — denial is the defense working.

    # drop your forged package here, then judge it:
    cp my_forgery.aep.json attacks/out/CHALLENGE.aep.json
    python3 did_you_break_it.py
"""

from __future__ import annotations

import glob
import os

import verify  # reuse the real trust store + appraisal clock
from aep import mandate, package

ROOT = os.path.dirname(os.path.abspath(__file__))
GOOD = os.path.join(ROOT, "samples", "good.aep.json")
CHALLENGE = os.path.join(ROOT, "attacks", "out", "CHALLENGE.aep.json")


def reference_scope() -> dict:
    ref = package.load(GOOD)
    return ref["mandate"]["body"]["scope"]


def out_of_reference_scope(aep: dict, ref_scope: dict) -> bool:
    return not mandate.scope_ok(aep.get("action", {}), ref_scope)


def judge(path: str, trust, ref_scope: dict) -> tuple[str, str]:
    """Return (verdict, note). verdict in {ALLOW, DENY, ERROR}."""
    try:
        aep = package.load(path)
        result = package.verify_aep(aep, trust, now=verify.NOW_DEFAULT, consumed=set())
    except Exception as exc:  # noqa: BLE001 — a malformed file is just a failed attack
        return "ERROR", f"unparseable/raised ({exc.__class__.__name__})"
    if result["verdict"] == "ALLOW":
        if out_of_reference_scope(aep, ref_scope):
            return "ALLOW", "🚩 OUT-OF-SCOPE ACTION ALLOWED — this is a break"
        return "ALLOW", "in-scope, legitimately authorised"
    return "DENY", f"denied: {result['reason']}"


def main() -> int:
    trust = verify.load_trust()
    ref_scope = reference_scope()

    targets = [GOOD, os.path.join(ROOT, "samples", "exceed-scope.aep.json")]
    targets += sorted(glob.glob(os.path.join(ROOT, "attacks", "out", "*.aep.json")))

    print("=" * 72)
    print("  AEP SANDBOX — did you break it?")
    print("=" * 72)
    broke = False
    for path in targets:
        verdict, note = judge(path, trust, ref_scope)
        if verdict == "ALLOW" and "break" in note:
            broke = True
        print(f"  {verdict:6}  {os.path.relpath(path, ROOT):40}  {note}")

    print("-" * 72)
    if os.path.exists(CHALLENGE):
        verdict, note = judge(CHALLENGE, trust, ref_scope)
        if verdict == "ALLOW" and "break" in note:
            print("  🚩🚩  CHALLENGE SOLVED — you got an out-of-scope action ALLOWed!")
        else:
            print(f"  CHALLENGE: {verdict} — {note}. The verifier held; keep trying.")
    else:
        print("  No attacks/out/CHALLENGE.aep.json yet. Forge one that verify.py ALLOWs")
        print("  but that authorises an action outside the reference scope, then re-run.")

    print("=" * 72)
    if broke:
        print("  Result: a package outside the mandate was ALLOWed. Something is broken —")
        print("  if that was a shipped attack, the sandbox has a bug; please report it.")
    else:
        print("  Result: every out-of-scope / forged package was DENIED. Defense held.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
