#!/usr/bin/env python3
"""Attack: replay a genuine, ALLOWed evidence package to double-execute the action.

The AEP is real and verifies cleanly the first time. But each AEP carries a one-shot nonce
(jti). A verifier running with --consume records it; the second submission of the same
package is caught as a replay.

Expected: first run ALLOW (exit 0), second run DENY:replayed (exit 2).
"""

import os

from _common import GOOD, ROOT, banner, run_verify

STATE = os.path.join(ROOT, "state", "consumed_nonces.txt")
NONCE = "aep-nonce-0001"  # the good sample's jti


def _forget(nonce: str) -> None:
    """Reset just this nonce so the demo is repeatable."""
    if not os.path.exists(STATE):
        return
    with open(STATE, encoding="utf-8") as fh:
        lines = [ln for ln in fh if ln.strip() and ln.strip() != nonce]
    with open(STATE, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


banner("replay — submit the same ALLOWed AEP twice (verifier in --consume mode)")
_forget(NONCE)  # clean slate

print("\n# first submission:")
rc1 = run_verify(GOOD, "--consume")
print(f"-> exit {rc1} (expected 0 / ALLOW, nonce now consumed)")

print("\n# replay the very same package:")
rc2 = run_verify(GOOD, "--consume")
print(f"-> exit {rc2} (expected 2 / DENY:replayed)")

_forget(NONCE)  # leave no trace so the demo can be re-run
