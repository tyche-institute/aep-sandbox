#!/usr/bin/env python3
"""Attack: the agent itself overreaches — a correctly-signed action outside its mandate.

This is the headline. The agent holds a valid, listed mandate (issue refunds up to 1000)
and its own signing key, and it signs a perfectly well-formed AEP for a 9000 EUR refund.
Every integrity and signature check passes. The verifier still says no, because the
principal's *scope* is enforced against the agent's own overreach.

We verify the shipped fixture (samples/exceed-scope.aep.json) so this works on a fresh clone
with no private keys. If you DO hold the local agent key, you can mint your own overreaching
actions with `python3 mint.py governed` and edit EXCEED_ACTION in mint.py.

Expected verdict: DENY:scope_violation
"""

from _common import EXCEED, banner, run_verify

banner("exceed_scope — valid agent signature, action outside the granted scope")
rc = run_verify(EXCEED)
print(f"\n-> exit {rc} (expected 2 / DENY:scope_violation — overreach denied despite a valid signature)")
