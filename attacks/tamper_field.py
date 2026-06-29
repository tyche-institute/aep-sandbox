#!/usr/bin/env python3
"""Attack: tamper a field in a signed AEP and leave the hashes alone.

The crudest move: edit the outcome (or the refund amount) and hope nobody recomputes the
digest. The chain_integrity check recomputes receipt_hash over the body and catches it.

Expected verdict: DENY:content_mutated
"""

from _common import banner, load_good, run_verify, save

banner("tamper_field — edit the outcome, don't touch the hashes")
aep = load_good()
aep["outcome"]["refund_id"] = "RF-ATTACKER"
aep["action"]["args"]["amount"] = 250  # unchanged on purpose; the outcome edit is enough
path = save(aep, "tamper_field.aep.json")
rc = run_verify(path)
print(f"\n-> exit {rc} (expected 2 / DENY:content_mutated)")
