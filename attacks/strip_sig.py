#!/usr/bin/env python3
"""Attack: strip / blank the agent signature and hope the verifier doesn't check it.

Some verifiers in the wild treat a missing or malformed signature as "not applicable" and
pass the record anyway. Here we zero out aep_sig (a syntactically valid but wrong 64-byte
signature). receipt_hash is computed over the body *excluding* the signature, so the chain
still looks intact — but the signature check fails.

Expected verdict: DENY:aep_sig_invalid
(Deleting aep_sig entirely instead yields DENY:malformed_aep — try it.)
"""

from _common import banner, load_good, run_verify, save

banner("strip_sig — replace the agent signature with zeros")
aep = load_good()
aep["aep_sig"] = "00" * 64  # well-formed length, wrong signature
path = save(aep, "strip_sig.aep.json")
rc = run_verify(path)
print(f"\n-> exit {rc} (expected 2 / DENY:aep_sig_invalid)")
