# attacks/

One readable script per attack lever. Each loads a legitimately-minted sample, mutates it the
way a real adversary would, writes the result to `out/` (git-ignored), and runs the real
`verify.py` on it so you see the exact verdict. None of them need the private trust-anchor
keys.

| Script | Lever | Expected verdict |
|---|---|---|
| `tamper_field.py` | edit a field, leave the hashes | `DENY:content_mutated` |
| `forge_rechain.py` | rewrite + recompute every hash | ledger **ALLOW** (lesson), signed AEP `DENY:aep_sig_invalid` |
| `forge_full.py` | mint a whole AEP with your own keys | `DENY:issuer_not_listed` |
| `swap_mandate.py` | splice a broader mandate into a real AEP | `DENY:aep_sig_invalid` |
| `exceed_scope.py` | valid signature, action outside the grant | `DENY:scope_violation` |
| `replay.py` | re-submit an ALLOWed package | `ALLOW` then `DENY:replayed` |
| `strip_sig.py` | blank the agent signature | `DENY:aep_sig_invalid` |

Start from any of these, copy it, and try to do better — the goal is an AEP that `verify.py`
**ALLOWs** but that authorises an action outside the reference mandate. Drop your best attempt
at `out/CHALLENGE.aep.json` and run `python3 ../did_you_break_it.py`.
