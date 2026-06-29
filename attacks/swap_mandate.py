#!/usr/bin/env python3
"""Attack: swap the mandate inside a real, agent-signed AEP for a broader one.

Keep the genuine agent signature's package, but splice in your own mandate that grants a
huge scope, then recompute receipt_hash so the chain looks intact. The catch: the agent
signed the *whole* receipt body, mandate included — so substituting the mandate invalidates
that signature, which you cannot reproduce without the agent's private key.

Expected verdict: DENY:aep_sig_invalid
"""

from _common import banner, load_good, run_verify, save
from aep import keys, mandate, package

banner("swap_mandate — replace the mandate with a self-signed, broader one")

aep = load_good()
attacker_principal = keys.generate_private()
attacker_issuer = keys.generate_private()

# A mandate granting the agent a vastly wider scope, signed by the attacker's principal key.
aep["credential"] = mandate.issue_credential(
    attacker_issuer, "demo-issuer:tyche-sandbox", "operator:alice",
    keys.pub_hex(attacker_principal),
)
aep["mandate"] = mandate.issue_mandate(
    principal_sk=attacker_principal, principal_id="operator:alice",
    agent_id=aep["agent_id"], agent_pub=aep["agent_pub"],
    scope={"allowed_methods": ["issue_refund"], "max_amount": 10_000_000},
    iat=0, exp=9_999_999_999,
)
aep["receipt_hash"] = package.receipt_hash(aep)  # repair the chain hash
path = save(aep, "swap_mandate.aep.json")
rc = run_verify(path)
print(f"\n-> exit {rc} (expected 2 / DENY:aep_sig_invalid — the agent never signed THIS mandate)")
