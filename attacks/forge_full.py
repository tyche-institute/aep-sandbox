#!/usr/bin/env python3
"""Attack: forge an ENTIRE evidence package from scratch with your own keys.

Don't tamper — *manufacture*. Generate a fresh issuer, principal and agent, write a mandate
granting yourself a huge scope, and sign every layer consistently with your own keys. Every
signature is internally valid and the chain is intact. The only thing you cannot do is make
your issuer appear in the verifier's trust store.

Expected verdict: DENY:issuer_not_listed — the trust anchor, not the math, is what stops you.
"""

from _common import banner, run_verify, save
from aep import keys, mandate, package

banner("forge_full — mint a wholly self-consistent AEP signed by attacker keys")

issuer = keys.generate_private()
principal = keys.generate_private()
agent = keys.generate_private()

action = {"method": "wire_transfer",
          "args": {"to": "attacker-iban", "amount": 1_000_000, "currency": "EUR"},
          "context": {"note": "totally legitimate"}}
outcome = {"status": "ok"}

credential = mandate.issue_credential(
    issuer, "attacker-issuer:not-listed", "operator:alice", keys.pub_hex(principal)
)
mandate_obj = mandate.issue_mandate(
    principal_sk=principal, principal_id="operator:alice", agent_id="agent:evil",
    agent_pub=keys.pub_hex(agent),
    scope={"allowed_methods": ["wire_transfer"], "max_amount": 10_000_000},
    iat=0, exp=9_999_999_999,
)
aep = package.build_aep(
    agent_sk=agent, agent_id="agent:evil", action=action, outcome=outcome,
    credential=credential, mandate_obj=mandate_obj, issued_at=1_750_000_000,
    nonce="attacker-nonce-1",
)
path = save(aep, "forge_full.aep.json")
rc = run_verify(path)
print(f"\n-> exit {rc} (expected 2 / DENY:issuer_not_listed — your issuer isn't a trust anchor)")
