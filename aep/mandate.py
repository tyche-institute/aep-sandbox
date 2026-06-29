"""The mandate layer — "who said the agent could do that?"

A scoped, signed, one-shot authorisation for a *specific* agent action. The trust chain
mirrors how a remote qualified signature keeps a human in sole control, transposed to an
agent action:

    issuer  --signs-->  credential (principal_id <-> principal public key)
    principal --signs-->  mandate   (this agent may do THIS action, within THIS scope,
                                      once, until exp)
    agent   --signs-->   the AEP receipt (see package.py)

Verification is an ordered list of checks; the first failure wins and is named, so an
attacker (and an auditor) can see exactly which guarantee fell. The verdict reasons are
the menu of things to attack.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import keys
from .canonical import digest

MANDATE_VERSION = "aep-mandate/1"

# Ordered failure reasons for the mandate chain. Checked top-to-bottom; first wins.
# (Replay and integrity are appraised at the AEP layer — see package.py.)
REASONS = (
    "issuer_not_listed",        # issuer key absent from / mismatched in the trust store
    "credential_sig_invalid",   # issuer's signature over the principal credential is bad
    "principal_sig_invalid",    # mandate not signed by the credentialed principal key
    "agent_binding_mismatch",   # mandate authorises a different agent key than signed the AEP
    "scope_violation",          # action is outside the granted scope (the headline check)
    "expired",                  # grant past its exp at appraisal time
)


def action_hash(action: dict) -> str:
    """sha256 over {method, args, context} — used by the AEP measurements binding."""
    return digest({
        "method": action.get("method"),
        "args": action.get("args", {}),
        "context": action.get("context", {}),
    })


# --------------------------------------------------------------------------- #
# Trust store + issuance                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class TrustStore:
    """The set of issuer public keys a verifier will accept — the trusted-list analog."""

    issuers: dict = field(default_factory=dict)  # issuer_id -> issuer_pub_hex

    def is_listed(self, issuer_id: str, issuer_pub: str) -> bool:
        return self.issuers.get(issuer_id) == issuer_pub

    @classmethod
    def from_dict(cls, d: dict) -> "TrustStore":
        return cls(issuers=dict(d.get("issuers", {})))

    def to_dict(self) -> dict:
        return {"issuers": dict(self.issuers)}


def issue_credential(issuer_sk, issuer_id: str, principal_id: str,
                     principal_pub: str) -> dict:
    """Issuer binds a principal id to a principal public key (a verifiable credential)."""
    body = {
        "v": "aep-credential/1",
        "issuer_id": issuer_id,
        "issuer_pub": keys.pub_hex(issuer_sk),
        "principal_id": principal_id,
        "principal_pub": principal_pub,
    }
    return {"body": body, "sig": keys.sign(issuer_sk, body)}


def issue_mandate(principal_sk, principal_id: str, agent_id: str, agent_pub: str,
                  scope: dict, iat: int, exp: int) -> dict:
    """The principal's scoped, time-bounded grant of a capability to a specific agent key.

    This is a *capability* grant, not an exact-action approval: the agent may act freely
    inside `scope` until `exp`. Every individual action is still recorded in its own signed
    AEP and re-checked against this scope at verify time — so an agent that overreaches is
    denied even though it validly holds the mandate and signs its own receipts.
    """
    body = {
        "v": MANDATE_VERSION,
        "principal_id": principal_id,
        "agent_id": agent_id,
        "agent_pub": agent_pub,
        "scope": scope,
        "iat": iat,
        "exp": exp,
    }
    return {"body": body, "sig": keys.sign(principal_sk, body)}


# --------------------------------------------------------------------------- #
# Scope enforcement                                                            #
# --------------------------------------------------------------------------- #
def scope_ok(action: dict, scope: dict) -> bool:
    """Is `action` inside `scope`?  Fails closed on anything malformed.

    Two illustrative rules (extend at will):
      * allowed_methods — the action.method must be in the allow-list
      * max_amount      — if the action carries args.amount, it must be a real number
                          (not a bool, string, or list) and must not exceed the cap

    A non-numeric amount under a cap is treated as out of scope rather than crashing the
    verifier: the agent is the untrusted party and can present any shape it likes.
    """
    methods = scope.get("allowed_methods")
    if methods is not None and action.get("method") not in methods:
        return False
    cap = scope.get("max_amount")
    if cap is not None:
        args = action.get("args")
        if args is not None and not isinstance(args, dict):
            return False  # can't read an amount from non-dict args under a cap -> fail closed
        amount = args.get("amount") if isinstance(args, dict) else None
        if amount is not None:  # amount-less actions (e.g. send_receipt) are not capped
            if isinstance(amount, bool) or not isinstance(amount, (int, float)):
                return False  # non-numeric amount under a cap = out of scope (fail closed)
            if amount > cap:
                return False
    return True


# --------------------------------------------------------------------------- #
# The ordered mandate check (returns reason or None)                           #
# --------------------------------------------------------------------------- #
def check_mandate(trust: TrustStore, credential: dict, mandate: dict,
                  presented_action: dict, agent_pub: str, agent_id: str,
                  now: int) -> str | None:
    """Run every mandate-chain guarantee in order. Return the first failing reason, or
    None if the action is authorised. (Replay is appraised separately at the AEP layer.)

    Assumes `credential` and `mandate` are dicts — the caller (package.verify_aep) gates
    structural shape first so this never has to crash on a hostile document.
    """
    cb = credential.get("body", {}) if isinstance(credential, dict) else {}
    mb = mandate.get("body", {}) if isinstance(mandate, dict) else {}
    if not isinstance(cb, dict) or not isinstance(mb, dict):
        return "malformed_mandate"

    if not trust.is_listed(cb.get("issuer_id"), cb.get("issuer_pub")):
        return "issuer_not_listed"
    if not keys.verify(cb.get("issuer_pub", ""), cb, credential.get("sig", "")):
        return "credential_sig_invalid"

    if cb.get("principal_id") != mb.get("principal_id") or not keys.verify(
        cb.get("principal_pub", ""), mb, mandate.get("sig", "")
    ):
        return "principal_sig_invalid"

    # The agent is bound by its public key (what signs the AEP) and its label.
    if mb.get("agent_pub") != agent_pub or mb.get("agent_id") != agent_id:
        return "agent_binding_mismatch"

    if not scope_ok(presented_action, mb.get("scope", {})):
        return "scope_violation"

    if now > mb.get("exp", 0):
        return "expired"

    return None
