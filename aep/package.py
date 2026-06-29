"""Layer 2 — the governed Action Evidence Package (AEP).

A governed AEP is a single JSON document that binds together, in one signed receipt:

  * the action the agent took (method + args + context) and its outcome,
  * the signed mandate that authorised it (issuer -> principal -> mandate),
  * a hash-chain link (prev_hash -> receipt_hash) for ordering/tamper-evidence,
  * the agent's own signature (aep_sig) over the whole receipt.

verify_aep() runs the full ordered check and returns ALLOW only if every guarantee holds.
Because the receipt is *signed* by the agent key the mandate names, a full re-chain forge
(which defeats the bare ledger) fails here at aep_sig — and because scope is enforced,
"exceed the mandate" returns DENY:scope_violation. Those two are the heart of the demo.
"""

from __future__ import annotations

import json

from . import keys, mandate
from .canonical import canonical_bytes, digest, sha256_hex

AEP_VERSION = "aep-sandbox/1"
GENESIS = "0" * 64

# Signature is computed over the receipt with these output fields removed.
_NONCORE = ("aep_sig", "receipt_hash")


def _receipt_core(aep: dict) -> dict:
    return {k: v for k, v in aep.items() if k not in _NONCORE}


def receipt_hash(aep: dict) -> str:
    return sha256_hex(canonical_bytes(_receipt_core(aep)))


def build_aep(agent_sk, agent_id: str, action: dict, outcome: dict,
              credential: dict, mandate_obj: dict, issued_at: int, nonce: str,
              prev_hash: str = GENESIS) -> dict:
    """Assemble and sign a governed AEP for one executed action.

    `nonce` is the per-action one-shot id (jti): a verifier with --consume records it, so
    re-submitting the same signed AEP is caught as a replay.
    """
    aep = {
        "aep_version": AEP_VERSION,
        "agent_id": agent_id,
        "agent_pub": keys.pub_hex(agent_sk),
        "action": action,
        "outcome": outcome,
        "measurements": {
            "action_sha256": digest(action),
            "outcome_sha256": digest(outcome),
        },
        "credential": credential,
        "mandate": mandate_obj,
        "nonce": nonce,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }
    aep["aep_sig"] = keys.sign(agent_sk, _receipt_core(aep))
    aep["receipt_hash"] = receipt_hash(aep)
    return aep


def verify_aep(aep: dict, trust: mandate.TrustStore, now: int,
               consumed: set | None = None) -> dict:
    """Full ordered verification of a governed AEP.

    Returns {verdict: 'ALLOW'|'DENY', reason: str|None, checks: [(name, ok)]}.
    `consumed` (optional) is the set of already-seen one-shot nonces for replay detection.
    """
    checks: list[tuple[str, bool]] = []

    def fail(name: str, reason: str) -> dict:
        checks.append((name, False))
        return {"verdict": "DENY", "reason": reason, "checks": checks}

    def ok(name: str) -> None:
        checks.append((name, True))

    # 0. shape — presence AND type, so a hostile document fails closed instead of crashing
    #    a later check. The agent is untrusted and may present any JSON shape.
    required = ("agent_pub", "action", "credential", "mandate", "nonce", "aep_sig",
                "receipt_hash")
    if not all(k in aep for k in required):
        return fail("structure", "malformed_aep")
    if not all(isinstance(aep.get(k), dict) for k in ("action", "credential", "mandate")):
        return fail("structure", "malformed_aep")
    if not isinstance(aep.get("measurements", {}), dict):
        return fail("structure", "malformed_aep")
    ok("structure")

    # 1. chain integrity: the stored receipt_hash must match the recomputed body
    if aep.get("receipt_hash") != receipt_hash(aep):
        return fail("chain_integrity", "content_mutated")
    ok("chain_integrity")

    # 2. agent signature over the receipt body (this is what defeats re-chain forgery)
    if not keys.verify(aep["agent_pub"], _receipt_core(aep), aep["aep_sig"]):
        return fail("aep_signature", "aep_sig_invalid")
    ok("aep_signature")

    # 3. measurements match the action/outcome they claim to digest. NOTE: action/outcome
    #    are already inside the signed core, so authority comes from aep_signature above;
    #    this is a self-consistency / defence-in-depth check, not the primary defence.
    m = aep.get("measurements", {})
    if m.get("action_sha256") != digest(aep["action"]) or \
       m.get("outcome_sha256") != digest(aep.get("outcome", {})):
        return fail("measurements", "measurement_mismatch")
    ok("measurements")

    # 4. the full mandate chain (issuer -> principal -> agent binding -> scope -> freshness)
    reason = mandate.check_mandate(
        trust=trust,
        credential=aep["credential"],
        mandate=aep["mandate"],
        presented_action=aep["action"],
        agent_pub=aep["agent_pub"],
        agent_id=aep.get("agent_id"),
        now=now,
    )
    if reason is not None:
        return fail("mandate", reason)
    ok("mandate")

    # 5. one-shot replay: has this AEP's nonce already been seen/consumed?
    if consumed is not None and aep.get("nonce") in consumed:
        return fail("replay", "replayed")
    ok("replay")

    return {"verdict": "ALLOW", "reason": None, "checks": checks}


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def dump(aep: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(aep, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
