#!/usr/bin/env python3
"""generate_round0.py — mint the Track-B Round-0 interlaboratory-comparison corpus.

Every vector is produced HERE, from the sandbox's own machinery (aep/*, the committed
trust-anchor keys under keys/private/). Nothing is hand-edited: re-running this script with
the same keys reproduces byte-identical vectors, because Ed25519 signing is deterministic
(RFC 8032) and every timestamp/nonce is fixed (no wall-clock).

  python3 interlab/round0/generate_round0.py

It writes:
  * vectors/r0-<nn>-<slug>.aep.json  — the corpus
  * vectors/cases.json               — per-case run parameters (now, consumed, scored class)
  * trusted_issuers.json             — a copy of the trust anchor list the runners load

NO private key material is emitted into any vector — only public keys and signatures, which
is exactly what a real evidence package carries.

Vector classes (see the build spec / design doc notes/tyche-labs/interlab-design-v0.1.md):
  COVERAGE (a-h) — DENY reasons the shipped parity corpus never exercised.
  BOUNDARY (i-m) — exact-edge accepts/denies.
  PROBES   (n-r) — canonicalisation / parser / type-semantics stress; a divergence between
                   the two reference implementations is a FINDING, not a failure, and these
                   are excluded from participant scoring.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))          # .../aep-sandbox
sys.path.insert(0, ROOT)                               # so `import aep...` resolves

from aep import keys, mandate, package                 # noqa: E402
from aep.mandate import MANDATE_VERSION                 # noqa: E402

VEC = os.path.join(HERE, "vectors")
PRIV = os.path.join(ROOT, "keys", "private")
SANDBOX_TRUST = os.path.join(ROOT, "keys", "trusted_issuers.json")

# --------------------------------------------------------------------------- #
# Fixed identities + logical clock (mirrors mint.py so the chain is coherent)  #
# --------------------------------------------------------------------------- #
ISSUER_ID = "demo-issuer:tyche-sandbox"
PRINCIPAL_ID = "operator:alice"
AGENT_ID = "agent:refund-assistant-1"
IAT = 1_750_000_000
EXP = 2_000_000_000
NOW_DEFAULT = 1_750_000_100
EXP_BOUNDARY = 1_750_000_500          # used by the now==exp boundary case
SCOPE = {"allowed_methods": ["issue_refund", "send_receipt"], "max_amount": 1000}

GOOD_ACTION = {
    "method": "issue_refund",
    "args": {"order_id": "ORD-4471", "amount": 250, "currency": "EUR"},
    "context": {"channel": "support-queue", "ticket": "T-9012"},
}
GOOD_OUTCOME = {"status": "ok", "refund_id": "RF-22317", "human_signoff": False}

# --------------------------------------------------------------------------- #
# Load the committed trust-anchor private keys (git-ignored on a fresh clone). #
# --------------------------------------------------------------------------- #
def _load_sk(name: str):
    with open(os.path.join(PRIV, f"{name}.sk"), encoding="utf-8") as fh:
        return keys.load_private_hex(fh.read())


ISSUER_SK = _load_sk("issuer")
PRINCIPAL_SK = _load_sk("principal")
AGENT_SK = _load_sk("agent")
AGENT_PUB = keys.pub_hex(AGENT_SK)
PRINCIPAL_PUB = keys.pub_hex(PRINCIPAL_SK)

# A deterministic throwaway "other agent" for the agent-binding-mismatch case. Its PRIVATE
# bytes are a fixed constant so re-runs are byte-identical; only its PUBLIC key ever reaches
# a vector file.
OTHER_AGENT_SK = keys.load_private_hex("11" * 32)
OTHER_AGENT_PUB = keys.pub_hex(OTHER_AGENT_SK)

CASES: list[dict] = []


# --------------------------------------------------------------------------- #
# Minting helpers                                                              #
# --------------------------------------------------------------------------- #
def base_credential() -> dict:
    return mandate.issue_credential(ISSUER_SK, ISSUER_ID, PRINCIPAL_ID, PRINCIPAL_PUB)


def base_mandate(scope=None, exp=EXP, agent_pub=AGENT_PUB, agent_id=AGENT_ID) -> dict:
    return mandate.issue_mandate(
        principal_sk=PRINCIPAL_SK, principal_id=PRINCIPAL_ID, agent_id=agent_id,
        agent_pub=agent_pub, scope=scope if scope is not None else SCOPE, iat=IAT, exp=exp,
    )


def build(action, outcome, nonce, credential=None, mandate_obj=None) -> dict:
    return package.build_aep(
        agent_sk=AGENT_SK, agent_id=AGENT_ID, action=action, outcome=outcome,
        credential=credential or base_credential(),
        mandate_obj=mandate_obj if mandate_obj is not None else base_mandate(),
        issued_at=IAT, nonce=nonce,
    )


def resign(aep: dict) -> dict:
    """Re-sign the receipt core with the real agent key and repair receipt_hash.

    This is the move an *insider* (a signer holding the agent key) makes: it lets the
    structure / chain_integrity / aep_signature checks all pass over a deliberately
    inconsistent core, so a later check (measurements, mandate-chain) is the one that fires.
    An outside attacker without this key cannot do it — see the reachability note in the
    build report.
    """
    aep["aep_sig"] = keys.sign(AGENT_SK, package._receipt_core(aep))
    aep["receipt_hash"] = package.receipt_hash(aep)
    return aep


def _dumps(aep: dict) -> str:
    return json.dumps(aep, ensure_ascii=False, indent=2) + "\n"


def emit(aep: dict, nn: int, slug: str, klass: str, *, now=NOW_DEFAULT, consumed=None,
         scored=True, design: str = "", note: str = "", raw_text: str | None = None) -> None:
    """Write one vector file and register its run parameters in CASES."""
    fname = f"r0-{nn:02d}-{slug}.aep.json"
    path = os.path.join(VEC, fname)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw_text if raw_text is not None else _dumps(aep))
    CASES.append({
        "file": fname,
        "slug": slug,
        "class": klass,          # coverage | boundary | probe
        "now": now,
        "consumed": list(consumed or []),
        "scored": scored,        # probes are excluded from scoring
        "design_expectation": design,
        "note": note,
    })


# --------------------------------------------------------------------------- #
# COVERAGE — uncovered DENY reasons                                            #
# --------------------------------------------------------------------------- #
def gen_coverage() -> None:
    # (a) malformed_aep — a required key is missing. Structure fails first (before any hash
    #     or signature check), so the stale sig left behind is irrelevant.
    a = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-a")
    del a["nonce"]
    emit(a, 1, "malformed-missing-key", "coverage",
         design="DENY:malformed_aep",
         note="required key 'nonce' absent -> structure check (presence) fails closed")

    # (b) malformed_aep — action is a list, not a dict.
    b = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-b")
    b["action"] = [
        {"method": "issue_refund",
         "args": {"order_id": "ORD-4471", "amount": 250, "currency": "EUR"}}
    ]
    emit(b, 2, "malformed-action-list", "coverage",
         design="DENY:malformed_aep",
         note="action is a JSON array -> structure check (type) fails closed")

    # (c) measurement_mismatch — action_sha256 tampered, THEN re-signed over the tampered
    #     core. Only reachable BY A SIGNER (we hold the agent key): an external tamperer trips
    #     chain_integrity/aep_signature first. See reachability note in the report.
    c = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-c")
    c["measurements"]["action_sha256"] = "0" * 64
    resign(c)
    emit(c, 3, "measurement-mismatch-tampered", "coverage",
         design="DENY:measurement_mismatch",
         note="measurements.action_sha256 replaced then core re-signed; structure/chain/"
              "aep_sig pass, self-consistency check fires")

    # (d) measurement_mismatch — measurements object absent entirely. structure passes
    #     (aep.get('measurements', {}) is a dict); the measurements check reads {} and the
    #     None digest mismatches. Re-signed so earlier checks pass.
    d = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-d")
    del d["measurements"]
    resign(d)
    emit(d, 4, "measurement-absent", "coverage",
         design="DENY:measurement_mismatch",
         note="no measurements key: structure treats absent-as-{} (dict) so it passes; the "
              "measurements check then sees None != digest")

    # (e) malformed_mandate — mandate.body is a string (mandate stays a dict so structure
    #     passes). Re-signed so the chain reaches the mandate check.
    e = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-e")
    e["mandate"] = {"body": "not-an-object", "sig": e["mandate"]["sig"]}
    resign(e)
    emit(e, 5, "malformed-mandate-body-string", "coverage",
         design="DENY:malformed_mandate",
         note="mandate.body is a str -> check_mandate returns malformed_mandate")

    # (f) credential_sig_invalid — credential body mutated (principal_id), issuer sig left
    #     stale; issuer_id/issuer_pub kept so issuer_not_listed does NOT fire first.
    f = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-f")
    f["credential"]["body"]["principal_id"] = "operator:mallory"
    resign(f)
    emit(f, 6, "credential-sig-invalid", "coverage",
         design="DENY:credential_sig_invalid",
         note="credential.body.principal_id changed, credential.sig stale; issuer still "
              "listed so the issuer's signature check is what fails")

    # (g) principal_sig_invalid — mandate body mutated (scope widened), principal sig stale;
    #     principal_id kept equal so the cause is the signature, not an id mismatch.
    g = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-g")
    g["mandate"]["body"]["scope"]["max_amount"] = 999_999
    resign(g)
    emit(g, 7, "principal-sig-invalid", "coverage",
         design="DENY:principal_sig_invalid",
         note="mandate.body.scope widened, mandate.sig stale; credential intact so the "
              "principal's signature over the mandate is what fails")

    # (h) agent_binding_mismatch — a fully valid credential+mandate, but the mandate names a
    #     DIFFERENT agent key; the outer package is signed by OUR agent. All signatures are
    #     internally valid; the binding check catches the mismatch.
    cred = base_credential()
    mand = base_mandate(agent_pub=OTHER_AGENT_PUB, agent_id="agent:other-1")
    h = package.build_aep(
        agent_sk=AGENT_SK, agent_id=AGENT_ID, action=GOOD_ACTION, outcome=GOOD_OUTCOME,
        credential=cred, mandate_obj=mand, issued_at=IAT, nonce="aep-nonce-h",
    )
    emit(h, 8, "agent-binding-mismatch", "coverage",
         design="DENY:agent_binding_mismatch",
         note="mandate authorises agent:other-1 / a different pubkey; AEP signed by our "
              "agent -> mb.agent_pub != agent_pub")


# --------------------------------------------------------------------------- #
# BOUNDARY — exact edges                                                       #
# --------------------------------------------------------------------------- #
def gen_boundary() -> None:
    # (i) now == exp exactly -> ALLOW (the check is `now > exp`, strict).
    i = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-i",
              mandate_obj=base_mandate(exp=EXP_BOUNDARY))
    emit(i, 9, "boundary-now-eq-exp", "boundary", now=EXP_BOUNDARY,
         design="ALLOW",
         note=f"appraised at now == exp == {EXP_BOUNDARY}; strict > means not expired")

    # (j) amount == max_amount exactly -> ALLOW (the check is `amount > cap`, strict).
    action_j = {
        "method": "issue_refund",
        "args": {"order_id": "ORD-4471", "amount": 1000, "currency": "EUR"},
        "context": {"channel": "support-queue", "ticket": "T-9012"},
    }
    j = build(action_j, GOOD_OUTCOME, "aep-nonce-j")
    emit(j, 10, "boundary-amount-eq-max", "boundary",
         design="ALLOW", note="args.amount == scope.max_amount == 1000; strict > means in scope")

    # (k) amount is the JSON string "5" -> scope_violation (non-numeric amount fails closed).
    action_k = {
        "method": "issue_refund",
        "args": {"order_id": "ORD-4471", "amount": "5", "currency": "EUR"},
        "context": {"channel": "support-queue", "ticket": "T-9012"},
    }
    k = build(action_k, GOOD_OUTCOME, "aep-nonce-k")
    emit(k, 11, "amount-string", "boundary",
         design="DENY:scope_violation",
         note='args.amount == "5" (string) under a numeric cap -> out of scope, not < 5')

    # (l) mandate WITHOUT an exp field -> expired (exp defaults to 0; now > 0).
    mb_body = {
        "v": MANDATE_VERSION, "principal_id": PRINCIPAL_ID, "agent_id": AGENT_ID,
        "agent_pub": AGENT_PUB, "scope": SCOPE, "iat": IAT,   # <- no 'exp'
    }
    mand_l = {"body": mb_body, "sig": keys.sign(PRINCIPAL_SK, mb_body)}
    lo = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-l", mandate_obj=mand_l)
    emit(lo, 12, "mandate-no-exp", "boundary",
         design="DENY:expired",
         note="mandate.body has no exp; check uses mb.get('exp', 0)=0 -> now > 0 -> expired")

    # (m) action WITHOUT method while allowed_methods present -> scope_violation.
    action_m = {
        "args": {"order_id": "ORD-4471", "amount": 250, "currency": "EUR"},
        "context": {"channel": "support-queue", "ticket": "T-9012"},   # <- no 'method'
    }
    m = build(action_m, GOOD_OUTCOME, "aep-nonce-m")
    emit(m, 13, "action-no-method", "boundary",
         design="DENY:scope_violation",
         note="action has no method; None not in allowed_methods -> out of scope")


# --------------------------------------------------------------------------- #
# PROBES — canonicalisation / parser / type-semantics stress (unscored)       #
# --------------------------------------------------------------------------- #
def gen_probes() -> None:
    # (n) float amount 0.1 in the SIGNED payload. Python '0.1' == JS '0.1' -> expect AGREE.
    action_n = {
        "method": "issue_refund",
        "args": {"order_id": "ORD-4471", "amount": 0.1, "currency": "EUR"},
        "context": {"channel": "support-queue", "ticket": "T-9012"},
    }
    n = build(action_n, GOOD_OUTCOME, "aep-nonce-n")
    emit(n, 14, "probe-float-0_1", "probe", scored=False,
         design="ALLOW (both) — control probe",
         note="float 0.1: Python canonical '0.1' == JS '0.1'; canonicalisation agrees")

    # (o) float amount 1e-7. Python canonical '1e-07' vs JS '1e-7' -> DELIBERATE divergence.
    action_o = {
        "method": "issue_refund",
        "args": {"order_id": "ORD-4471", "amount": 1e-07, "currency": "EUR"},
        "context": {"channel": "support-queue", "ticket": "T-9012"},
    }
    o = build(action_o, GOOD_OUTCOME, "aep-nonce-o")
    emit(o, 15, "probe-float-1e-7", "probe", scored=False,
         design="DIVERGENCE — Python ALLOW, JS DENY:content_mutated",
         note="float 1e-07: Python canonical '1e-07' vs JS '1e-7' -> JS recomputes a "
              "different receipt_hash and fails chain_integrity")

    # (p) unicode string in a signed field (emoji U+1F4A5 + combining acute + U+2212 minus +
    #     Cyrillic). Python(ensure_ascii=False) and JS JSON.stringify emit identical bytes.
    action_p = {
        "method": "issue_refund",
        "args": {"order_id": "ORD-4471", "amount": 250, "currency": "EUR"},
        "context": {"channel": "support-queue", "ticket": "T-9012",
                    "note": "сумма 5 − \U0001F4A5 café"},
    }
    p = build(action_p, GOOD_OUTCOME, "aep-nonce-p")
    emit(p, 16, "probe-unicode", "probe", scored=False,
         design="ALLOW (both) — control probe",
         note="emoji+combining+U+2212+Cyrillic in a signed field; UTF-8 bytes identical "
              "across Python ensure_ascii=False and JS JSON.stringify")

    # (q) duplicate JSON key in the RAW file text. Decoy value first, signed value last;
    #     both parsers keep the LAST -> the signed value -> ALLOW. (A parser that kept the
    #     first would DENY, so agreement here confirms last-wins on both.)
    q = build(GOOD_ACTION, GOOD_OUTCOME, "aep-nonce-q")
    raw = _dumps(q).replace('"status": "ok"',
                            '"status": "DECOY", "status": "ok"', 1)
    emit(q, 17, "probe-dup-key", "probe", scored=False, raw_text=raw,
         design="ALLOW (both) — confirms last-key-wins",
         note='raw text carries outcome.status twice ("DECOY" then "ok"); both parsers keep '
              'the last, so the digest matches the signed value')

    # (r) numeric nonce (a JSON number, not a string) with the consumed-set holding its
    #     STRING form. `12345 in {"12345"}` is False in both languages -> not a replay.
    r = build(GOOD_ACTION, GOOD_OUTCOME, 12345)
    emit(r, 18, "probe-numeric-nonce", "probe", scored=False, consumed=["12345"],
         design="ALLOW (both) — replay type-semantics",
         note="nonce is the number 12345; consumed set holds the string '12345'; neither "
              "impl matches across types, so it is NOT flagged replayed")


def write_trust() -> None:
    """Copy the sandbox trust anchor list next to the runners (byte-identical to the CTF)."""
    with open(SANDBOX_TRUST, encoding="utf-8") as fh:
        trust_text = fh.read()
    with open(os.path.join(HERE, "trusted_issuers.json"), "w", encoding="utf-8") as fh:
        fh.write(trust_text)


def write_cases() -> None:
    with open(os.path.join(VEC, "cases.json"), "w", encoding="utf-8") as fh:
        json.dump(CASES, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def main() -> None:
    os.makedirs(VEC, exist_ok=True)
    gen_coverage()
    gen_boundary()
    gen_probes()
    write_trust()
    write_cases()
    print(f"[round0] wrote {len(CASES)} vectors to {VEC}")
    for c in CASES:
        tag = "probe" if not c["scored"] else c["class"]
        extra = ""
        if c["now"] != NOW_DEFAULT:
            extra += f" now={c['now']}"
        if c["consumed"]:
            extra += f" consumed={c['consumed']}"
        print(f"  {c['file']:<42} [{tag}]{extra}")


if __name__ == "__main__":
    main()
