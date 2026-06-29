# Threat model & rules of engagement

## What this is

`aep-sandbox` is an intentionally minimal, intentionally attackable reference for agent
action-evidence and mandate enforcement. It is meant to make a clear claim and let you test
it: **an agent's evidence package should let an outside party verify what it did and whether
it was allowed — without trusting the agent.**

## Authorised use

This is a target for education and for testing systems **you own or are explicitly authorised
to test**. Do not use it, or techniques learned here, against systems you do not control.
Within a research group, run it against your own deployments. Nothing here phones home, needs
the network (except the optional Docker base-image pull for the TPM demo), or touches real
identities, keys, or money.

## The attack levers and what verify.py should do

| Lever | Attack | Verifier verdict | Why |
|---|---|---|---|
| Tamper | edit a field, leave the hashes | `DENY:content_mutated` | receipt_hash is recomputed over the body |
| Re-chain forge (Layer 1) | rewrite + recompute the whole hash-chain | **ALLOW (undetected)** | a bare hash-chain has no key; this is the lesson |
| Re-chain forge (Layer 2) | same trick on the signed AEP | `DENY:aep_sig_invalid` | you cannot re-sign without the agent key |
| Forge whole package | mint a self-consistent AEP with your own keys | `DENY:issuer_not_listed` | the trust anchor, not the math, stops you |
| Swap mandate | splice a broader mandate into a real AEP | `DENY:aep_sig_invalid` | the agent signed the mandate into the receipt |
| Exceed scope | valid signature, action outside the grant | `DENY:scope_violation` | the principal's scope is enforced at verify |
| Replay | re-submit an ALLOWed package | `DENY:replayed` | per-AEP one-shot nonce (verifier `--consume`) |
| Strip / blank signature | zero the agent signature | `DENY:aep_sig_invalid` | a wrong signature is not a missing check |

The CTF win is to make the verifier **ALLOW** an out-of-scope or otherwise unauthorised
action. If you achieve that, you have found a real bug — please report it (see below).

## What each layer does NOT defend (by design)

- **Layer 1 (ledger) has no signature and no external anchor.** A writer of the file forges
  the whole history undetectably. It is shipped to demonstrate exactly that gap. Do not treat
  a hash-chain as tamper-*proof*; it is tamper-*evident only against editors who cannot
  recompute it*.
- **The attester is trusted for its own measurements.** Layer 2 hashes the action and outcome
  the agent reports; it cannot independently confirm the agent truly did what it claims. That
  binding to ground truth is what Layer 3 (TPM) and a real RATS/Veraison verifier add.
- **Layer 3 uses an emulated TPM (swtpm), not hardware.** It demonstrates the *protocol and
  the output-binding*, not a hardware root-of-trust guarantee. Conclusions about real,
  unmodified-hardware attestation do not follow from an emulated attester.
- **Key compromise is out of scope.** If you hold the issuer, principal, or agent private key,
  you can of course mint accepted packages — that models a compromised authority, not a flaw
  in the scheme. The private keys are git-ignored precisely so the interesting attacks are the
  ones that work *without* them.
- **Revocation / de-listing mid-validity is not implemented.** There is no CRL or short-lived
  re-attestation here; a mandate is valid until `exp`. Real deployments need revocation. This
  is a known, deliberate omission and a good thing to prototype next.

## Relationship to the real verifier

This sandbox is a teaching model. The production-grade signed-`.aep` format and verifier live
in [tyche-institute/eatf](https://github.com/tyche-institute/eatf); the RATS/Veraison
composition (binding an AEP outcome into a hardware-rooted attestation) is described in the
EATF work and the `draft-sokolov-rats-aep-composition` Internet-Draft. The Layer-1/Layer-2
split here exists to make the difference between *integrity* and *authorisation* impossible to
miss.

## Responsible disclosure

If you find a way to make `verify.py` ALLOW an action outside the reference mandate (a real
bypass, not a shipped Layer-1 lesson), or any other security-relevant defect, please open an
issue or contact `info@tyche.institute`. This is a research artifact; we want it broken
honestly.
