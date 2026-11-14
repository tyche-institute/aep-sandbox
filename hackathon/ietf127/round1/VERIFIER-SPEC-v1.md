# AEP verifier — behavioural specification, frozen v1

This document states the verifier's required behaviour in prose, so that an implementation can
be written **from the specification alone**, without reading either reference implementation.
It exists for the clean-room lane of the Tyche Labs interlaboratory comparison: a second
implementer who has read only this file, and who can attest to that, produces a genuinely
independent result. Reading the reference source and then writing a verifier is a port, not an
independent implementation, and the two must never be reported as if they were the same thing.

Frozen 2026-08-24. Any change opens v2 and does not alter v1.

## 1. Object under verification

An Action Evidence Package (AEP) is a JSON object. It carries an action, the mandate and
credential that authorise it, the agent's public key, a nonce, a signature over the package,
and a hash over the package's own core.

## 2. Canonical form

All hashing and signing is over **canonical JSON**: object keys sorted, no insignificant
whitespace, the compact separators `,` and `:`, and non-ASCII characters emitted literally
rather than escaped.

⚠ **Numbers.** Implementations of canonical JSON do not agree on how to render every number;
see Finding 001. In this specification the signed payload carries only **integers within
±(2⁵³−1)**. A package containing a non-integer number, or an integer outside that range, is
outside the profile; a verifier may reject it, and this specification does not define which
verdict such a package receives.

## 3. Receipt core

The **receipt core** is the package with the fields `aep_sig` and `receipt_hash` removed.
Everything else, including `measurements`, is inside it and therefore inside the signature.

## 4. Ordered checks

A verifier returns `ALLOW`, or `DENY` with a reason. It **must** evaluate the guarantees in the
order below and return the reason of the **first** one that fails, because that ordering is
what the assigned values record.

1. **Structure** — the object must be a JSON object carrying `agent_pub`, `action`,
   `credential`, `mandate`, `nonce`, `aep_sig`, `receipt_hash`; `action`, `credential` and
   `mandate` must themselves be objects; `measurements`, if present, must be an object.
   Otherwise → `malformed_aep`.
2. **Chain integrity** — `receipt_hash` must equal the SHA-256, in lowercase hex, of the
   canonical form of the receipt core. Otherwise → `content_mutated`.
3. **Package signature** — `aep_sig` must be a valid Ed25519 signature by `agent_pub` over the
   canonical form of the receipt core. Otherwise → `aep_sig_invalid`.
4. **Measurements** — `measurements.action_sha256` must equal the digest of `action`, and
   `measurements.outcome_sha256` the digest of `outcome` (an absent `outcome` digests as the
   empty object). Otherwise → `measurement_mismatch`.
5. **Mandate chain**, in this order:
   a. `credential.body` and `mandate.body` must be objects → else `malformed_mandate`.
   b. The credential's issuer must appear in the trust anchor list with exactly the public key
      the credential carries → else `issuer_not_listed`.
   c. The credential body must carry a valid signature by that issuer key → else
      `credential_sig_invalid`.
   d. The mandate's principal must match the credential's principal, and the mandate body must
      carry a valid signature by the credential's principal key → else `principal_sig_invalid`.
   e. The mandate must name this agent: both its agent public key and its agent identifier must
      match the package → else `agent_binding_mismatch`.
   f. The action must fall inside the mandate's scope: if the scope lists allowed methods, the
      action's method must be among them; if the scope sets a maximum amount, an amount present
      in the action arguments must be numeric and not exceed it → else `scope_violation`.
   g. The current time must not be **after** the mandate's expiry; a mandate carrying no expiry
      is treated as expired → else `expired`.
6. **Replay** — the nonce must not be in the set of consumed nonces → else `replayed`.

If every check passes, the verdict is `ALLOW` with no reason.

## 5. Notes an implementer will want

- Comparison at step 5g is strict: equality of the current time and the expiry is **not**
  expired.
- Nonce comparison is by value and type; a numeric nonce and the string of the same digits are
  different values. This is observed behaviour in both references, recorded rather than
  endorsed.
- Step 4 is only reachable for a package whose signature already verified, so it constrains a
  signer's own self-consistency rather than protecting against tampering in transit.

## 6. Attestation for the clean-room lane

A clean-room implementer states, in their submission: which version of this document they read,
that they did not read the reference implementations or the assigned values, and who (if
anyone) reviewed their code. We publish that statement alongside their results verbatim.
