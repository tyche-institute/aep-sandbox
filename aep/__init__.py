"""aep — a small, self-contained reference toolkit for Action Evidence Packages (AEP).

Three layers, deliberately stacked weakest-first so you can see what each one buys:

  * ledger   — an *unsigned* sha256 hash-chain of action receipts (integrity only).
               Catches a single edited field; does NOT survive a full re-chain forge.
  * mandate  — an Ed25519 *signed*, scope-bound, one-shot Action Mandate (the
               "who said the agent could do that" layer). Issuer -> principal ->
               mandate(action_hash + scope) -> agent.
  * package  — a governed AEP that folds a signed mandate into a signed receipt,
               so "exceed the mandate" and "forge the evidence" both fail at verify.

This is a *reference implementation of the primitive*, not a product. It exists to be
attacked: see ../THREAT-MODEL.md and ../attacks/.
"""

__version__ = "1.0.0"
