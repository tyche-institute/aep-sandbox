# Round-0 rules — Track B (verifier conformance) · DRAFT

Open **interlaboratory comparison** (not, at this stage, an accredited proficiency-testing
scheme — see `notes/tyche-labs/interlab-design-v0.1.md` §"Что делает это credible" and the
ISO/IEC 17043 alignment note). Track B measures whether a participant's AEP (Action Evidence
Package) verifier reproduces the reference verdicts on a fixed, versioned corpus.

These rules are **assigned before the round opens and sealed by hash** (precommit
discipline, as in the RIPE Atlas pilot). Nothing below may change once the commitment is
published; a corrected corpus opens a new round with a new commitment.

---

## 1. What a participant does

1. Pull the Round-0 corpus: `vectors/r0-*.aep.json` + the per-case run parameters in
   `vectors/cases.json` + the trust anchor list `trusted_issuers.json`.
2. For **every** vector, run their own verifier with the case's `now` and `consumed` inputs
   and record a verdict of the form `ALLOW` or `DENY:<reason>`, where `<reason>` is drawn
   from the fixed reason vocabulary (below).
3. Return a single JSON array of `{file, verdict, reason}` — nothing else. Submissions are
   coded (blind): we do not learn which lab produced which return until scoring is complete.

### Fixed reason vocabulary
`malformed_aep`, `content_mutated`, `aep_sig_invalid`, `measurement_mismatch`,
`malformed_mandate`, `issuer_not_listed`, `credential_sig_invalid`, `principal_sig_invalid`,
`agent_binding_mismatch`, `scope_violation`, `expired`, `replayed`. On `ALLOW`, `reason` is
`null`.

The reference appraisal order (first failing guarantee wins) is: **structure → chain
integrity → agent signature → measurements → mandate chain (issuer listing → credential sig
→ principal sig → agent binding → scope → expiry) → replay.** A conformant verifier must
return the reason of the *first* guarantee that fails, because that is what determines the
assigned value.

---

## 2. Assigned values (the ground truth)

The assigned value for a vector is the verdict on which **two independent reference
implementations agree**: the Python reference (`aep-sandbox`, `aep/package.py` +
`aep/mandate.py`) and the JavaScript port (`tyche-institute-site` `verify.mjs`). Both were
run before publication (`run_reference.py`, `run_port.mjs`) and joined by `compare.py`.

- Agreements → `assigned-values.json` (the sealed ground truth).
- **Disagreements between the two references are NOT assigned.** Per the design, a
  reference-vs-reference divergence is a **corpus defect, published as a finding**
  (`findings.md`), never resolved by editing a verifier. Such a vector is excluded from
  scoring until the divergence is fixed upstream, which requires a new round.

### The sealed commitment (precommit)

The Round-0 commitment is the SHA-256 of `assigned-values.json`:

```
c5a5ad400eec0baea85c9edb77e91b79f1122113412195bca3667637cee6e189  assigned-values.json
```

This value is published **before** any participant returns are opened. `MANIFEST.sha256`
seals the whole corpus (every `vectors/*` file + `assigned-values.json`); a participant can
verify their pull with `sha256sum -c MANIFEST.sha256`. The entire corpus is reproducible
from a committed generator (`generate_round0.py`) over the committed trust-anchor keys —
re-running yields byte-identical vectors (Ed25519 is deterministic; every timestamp/nonce is
fixed), so an independent party can rebuild and re-hash without us.

---

## 3. Scoring

- **Scored population:** the 13 vectors whose `class` is `coverage` or `boundary` **and**
  whose `scored` flag is `true` in `assigned-values.json`.
- **Score:** exact match of **both** `verdict` and `reason` against the assigned value.
  A right `ALLOW/DENY` with the wrong reason is **wrong** — the reason is the diagnostic
  content of a conformance verdict and is scored, not just the accept/reject bit.
- **Per-lab metrics:** accuracy = correct / 13; plus a per-reason confusion matrix so a
  systematic mis-ordering (e.g. a verifier that checks scope before signatures) is visible,
  not just a count.
- **Probes are excluded and marked.** The 5 `probe`-class vectors are canonicalisation /
  parser / type-semantics stressors where implementations *may legitimately diverge*; they
  are reported per-lab for interest but do **not** enter the score. Four probes are still
  assigned values (the references agree); the one where the references diverge
  (`r0-15-probe-float-1e-7`) is a published finding, not an assigned value.

---

## 4. Statistics plan (small-ILC)

Minimum viable round: **3 external participants + 2 in-house references** (EA-4/21 INF treats
≤ 7 participants as a *small* interlaboratory comparison; statistics per ISO 13528:2022).

- **Per-vector consensus:** with a categorical (verdict) outcome, the assigned value is the
  reference pair, not a participant consensus; we additionally report the participant
  agreement rate per vector. A vector on which many conformant labs miss identically is a
  signal the vector (or the spec text) is ambiguous → candidate finding for the next round.
- **Per-lab summary:** accuracy with a Wilson 95 % interval on 13 Bernoulli trials
  (exact-match per scored vector). No z-scores / E_n on the verdicts themselves — the
  outcome is categorical, so ISO 13528 §9 quantitative statistics do not apply; we use its
  §7 qualitative/ordinal treatment (evaluation against pre-assigned values with a stated
  decision rule = exact match).
- **Corpus-defect rate:** number of reference divergences / total vectors, published openly
  (Round-0: 1 / 18, all in the probe class). Honesty about corpus defects is a scored
  property of *the scheme*, not of the participants.

---

## 5. Confidentiality & blinding (17043 §4.2 alignment)

- Participants do not receive `assigned-values.json` or `findings.md` until after their
  returns are locked.
- Submissions are coded; the operator scoring the returns does not see lab identities.
- The precommit hash lets any participant confirm, after the fact, that the ground truth was
  fixed before their return — the commitment cannot have been retrofitted to their answers.

---

## 6. Versioning

Round-0 corpus = this directory at the committed revision. A DOI is minted per round. Any
change to a vector, an assigned value, or these rules ends Round-0 and opens Round-1 with a
fresh commitment; the old commitment and its corpus remain published for reproducibility.

---

## Integrity note: our reference implementations are public

Both references are open source — the Python verifier lives in this repository and the
JavaScript port is served from the Tyche Institute site. Running one of them over the
corpus and returning its output is therefore trivially possible, and equally meaningless:
it measures nothing except that our own code agrees with itself.

What this comparison measures is whether an **independently written** verifier reaches the
same verdicts. Participation is a statement that the returned verdicts came from the
participant's own implementation. We cannot enforce that and do not try to; we state it
plainly so that a return which merely echoes our reference is understood as a null result
rather than a passing score.

The ground truth is deliberately absent from this repository: `assigned-values.json` and
the two per-implementation verdict files are withheld until the round closes. What is
published is their commitment — the SHA-256 printed above — which anyone can check against
the values when they are released.
