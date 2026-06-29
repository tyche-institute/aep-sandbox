# AEP output-binding demo (software TPM)

A clean, portable, **one-command** demo of the **output-binding** protocol for an
Action Evidence Package (AEP): it cryptographically ties an AI agent's *outcome*
(not just its boot state) into a TPM-signed attestation quote, and shows a minimal
RATS/Veraison-style appraiser resolving four cases. It runs end-to-end on an
**emulated software TPM (swtpm)** — no hardware needed — so you can demo it on any
laptop with Docker, or natively if you have `swtpm` + `tpm2-tools` installed.

Author: Anton Sokolov, Tyche Institute, Tallinn, Estonia (Researcher).
This packages a verified attestation-feasibility experiment for hands-on demoing.

---

## Run it

```bash
./demo.sh            # auto: runs natively if swtpm+tpm2_startup are on PATH, else uses Docker
./demo.sh --native   # force native (needs swtpm + tpm2-tools + openssl on PATH)
./demo.sh --docker   # force the container path (needs Docker; first build pulls a base image)
```

That's the whole demo. It writes its artefacts next to the script
(`results.json`, `run.log`, `reference-pcrs.txt`, `golden.pcrs`, `aep.json`) and
prints the four verdicts at the end.

**Native requirements:** `swtpm`, `tpm2-tools` (`tpm2_startup`/`quote`/`checkquote`/
`pcrextend`/`createek`/`createak`/`pcrread`/`evictcontrol`/`flushcontext`), `openssl`,
and `sha256sum`/`cmp` (coreutils). `jq` is optional (used only to pretty-print verdicts).

**Docker path:** `./demo.sh --docker` builds the image from the bundled `Dockerfile`
(`debian:bookworm-slim` + `swtpm`/`swtpm-tools`/`tpm2-tools`/`openssl`) and runs the
same script inside a container, mounting this directory so `results.json` lands back on
the host. The first build needs network access to pull the base image and apt packages.

You can also build/run the image by hand:

```bash
docker build -t tyche-aep-demo .
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/demo" tyche-aep-demo /demo
```

---

## What it proves — the architecture

The idea: a normal TPM attestation proves *what booted*. Here we additionally bind
*what the agent did* into the same signed evidence, so a verifier can tell apart a
genuine, fresh, correctly-attributed outcome from a tampered platform, a replayed
quote, or a forged outcome.

**1. PCR3 = the model-artefact measurement.** During the simulated measured boot the
script extends PCR 0–2 with firmware/bootloader/kernel and **PCR 3 with the model
artefact's digest**. So the *model version in use* becomes part of the attested
platform state — swap the model after boot and PCR3 diverges from the reference.

**2. Output-binding = `H(outcome) || nonce` in the quote's qualifying data.** The AEP
records the agent's action and its `outcome_digest`. The appraiser issues a **fresh
nonce**; the attester computes `qualifying_data = H( H(AEP outcome) : nonce )` and folds
it into the **qualifying data of an AK-signed TPM quote**. Because the quote is signed
over both the PCR set *and* this qualifying data, you cannot change the outcome, reuse an
old quote, or perturb the platform without breaking the signature or the PCR match.

**3. The appraiser** is a minimal stand-in for a RATS Verifier (RFC 9334): it runs
`tpm2_checkquote` (signature + qualifying-data/freshness check) and compares the quoted
PCRs against a golden reference. It is **not** a full Verifier — see caveats.

### The four verdicts and what each proves

| Case | Condition | Verdict | What it demonstrates |
|---|---|---|---|
| **A** | good platform, fresh nonce | **Attested** | signature ✓ and PCRs match reference → a genuine, fresh, correctly-bound outcome |
| **B** | PCR3 perturbed (model swapped after boot) | **Contested** | signature ✓ but PCRs diverge → the *platform/model* changed; the outcome is no longer trustworthy |
| **C** | run-A's quote replayed under a new challenge | **Expired** | freshness check fails → replay/stale evidence is caught by the nonce |
| **binding** | forged AEP outcome under run-A's quote | **rejected** | `tpm2_checkquote` fails → you cannot swap the outcome without invalidating the quote (this is the core output-binding claim) |

The two platform verdicts (Attested / Contested / Expired) line up with the two-axis
verdict model in the companion IETF Internet-Draft
(`draft-sokolov-rats-aep-composition-00`), where AEP application-layer Evidence is
appraised alongside platform Evidence and mapped onto AR4SI/EAR. That draft is an
**individual submission — not WG-adopted**.

---

## Verified output (reference run)

Reproduced on this box (swtpm 0.7.3 / tpm2-tools 5.6); identical verdicts and AEP digest
when re-run, and identical inside the container (swtpm 0.7.1 / tpm2-tools 5.4):

```
AEP digest          = b80c48d9115da3ed8d388f670af5d713cfd990d6743c77094495fcabe3e59d89
RUN A  sig=yes pcrs=match     -> VERDICT: Attested
RUN B  sig=yes pcrs=diverged  -> VERDICT: Contested   (PCR3 model-artefact swapped)
RUN C  sig=no  (freshness)    -> VERDICT: Expired     (run A quote replayed under a new challenge)
BIND   forged AEP outcome under run-A quote: checkquote=no -> rejected
```

`results.json` (machine-readable summary written by the run):

```json
{
  "aep_digest": "b80c48d9115da3ed8d388f670af5d713cfd990d6743c77094495fcabe3e59d89",
  "verdicts": {
    "run_A_good_fresh": "Attested",
    "run_B_perturbed_pcr3": "Contested",
    "run_C_replayed_quote": "Expired"
  },
  "output_binding_forged_aep": "rejected"
}
```

The AEP digest above is the digest of the synthetic `aep.json` the pipeline generates.
The bundled **`demo.aep.json`** is a separate, richer neutral demo AEP (EAT profile
`https://eatf.eu/aep/v1`, a policy-compliance-review action) to show the AEP *shape* an
audience would see; its own `_output_binding_note` explains how `H(outcome) || nonce`
folds into the quote. The pipeline does not depend on `demo.aep.json` — it is bundled for
the walkthrough.

---

## Honest scope / caveats

- **Emulated swtpm is not a hardware guarantee.** This demonstrates the *protocol and the
  binding* on a **software TPM (swtpm), not a hardware root of trust**. You cannot draw
  conclusions about real unmodified-hardware guarantees from an emulated Attester.
- **The appraiser is a minimal RATS-Verifier stand-in.** It performs the signature +
  freshness check and the reference-value comparison a Verifier performs; it does **not**
  implement endorsement chains, CoRIM reference values, or AR4SI/EAR result
  serialization. The next step is a **real Verifier (Veraison)** appraising this evidence
  (OVERT-inspired, not conformant), with a real TPM/TEE and a measured model artefact.
- **Synthetic semantics.** The AEP exercises the binding mechanics, not real agent
  behaviour.
- These four behaviours are the load-bearing feasibility claims. A hardware-rooted study
  (real TPM/TEE, full Veraison appraisal, measured model artefact) is the next step. The
  associated IEEE write-ups are **under review**.

---

## Files

| File | Purpose |
|---|---|
| `demo.sh` | one-command launcher (native if possible, else Docker) |
| `run_pipeline.sh` | the self-contained pipeline (spins up swtpm, runs the four cases) |
| `Dockerfile` | `debian:bookworm-slim` + swtpm/tpm2-tools/openssl; ENTRYPOINT runs the pipeline |
| `demo.aep.json` | a neutral demo AEP (EAT profile `https://eatf.eu/aep/v1`) for the walkthrough |
| `README.md` | this file |

References: RATS architecture (RFC 9334), TPM remote attestation. AR4SI / EAR / CMW /
CoRIM / CoSERV / multi-verifier are cited as Internet-Drafts.
