# Round 1 rules: AEP verifier verdicts, sealed

These rules are fixed before the round opens. If a vector, the answer key (below: the key)
or these rules must change, Round 1 ends and a new round opens with a new commitment. Round 1
and its commitment stay published.

Round 1 is an open comparison of verifier verdicts. It is not an accredited scheme and it
certifies nothing.

## 1. What is measured

Round 1 measures whether a verifier written from `VERIFIER-SPEC-v1.md` reaches the same
verdicts as the sealed key on 22 Action Evidence Package (AEP) test vectors.

Agreement is "agreement under VERIFIER-SPEC-v1, a Tyche sandbox specification, not an IETF
draft". The vocabulary comes from draft-sokolov-rats-aep-composition-06, an individual
Internet-Draft. That draft leaves the encoding profile open. This sandbox format is one
instantiation, used for testing.

## 2. What a participant does

1. Take `vectors/r1-*.aep.json`, the run inputs in `vectors/cases.json` (`file`, `now`,
   `consumed`) and the trust anchor list `trusted_issuers.json`.
2. Run your own verifier on every vector with that vector's `now` and `consumed`.
3. Return one JSON array of `{file, verdict, reason}`. `verdict` is `ALLOW` or `DENY`. On
   `ALLOW`, `reason` is `null`. On `DENY`, `reason` is one word from the vocabulary in
   section 3. Return a verdict for every vector.
4. Send the return to the address on tyche.institute, or hand it to the Tyche table at the
   IETF 127 Hackathon.

With the return, please state: the specification version you read; whether you read or ran
any Tyche verifier first; who reviewed your code, if anyone; and whether we may name you.

## 3. Reason vocabulary and check order

The 12 reasons are: `malformed_aep`, `content_mutated`, `aep_sig_invalid`,
`measurement_mismatch`, `malformed_mandate`, `issuer_not_listed`,
`credential_sig_invalid`, `principal_sig_invalid`, `agent_binding_mismatch`,
`scope_violation`, `expired`, `replayed`.

Section 4 of the specification is the normative text for the order of the checks. This
summary is not. In short: structure, chain integrity, package signature, measurements,
mandate chain (body shape, issuer listing, credential signature, principal signature, agent
binding, scope, expiry), replay. The first check that fails gives the reason. Some vectors
carry more than one defect, so the order matters.

A return that uses a reason outside the 12 words is refused by the scoring tool and is not
scored.

## 4. Clean-room rule

Section 6 of the specification describes a clean-room lane. Build from VERIFIER-SPEC-v1 and
the vectors. Do not run or read the Tyche verifiers before you return. Tyche Institute
publishes 2: a Python verifier in the aep-sandbox repository and a JavaScript port on
tyche.institute. A copy of the port is in this pack, at `../onebyte/vendor/site/verify.mjs`.
`../onebyte/` and `../tools/explain.py` run these verifiers. Leave both until you have sent
your return.

This is an honour rule. We cannot check it, and we do not try to. A return made by running
our code is still welcome. Tell us. It carries the label of the Tyche verifier that was run
(section 9). Such a return measures our own code, not the specification.

## 5. The sealed key and its commitment

The key is `expected.json`. For each vector it gives the class, whether the vector is
scored, the verdict, the reason and the clause of the specification that decides it.

The SHA-256 of the key is fixed here, and in line 1 of `../SEAL.sha256`:

```
38a07c9e8c91e15a99737cad9ec5e93397cbb3a1e05f3c22984f58be0a581745
```

The key, the generator and the 3 Tyche verdict files (Python verifier, JavaScript port,
reading of the text) stay withheld until the round closes. We publish them in this pack by Sunday 29 November 2026. Anyone can then check
that the SHA-256 of the released key equals the commitment above. The time-stamp tokens in
`../timestamps/` show a time at which `../SEAL.sha256` already existed. So the key was fixed
by that time. It cannot have been changed later to fit a return.

The commitment fixes the key. It does not hide it: the Tyche verifiers named in section 4
compute the scored values. A participant who keeps the clean-room rule does not see them.

The round closes on Sunday 22 November 2026 at 23:59 UTC (Coordinated Universal Time).

## 6. How the key was made

A vector has an assigned value when 3 readings agree. They are the Tyche Python verifier,
the Tyche JavaScript port, and a reading of the specification text made at Tyche Institute.
All 3 come from one owner. The key rests on no outside reading.

Where the 3 do not agree, the vector stays in the corpus and is unscored. A findings file,
published with the key, describes it. We do not edit a verifier to make a reading agree, and
we do not drop a vector.

Some vectors are unscored by design. They test behaviour that the specification leaves open.
Which vectors these are is part of the sealed key. A careful reader may spot some of them.
An unscored vector still asks for a verdict, like every other vector.

## 7. Scoring

- Scored population: the vectors marked scored in the key.
- Score: exact match of both `verdict` and `reason`. A right `ALLOW` or `DENY` with the
  wrong reason does not match.
- We also report verdict-only matches, next to the count that a return of `DENY` for every
  vector would get.
- Each sender gets the report for their own return: k of n exact matches, a Wilson 95 %
  interval for k of n, a per-reason confusion table, the mismatches and the vectors not
  returned.
- Unscored vectors are reported for interest. They do not enter k or n.
- The tool is `../tools/score.py`. It scores one return at a time.

## 8. No ranking, coded returns, consent

- Before scoring, we replace the sender's name on every return with a code. The scoring tool
  reads the coded file only, and it is deterministic: the score does not depend on who sent
  the return.
- We publish no ranking of participants and no comparison between named participants.
- A name appears next to a result only with the written consent of the person named.
- We publish results as a table of verdicts per vector: which vectors were answered
  differently, by how many returns, and how. Returns appear under codes.
- We publish no result about a return before its sender has reviewed it.

## 9. Implementation labels

Every row of any table we publish carries one of 4 labels:

| label | meaning |
|:--|:--|
| author | written by Tyche Institute, which wrote the specification and the vectors |
| same-owner | a second or later implementation by an owner who already has a row; the first row keeps its own label |
| co-author | written by someone who co-authors a related Internet-Draft with a Tyche Institute researcher |
| non-author | none of the above |

The Tyche Python verifier (author) and the Tyche JavaScript port (same-owner) count as one
party. The JavaScript side is a port of the Python verifier.

A return made by running a Tyche verifier carries the label of that verifier. A verifier
written after its writer read or ran a Tyche verifier keeps its own label, and we add a note
to its row: "read Tyche code first" or "ran Tyche code first".

## 10. Round 0 is the practice set

Round 0 is the open practice set: its expected verdicts are published in its `cases.json`.
It is in the public aep-sandbox repository of Tyche Institute, directory `interlab/round0`.
That repository also holds the Tyche Python verifier (`verify.py`, `aep/`) and the Round 0
runners (`run_reference.py`, `run_port.mjs`, `compare.py`). Before your Round 1 return, use
only `interlab/round0/vectors/` and `interlab/round0/trusted_issuers.json`. Do not open or
run the rest. Use Round 0 to debug. `../tools/score.py --round0-open` scores a return against it. A Round 0
score is not a blind result.

## 11. Integrity of the files

`MANIFEST.sha256` lists the SHA-256 of every other file in this directory, and of no file
outside it. From this directory, `sha256sum -c MANIFEST.sha256` must report `OK` for every
line. `make_manifest.py` is the script we used to write the manifest. Do not run it to check
the files: it overwrites the manifest.

## 12. Minimum round

We want at least 3 non-author returns. If we do not reach that number by the closing date,
we publish the count we reached. We present no result as more than it is.

## 13. Disagreeing with us is useful

If your verifier disagrees with the key on a vector, tell us why. A disagreement may show
a gap in the specification or a defect in our verifiers. We publish such a finding only
after the sender has reviewed it, and without the sender's name unless the sender consents
in writing.
