# Round 1 results

Published on 23 November 2026. Round 1 closed on Sunday 22 November 2026 at 23:59 UTC.
The rules are in `../../round1/RULES.md`; the key and the Tyche verdict files are in
`../../sealed/round1/`.

2 returns arrived before the round closed. Each sender has reviewed the report on their own
return and found nothing wrong in it (rules, section 8). Returns appear under codes. The
names below are given with the written consent of each person named. This table is not a
ranking, and it does not compare participants.

## Returns

| return | label | written by | exact matches on the 18 scored vectors | Wilson 95 % interval |
|:--|:--|:--|:--|:--|
| R1-01 | non-author | Kenny Wang (CIRWEL). In the participant's words: "Designed and directed by Kenny Wang. Code written by an AI model (Claude) and independently cross-checked by two other AI model families (Gemini, Codex). No human code review." | 18 of 18 | 82.4 % to 100.0 % |
| R1-02 | non-author | Muntaser Syed; code and method reviewed by Katherine Burge | 18 of 18 | 82.4 % to 100.0 % |

An exact match means the verdict and the reason both equal the key. Both senders state that
they did not read or run a Tyche verifier before the return, so no row carries a note
(rules, sections 4 and 9). We cannot check that statement, and we did not try to. Both
verifiers are written in Python with the `cryptography` package for Ed25519.

## Verdicts per vector

No vector was answered differently by the 2 returns. No return differs from the key on a
scored vector. The last 2 columns are the Tyche rows, one party: the Python verifier
(label: author) and its JavaScript port (label: same-owner), from `../../sealed/round1/`.

| vector | scored | key | R1-01 | R1-02 | Tyche Python | Tyche JavaScript |
|:--|:--|:--|:--|:--|:--|:--|
| r1-01 | no | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| r1-02 | yes | DENY:expired | DENY:expired | DENY:expired | DENY:expired | DENY:expired |
| r1-03 | yes | DENY:measurement_mismatch | DENY:measurement_mismatch | DENY:measurement_mismatch | DENY:measurement_mismatch | DENY:measurement_mismatch |
| r1-04 | yes | DENY:issuer_not_listed | DENY:issuer_not_listed | DENY:issuer_not_listed | DENY:issuer_not_listed | DENY:issuer_not_listed |
| r1-05 | no | (no key value) | ALLOW | ALLOW | ALLOW | ALLOW |
| r1-06 | yes | DENY:content_mutated | DENY:content_mutated | DENY:content_mutated | DENY:content_mutated | DENY:content_mutated |
| r1-07 | yes | DENY:replayed | DENY:replayed | DENY:replayed | DENY:replayed | DENY:replayed |
| r1-08 | yes | DENY:principal_sig_invalid | DENY:principal_sig_invalid | DENY:principal_sig_invalid | DENY:principal_sig_invalid | DENY:principal_sig_invalid |
| r1-09 | no | (no key value) | ALLOW | ALLOW | ALLOW | DENY:content_mutated |
| r1-10 | yes | DENY:scope_violation | DENY:scope_violation | DENY:scope_violation | DENY:scope_violation | DENY:scope_violation |
| r1-11 | yes | DENY:agent_binding_mismatch | DENY:agent_binding_mismatch | DENY:agent_binding_mismatch | DENY:agent_binding_mismatch | DENY:agent_binding_mismatch |
| r1-12 | yes | DENY:aep_sig_invalid | DENY:aep_sig_invalid | DENY:aep_sig_invalid | DENY:aep_sig_invalid | DENY:aep_sig_invalid |
| r1-13 | yes | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| r1-14 | yes | DENY:expired | DENY:expired | DENY:expired | DENY:expired | DENY:expired |
| r1-15 | no | (no key value) | ALLOW | ALLOW | ALLOW | DENY:content_mutated |
| r1-16 | yes | DENY:credential_sig_invalid | DENY:credential_sig_invalid | DENY:credential_sig_invalid | DENY:credential_sig_invalid | DENY:credential_sig_invalid |
| r1-17 | yes | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| r1-18 | yes | DENY:malformed_aep | DENY:malformed_aep | DENY:malformed_aep | DENY:malformed_aep | DENY:malformed_aep |
| r1-19 | yes | DENY:malformed_mandate | DENY:malformed_mandate | DENY:malformed_mandate | DENY:malformed_mandate | DENY:malformed_mandate |
| r1-20 | yes | DENY:scope_violation | DENY:scope_violation | DENY:scope_violation | DENY:scope_violation | DENY:scope_violation |
| r1-21 | yes | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| r1-22 | yes | DENY:credential_sig_invalid | DENY:credential_sig_invalid | DENY:credential_sig_invalid | DENY:credential_sig_invalid | DENY:credential_sig_invalid |

4 vectors are unscored. r1-01 has a key value and carries integers at exactly plus and
minus (2^53 - 1). r1-05, r1-09 and r1-15 have no key value: the specification leaves their
verdict open (`../../sealed/round1/findings.md`). On r1-09 and r1-15 both returns answer as
the Tyche Python verifier does, and the Tyche JavaScript port answers
`DENY:content_mutated`.

## What the table supports

2 verifiers written outside Tyche Institute from the text of VERIFIER-SPEC-v1 agree with
the key on 18 of 18 scored vectors. With 18 vectors the interval is wide. Both senders had
the Round 0 practice set with its published expectations. Both verifiers are in Python, as
the Tyche verifier that signed the vectors is; on the 3 open vectors the answer follows the
language's JSON handling. The result is agreement on these 22 vectors. It is not a
statement about the specification as a whole, and it is not a certification of any
implementation.

To reproduce a score from a return file (run in `hackathon/ietf127/`):

```sh
python3 tools/score.py your-return.json --key sealed/round1/expected.json
```

## What the returns found in the specification

Both senders wrote down each place where the text made them choose a reading.
`QUESTIONS-TO-SPEC-v1.md` in this directory lists those places. The notes on r1-05, r1-09
and r1-15 in return R1-01 are by Kenny Wang (CIRWEL).

## Not published

The return files, the letters of the senders and their addresses stay private.
