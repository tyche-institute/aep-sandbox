# Questions to VERIFIER-SPEC-v1 from the Round 1 returns

Published on 23 November 2026. Source: the notes each sender wrote with the return, and
nothing else. Returns are cited by the codes of `RESULTS.md`. VERIFIER-SPEC-v1 is frozen,
so we do not edit it; these are inputs to a version 2.

"Named by" says which return wrote the place down. A return that does not name a place
may still have taken the same reading. Wherever both returns name a place, they took the
same reading. Both name the same 3 vectors as depending on behaviour the text leaves open.

## A. Canonical form (section 2)

| # | Where the text is silent | Reading taken | Named by | Decides a Round 1 vector? |
|:--|:--|:--|:--|:--|
| A1 | "object keys sorted": sorted by what? | Unicode code point. UTF-16 code unit order (the ECMAScript default, and the order of RFC 8785) gives other bytes when a character from U+E000 to U+FFFF meets one outside the Basic Multilingual Plane | R1-01, R1-02 | r1-09 |
| A2 | Duplicate member names | the parser keeps the last value; keeping the first and rejecting the file are the other 2 behaviours | R1-01, R1-02 | r1-05 |
| A3 | A number spelled as a decimal with an integer value (100.0): is it inside the integer-only profile, and what is the verdict outside it? | kept as written (Python rendering); not rejected | R1-01, R1-02 | r1-15 |
| A4 | Digest of action and of outcome for the measurements | SHA-256, lowercase hex, of the canonical form | R1-02 | no |

## B. Names and signed bytes

| # | Where the text is silent | Reading taken | Named by |
|:--|:--|:--|:--|
| B1 | Member names: `body` and `sig` inside credential and mandate, `issuer_id`, `issuer_pub`, `principal_id`, `principal_pub`, `agent_id`, `scope.allowed_methods`, `scope.max_amount`, `exp`, `action.method`, `action.args.amount`; keys, signatures and digests as hex strings | read off the vectors | R1-02; R1-01 for `issuer_pub` (check 5b) |
| B2 | Signed bytes of `credential.sig` and `mandate.sig` (the text names them only for `aep_sig`) | canonical form of the respective `body`; R1-02 adds: the mandate is verified with the credential's principal key | R1-01, R1-02 |

## C. Absent or wrongly typed members (no Round 1 vector exercises these)

| # | Shape | Reading taken | Named by |
|:--|:--|:--|:--|
| C1 | `measurements` absent | no digests claimed, so `measurement_mismatch` (as Round 0 vector r0-04) | R1-01, R1-02 |
| C2 | `exp` not numeric | `expired` | R1-01, R1-02 |
| C3 | `agent_id` absent from both the mandate and the package | the 2 compare equal; check 5e passes | R1-01, R1-02 |
| C4 | `scope` is not an object | no scope constraint applied | R1-02 |
| C5 | `allowed_methods` is a single string | treated as a one-item list | R1-02 |
| C6 | `max_amount` not numeric | the amount check is skipped; the sender notes that this reading fails open | R1-02 |
| C7 | the action has no `method`, and the scope lists methods | outside the scope | R1-01 |
| C8 | the amount is a boolean; there is no `args` object | a boolean is not numeric; no `args` means no amount is present | R1-01 |
| C9 | the file does not parse as JSON | `malformed_aep` | R1-02 |
| C10 | nonce comparison for replay (check 6) | by value and type | R1-01 |

In return R1-02, C3 to C6 are recorded as comments from the review by Katherine Burge.

## D. Our own observations

`../../sealed/round1/findings.md`, section "Observations outside the corpus": `exp: null`,
`exp: "200"` and `amount: null`. C2 and C6 touch the same ground from outside.

## What a version 2 would have to say

1. The sort order of member names (A1) and the treatment of duplicates (A2).
2. Whether the profile is lexical or by value, and the verdict outside it (A3).
3. The member names and the signed bytes of all 3 signatures (B1, B2), and the digest of
   the measurements (A4).
4. One verdict for each shape in part C; C6 first, because the reading taken admits a
   package it should not.
