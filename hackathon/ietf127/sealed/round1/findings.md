# Round 1 - reference findings (SEALED until the round closes)

Three readings per vector: the Tyche Python reference (aep-sandbox origin/main), the
Tyche JavaScript port (tyche-institute-site origin/main, verify.mjs) - same owner, one
party - and the verdict derived from VERIFIER-SPEC-v1 text alone. A vector has an
assigned value only where all three agree.

Vectors: 22. Scored: 18. Without an assigned value: 3. Scored-intent vectors that lost their score: 0.

## r1-05.aep.json (probe, slug probe-duplicate-nonce-member)

- Python: `ALLOW`
- JavaScript: `ALLOW`
- Spec reading: `UNDEFINED` (s1 (a JSON object) and s2: the specification does not say how a duplicate member name is treated)
- Design: raw text carries the top-level nonce member twice: first a consumed decoy, then the signed value. Last-wins parsers: ALLOW; first-wins: content_mutated (hash over the decoy); a parser that rejects duplicates may say malformed_aep
- Canonical receipt-core bytes are identical.

## r1-09.aep.json (probe, slug probe-nonascii-key-order)

- Python: `ALLOW`
- JavaScript: `DENY:content_mutated`
- Spec reading: `UNDEFINED` (s2 ('object keys sorted': the sort order is not defined))
- Design: action.context member names U+FF34.. (fullwidth 'Tag') and U+1F4CE: code point / UTF-8 byte order puts U+FF34 first (Python signer); UTF-16 code unit order (JS sort) puts the emoji first -> different canonical bytes -> JS content_mutated
- Canonical receipt-core bytes differ at character 103:

```text
python: e-intl"},"context":{"channel":"portal","Ｔａｇ":"priorité","📎":"attachment-2"},"met
js    : e-intl"},"context":{"channel":"portal","📎":"attachment-2","Ｔａｇ":"priorité"},"met
```

## r1-15.aep.json (probe, slug probe-float-100-point-0)

- Python: `ALLOW`
- JavaScript: `DENY:content_mutated`
- Spec reading: `UNDEFINED` (s2 Numbers (non-integer number: outside the profile under a lexical reading; the spec does not define the verdict))
- Design: args.amount written as 100.0; Python signs over '100.0', JS re-serialises 100 -> content_mutated in JS, ALLOW in Python
- Canonical receipt-core bytes differ at character 31:

```text
python: {"action":{"args":{"amount":100.0,"from":"EUR","to":"USD"},"context":{"
js    : {"action":{"args":{"amount":100,"from":"EUR","to":"USD"},"context":{"de
```

---

## Observations outside the corpus (not vectors; candidates for a later round)

Found while building Round 1 with throw-away keys in a scratch directory. No Round 1 vector
carries these shapes. Recorded so that the gap is not lost; nothing was fixed.

| shape (mandate body or action, otherwise valid and signed) | Python reference | JavaScript port | spec text |
|:--|:--|:--|:--|
| `mandate.body.exp: null` | `DENY:malformed_aep` (TypeError in `now > None`, caught by the CLI-style guard) | `DENY:expired` (`null ?? 0`) | s4 5g "a mandate carrying no expiry is treated as expired": a null exp arguably carries no expiry -> `expired`; the Python result is reached only through the exception guard |
| `mandate.body.exp: "200"` (string), now = 50 | `DENY:malformed_aep` (TypeError) | `ALLOW` (JS coerces "200" to 200) | undefined; a non-numeric string exp (for example "abc") would give NaN in JS and also ALLOW: a wrongful-ALLOW risk in the port |
| `action.args.amount: null` under a cap | `ALLOW` (null treated as absent) | `ALLOW` | s4 5f "an amount present in the action arguments must be numeric": a member present with value null is arguably present and not numeric -> `scope_violation`. Spec reading and both references disagree |

All three are inside the integer-only profile (they contain no out-of-profile number), so a
future round could score them only after the specification text says which reading holds.
That needs VERIFIER-SPEC-v2; v1 is frozen.

## Notes on the 3 vectors above

- r1-05 (duplicate member): both references agree (last value wins), but the specification
  says nothing about duplicate member names, so there is no assigned value. RFC 8259 says
  names "SHOULD be unique" and that behaviour with duplicates is unpredictable.
- r1-09 (non-ASCII member names): a real reference divergence inside the integer-only
  profile. "object keys sorted" in s2 does not say by what. Python sorts by code point (the
  same order as UTF-8 bytes); JavaScript `Array.prototype.sort` compares UTF-16 code units.
  The two orders differ whenever a BMP character at or above U+E000 meets a character outside
  the BMP. This is a new finding of the same family as Round 0 Finding 001 (canonical form
  is not fully pinned down), but it concerns strings, not numbers, so the integer-only
  profile does not protect against it.
- r1-15 (`100.0`): outside the profile under a lexical reading ("integer" = the JSON text has
  no fraction or exponent). Under a value reading (100.0 is the integer 100) it would be
  inside the profile, and then the Python signer's canonical text "100.0" would contradict
  the JavaScript text "100". The spec does not define the verdict either way.

No scored-intent vector lost its score: on all 18 scored vectors the Python reference, the
JavaScript port and the spec-text reading agree.
