# Guess ledger

Sealed on 14 November 2026 (UTC), before any return could arrive. The SHA-256 of this file
is line 4 of the public `SEAL.sha256`. We publish the file unchanged after the pack closes,
whether the predictions held or not.

It holds 3 things:

1. what we measured on our own material before the seal (part A);
2. what we predict the returns will show (part B);
3. the places where the builders of this pack recorded a choice between readings of a text
   (part C).

Nothing here is a result of another party. Everything in part A was measured inside Tyche
Institute, so it carries the label author or same-owner.

salt: 17a457ea0258fe0d46c2694390b736a6f8ebdca0d09e80713c528cbeaa7c2b32

The salt is 32 random bytes. With it, the posted hash cannot be used to test guesses of this
file's text.

Short forms used below that the pack README does not list: ASCII (American Standard Code for
Information Interchange), CWT (CBOR Web Token, RFC 8392), JS (JavaScript), RATS (Remote
ATtestation procedureS, an IETF working group), SCITT (Supply Chain Integrity, Transparency
and Trust, an IETF working group), URL (Uniform Resource Locator), UTF-8 and UTF-16 (Unicode
Transformation Formats with 8-bit and 16-bit code units).

## Part A. Measured before the seal

| What | Result | When (UTC, 14 November 2026) |
|:--|:--|:--|
| Round 1: Tyche Python verifier, Tyche JavaScript port and a reading of the specification text, on the 18 scored vectors | 18 of 18 agree | key built 03:18 |
| Round 1: a same-lab clean-room build, written from the specification, the public Round 1 files and the public Round 0 practice set, with no Tyche verifier code read; run once | 18 of 18 scored vectors equal the key | verifier and return written 03:22, scored 04:09 |
| Round 1: the builder's record of the files read for that clean-room build (kept by Tyche Institute, not in this pack) | 0 reads of a Tyche verifier, of the generator or of the key | checked 04:11 |
| Round 1: a surface guess from the vectors, no verifier written | 12 of 18 exact, 17 of 18 verdict-only | guess written 03:58, scored again 04:16 |
| Cell 1: Tyche verifier against the cell-1 key | 12 of 12, outcome and reason | 04:12 |
| Cell 1: a second same-lab reading with different tooling | 12 of 12 outcomes | return written 03:38, compared again 04:16 |
| Cell 2: Tyche verifier against the cell-2 key | 10 of 10, outcome and reason | 04:12 |
| Cell 2: a second same-lab reading with different tooling | 10 of 10 outcomes | return written 03:41, compared again 04:16 |

Times are exact to a few minutes. All of these come from one owner. None is an outside
reading.

The 3 keys were last written at 03:18 (Round 1), 03:15 (cell 1) and 03:32 (cell 2). After 2
internal reviews of the pack we edited this ledger, the public texts and the public scripts,
not the keys and not the vectors. We ran every comparison in the table again at 05:10, after
the last change to a script. For that run we started both Tyche verifiers again on every
vector. The numbers did not change.

## Part B. Predictions

### Round 1 (verifiers of Action Evidence Packages, VERIFIER-SPEC-v1)

- B1. Vector r1-09 has member names outside ASCII. A verifier that sorts member names by
  UTF-16 code unit returns DENY content_mutated. A verifier that sorts by code point, or by
  UTF-8 bytes, returns ALLOW. We predict: if any return written in JavaScript or TypeScript
  arrives, at least 1 of them says DENY content_mutated. Unscored.
- B2. Vector r1-15 carries the amount 100.0. A JSON library that prints it as `100` gives
  DENY content_mutated. One that prints `100.0` gives ALLOW. We ran Python (ALLOW) and
  JavaScript (DENY). We predict the same split in other languages, by how the library prints
  a float with a zero fraction. There are 2 exceptions. A library that keeps the source text
  of a number gives ALLOW. A verifier that rejects numbers outside the profile gives another
  DENY. Unscored.
- B3. Vector r1-05 has the member `nonce` twice. The first value is in the consumed set, the
  last is not. A last-wins parser gives ALLOW, a first-wins parser gives DENY
  content_mutated, a strict parser gives DENY malformed_aep. We predict that most returns
  say ALLOW and that at least 1 return says DENY, with either reason. Unscored.
- B4. Vector r1-01 has integers at the edge of the range, +(2^53 - 1) and -(2^53 - 1). We
  predict ALLOW in every return. Unscored.
- B5. Vector r1-17 is scored ALLOW. It sets 2 traps. Its consumed set holds near copies of
  the nonce: upper case, one character changed, one character appended. And its action
  carries no amount, while the scope sets a maximum. We predict that at least 1 return says
  DENY replayed. DENY scope_violation is the other wrong answer. We predict it is rarer.
- B6. 9 scored vectors carry 2 defects, so the order of the checks decides the reason. We
  predict that among the scored mismatches of non-author returns, a right DENY with a wrong
  reason is more common than a wrong verdict. In our own surface guess (part A, row 4), 5 of
  the 6 misses were of this kind.
- B7. This one is a commitment, not a prediction. A careful build from the text reached 18
  of 18 (part A, row 2). So we treat a scored mismatch in a careful non-author return as a
  finding about the specification or about our key. We do not treat it as an error of the
  participant.
- B8. The specification does not name the members of the credential body and the mandate
  body (issuer identifier, issuer key, scope, allowed methods, maximum amount, expiry). We
  predict that every non-author who sends notes lists this among the places where they had
  to guess.
- B9. We predict 0 to 2 non-author Round 1 returns by Sunday 15 November 2026, 13:30 Pacific
  time. Writing a verifier takes hours, and the room has many projects. We do not know
  whether the round reaches 3 non-author returns by 22 November.

### Cell 1 (one payload, 2 declared encodings)

- B10. Vector c1-01 gives the verifier a held JSON text with a duplicate member name. Our
  verifier refuses the held value: failed. A verifier with a lenient JSON parser says
  verified. We predict that at least 1 return says verified.
- B11. Vectors c1-04 (label 271 with a value the verifier does not implement) and c1-08
  (label 271 absent) are unverified in our key. We predict that returns split on both. A
  verifier that assumes the encoding, or infers it from content type 259, says verified. A
  verifier that treats an unknown or absent declaration as an error says failed. Vector
  c1-06 is failed in our key: its content type 259 does not fit its label 271. A verifier
  that skips that consistency check says verified.
- B12. Vector c1-05 has a bad signature on the JSON side. Both drafts report signature
  validity apart from the content binding. We fold both into one outcome: failed. We
  predict that an implementation built from the drafts reports 2 values here, so the row
  needs a note, not a mismatch.
- B13. Every record is signed with COSE algorithm -8 (EdDSA). A verifier that accepts only
  the fully-specified value -19 rejects all 12. We predict at least 1 question about -8
  against -19.
- B14. Vector c1-12 (header 271 = 1, digest taken over the JCS bytes) is failed in our key.
  We predict that every return says failed.

### Cell 2 (ARD trust manifest)

- B15. We predict that returns differ from our key on vectors a2-01, a2-02, a2-05, a2-06
  and a2-10 more often than on a2-03, a2-04, a2-07, a2-08 and a2-09. Each of the first 5 has
  a reading of its own that changes its outcome (C6-06, C6-02, C6-07, C6-05, C6-03). The
  other 5 change only under the entry-level reading of B17 (a2-04, a2-08), under readings
  that we judge rarer (C6-08 for a2-08; C6-01 and C6-04 for a2-03 and a2-07), or under no
  reading that we found (a2-09, C6-12).
- B16. Vector a2-05: the record names the right identifier and a different artifact digest.
  Section 3.5.2 says "identifier and/or ... digest". Ours: failed. We predict that this is
  the vector most often returned as verified.
- B17. Take a reader for whom a failed or unchecked attestation (its pin or its binding)
  stops only that attestation, and not the whole entry (C6-09). That reader returns verified
  on a2-04, a2-05, a2-06 and a2-08. We predict that at least 1 reader takes that reading.
- B18. We predict that no return for cell 2 arrives before Sunday 15 November 2026, 13:30
  Pacific time.

A note on cell 2. The attestation in the public `ard/` directory pins a stand-in record over
the cell-1 payload. It does not pin a cell-1 vector record. A second version pins the cell-1
record c1-07. We hold it back until the cell-1 key is published, because it would show that
we accept c1-07.

## Part C. Where the builders chose between readings

Each entry: the text, the question, the readings, the choice made, and the vector that
tells the readings apart. The entries are recorded as the builders wrote them, with a few
edits for clarity. Entries of different builders overlap: the overlap shows which questions
more than one reader met. The C7 entries come from a second reader. That reader wrote them
after fixing their own returns. We then compared the choices with our keys: "(= sealed)"
marks a choice equal to our key.

### C1. Builder of Round 1

**C1-01.** VERIFIER-SPEC-v1.md, 2 Canonical form

- Question: In what order are object keys 'sorted'?
- Readings: (a) by Unicode code point, which is the same as UTF-8 byte order (Python sort_keys); (b) by UTF-16 code unit (JavaScript Array.prototype.sort); (c) locale collation
- Choice: No assigned value; the vector is an unscored probe. The mechanical spec check used reading (a).
- Telling vector: r1-09 (context member names U+FF34-based 'Tag' and U+1F4CE): (a) gives ALLOW, (b) gives DENY:content_mutated

**C1-02.** VERIFIER-SPEC-v1.md, 2 Numbers

- Question: Is 100.0 an 'integer' (by value) or a non-integer number (by lexical form)?
- Readings: (a) lexical: a fraction part means outside the profile, verdict undefined; (b) value: 100.0 is the integer 100, inside the profile, and the canonical text is then ambiguous ('100.0' from Python, '100' from JavaScript)
- Choice: Reading (a): outside the profile, unscored probe, no assigned value
- Telling vector: r1-15: Python ALLOW, JavaScript DENY:content_mutated

**C1-03.** VERIFIER-SPEC-v1.md, 2 Numbers

- Question: Is 'within ±(2^53−1)' inclusive?
- Readings: (a) inclusive, |n| <= 2^53-1; (b) exclusive
- Choice: Inclusive. The vector is still an unscored probe, by design.
- Telling vector: r1-01: inclusive gives ALLOW from all three readings; exclusive puts it outside the profile

**C1-04.** VERIFIER-SPEC-v1.md, 1 and 2 (no text on duplicate member names)

- Question: How is a duplicate JSON member name treated?
- Readings: (a) last value wins; (b) first value wins; (c) reject as malformed
- Choice: No assigned value (spec silent). Both references are last-wins.
- Telling vector: r1-05: (a) ALLOW, (b) DENY:content_mutated, (c) probably DENY:malformed_aep

**C1-05.** VERIFIER-SPEC-v1.md, 4 step 5f

- Question: Is a JSON null amount 'present'?
- Readings: (a) present and not numeric, so scope_violation; (b) treated as absent, so the cap does not apply (both references)
- Choice: Not put in the corpus. Recorded in findings.md as a reference-versus-spec gap.
- Telling vector: none in Round 1 (a throw-away test outside the corpus: both references give ALLOW)

**C1-06.** VERIFIER-SPEC-v1.md, 4 step 5g

- Question: Does a null or non-integer exp count as 'carrying no expiry'?
- Readings: (a) null counts as no expiry, so expired; (b) undefined. The references split: Python malformed_aep through the exception guard; JavaScript expired for null and ALLOW for a numeric string such as "200" at now=50 (tested with throw-away keys). By reading, not tested: a string that is not a number, such as "abc", would never expire in the port. Only the principal's key can sign such a mandate, so this is a difference between the 2 verifiers, not a way to forge an ALLOW
- Choice: Not put in the corpus. Recorded in findings.md.
- Telling vector: none in Round 1

**C1-07.** VERIFIER-SPEC-v1.md, 4 step 5d

- Question: Does 'the mandate's principal must match the credential's principal' compare principal_id or the principal key?
- Readings: (a) principal_id (the references); (b) principal_pub
- Choice: Reading (a). r1-16 carries an id mismatch as its losing defect, so the difference does not change any assigned value.
- Telling vector: No scored vector has an id mismatch as its winning reason. The in-memory self-check of r1-16 (id defect alone) gives principal_sig_invalid under (a).

**C1-08.** VERIFIER-SPEC-v1.md, 4 step 6

- Question: How is the consumed set supplied, and how is a decoy compared?
- Readings: consumed is a JSON array from cases.json, compared by value and type (s5 note) versus case-insensitively or as a prefix
- Choice: Exact value and type
- Telling vector: r1-17 (consumed holds the nonce in upper case, the nonce with one character changed, and the nonce with one character appended): exact comparison gives ALLOW

### C2. Clean-room build of a Round 1 verifier (same lab)

**C2-01.** VERIFIER-SPEC-v1, 2 (canonical form)

- Question: What order does 'object keys sorted' mean?
- Readings: Unicode code-point order (Python sorted) or UTF-16 code-unit order (JavaScript default sort, RFC 8785 JCS)
- Choice: code-point order
- Telling vector: r1-09 (action.context keys U+FF34 'Ｔａｇ' and U+1F4CE '📎'): code-point order gives ALLOW, UTF-16 order gives content_mutated

**C2-02.** VERIFIER-SPEC-v1, 2 (numbers outside the integer profile)

- Question: Render or reject a non-integer number, and how to render it
- Readings: Python repr ('100.0'), JavaScript ('100'), or reject with some reason
- Choice: render as Python json does; never reject
- Telling vector: r1-15 (action.args.amount = 100.0): Python rendering gives ALLOW, JavaScript rendering gives content_mutated, reject gives an undefined reason; Round 0 r0-14, r0-15

**C2-03.** VERIFIER-SPEC-v1, 1-2 (JSON parsing; no clause)

- Question: Duplicate member names
- Readings: last wins, first wins, or reject the package
- Choice: last wins
- Telling vector: r1-05 (nonce twice; the first value is in consumed): last wins gives ALLOW, first wins gives content_mutated, reject gives malformed_aep; Round 0 r0-17

**C2-04.** VERIFIER-SPEC-v1, 4.5b-4.5g, 4.3

- Question: JSON member names of the credential, mandate, scope and action
- Readings: The specification names none of credential.body.issuer_id/issuer_pub/principal_id/principal_pub, credential.sig, mandate.sig, mandate.body.principal_id/agent_id/agent_pub/scope/exp, scope.allowed_methods/max_amount, action.method, action.args.amount, package agent_id
- Choice: names taken from the vectors
- Telling vector: every vector

**C2-05.** VERIFIER-SPEC-v1, 4.3, 4.4, 4.5c-d

- Question: Encoding of signatures, the signing input and 'digest'
- Readings: signature hex or base64; signing input UTF-8 or another encoding; digest = SHA-256 hex of the canonical form or another hash or encoding
- Choice: hex signatures (bytes.fromhex, accepts upper case); UTF-8 bytes; SHA-256 lowercase hex of the canonical form, as check 2 states
- Telling vector: every vector (only one reading works)

**C2-06.** VERIFIER-SPEC-v1, 4.2

- Question: Is an upper-case hex receipt_hash equal?
- Readings: exact string compare, or case-insensitive
- Choice: exact (upper case gives content_mutated)
- Telling vector: none in Round 1

**C2-07.** VERIFIER-SPEC-v1, 4.1

- Question: Is measurements: null 'present'?
- Readings: present and not an object (malformed_aep), or treated as absent (measurement_mismatch)
- Choice: malformed_aep
- Telling vector: none (r1-18 has a list, which is unambiguous)

**C2-08.** VERIFIER-SPEC-v1, 4.4

- Question: outcome: null versus an absent outcome
- Readings: null digests as 'null', or as {}
- Choice: only an absent outcome digests as {}
- Telling vector: none

**C2-09.** VERIFIER-SPEC-v1, 4.5b

- Question: 'exactly the public key the credential carries'
- Readings: exact string compare, or compare decoded key bytes (case-insensitive hex)
- Choice: exact string compare
- Telling vector: none (r1-04 carries a different key)

**C2-10.** VERIFIER-SPEC-v1, 4.5d

- Question: principal_id absent on both sides
- Readings: match (both missing), or no match
- Choice: no match (principal_sig_invalid)
- Telling vector: none

**C2-11.** VERIFIER-SPEC-v1, 4.1 and 4.5e

- Question: The package agent_id is not required by check 1; what if it is absent?
- Readings: absent on both sides matches, or the mandate does not name this agent
- Choice: agent_binding_mismatch if either side lacks agent_id
- Telling vector: none

**C2-12.** VERIFIER-SPEC-v1, 4.5f

- Question: Scope edge cases
- Readings: absent scope; scope not an object; allowed_methods not a list (substring trap) or an empty list; true/false as numeric; non-numeric max_amount; where the amount lives
- Choice: absent scope = no constraint; scope not an object or allowed_methods not a list = violation; empty list allows nothing; booleans are not numeric; non-numeric cap = violation; amount only in action.args; floats count as numeric
- Telling vector: only r1-15 touches this (float amount accepted as numeric)

**C2-13.** VERIFIER-SPEC-v1, 4.5g

- Question: exp present but not numeric (string, null, bool)
- Readings: treat as no expiry (expired), or as malformed
- Choice: expired
- Telling vector: none (r1-10 lacks exp, but scope fails first)

**C2-14.** VERIFIER-SPEC-v1, 5 (nonce by value and type)

- Question: Is 1 equal to 1.0? Is true equal to 1?
- Readings: JSON-number equality, or byte equality
- Choice: 1 equals 1.0; booleans never equal numbers
- Telling vector: none (r1-17 near-miss strings are unambiguous)

**C2-15.** VERIFIER-SPEC-v1, 4.1

- Question: Unparseable text, NaN/Infinity, invalid UTF-8
- Readings: malformed_aep, or not defined
- Choice: malformed_aep
- Telling vector: none

**C2-16.** VERIFIER-SPEC-v1, 4.3, 4.5c, 4.5d

- Question: Key or signature that is not hex, the wrong length, or not a string
- Readings: signature invalid, or malformed
- Choice: signature invalid (aep_sig_invalid / credential_sig_invalid / principal_sig_invalid)
- Telling vector: none

### C3. Builder of the explain tool

**C3-01.** VERIFIER-SPEC-v1 (aep-sandbox interlab/spec), 4 step 1 and step 3; section 2

- Question: What reason does a package get when agent_pub is present but is not a string (e.g. a JSON number)?
- Readings: (a) by the text, step 1 checks only presence, so step 3 fails with aep_sig_invalid (the JS port does this); (b) the Python reference raises inside keys.pub_from_hex, and the verify.py guard reports malformed_aep at structure
- Choice: explain.py keeps the sandbox verdict (malformed_aep) but reports the fail at the check where the exception happened (package signature), with a note that verify.py reports it at structure
- Telling vector: a test file kept by Tyche Institute, not in this pack (the good sample with agent_pub=123 and receipt_hash recomputed): Python DENY:malformed_aep, JS DENY:aep_sig_invalid

**C3-02.** VERIFIER-SPEC-v1, 2 (Numbers)

- Question: What outcome should a package outside the integer profile get when the sandbox says ALLOW?
- Readings: (a) verified, because the sandbox verdict is ALLOW; (b) unverified, because the spec 'does not define which verdict such a package receives'
- Choice: unverified for ALLOW; failed for DENY (spec says a verifier may reject). Sandbox verdict printed unchanged
- Telling vector: r0-14-probe-float-0_1 and r0-15-probe-float-1e-7 (sandbox ALLOW, outcome unverified)

**C3-03.** VERIFIER-SPEC-v1, 2 and 4

- Question: Does a document with a duplicate key count as in-profile?
- Readings: (a) yes, since only numbers are restricted and json.load keeps the last value; (b) no, since the canonical form of the raw bytes is ambiguous
- Choice: (a): explain.py tests the parsed document, so duplicates are invisible to it (stated as a limit in the README)
- Telling vector: r0-17-probe-dup-key (outcome verified)

**C3-04.** draft-sokolov-rats-aep-composition-06, 11, lines 591-594

- Question: What is a 'layer of rejection'?
- Readings: (a) RATS layers: platform Evidence appraisal versus AEP Evidence versus application decision; (b) the individual failing check in an ordered verifier
- Choice: the text we propose for that section asks for both: the layer (4 named) and the first failing check in a stated order
- Telling vector: in our machine-mandate demonstration, the case 'replayed stale attestation' (layer 2 denies, layer 3 is still evaluated), against AEP r0-06 (stops at 5c)

**C3-05.** VERIFIER-SPEC-v1, 4 step 5a versus the reference

- Question: Is an absent credential.body or mandate.body a 5a failure?
- Readings: (a) yes, 'must be objects'; (b) no, the reference reads absent as {} and fails later (at 5b or 5d)
- Choice: explain.py only maps the returned reason, so it follows the reference; not tested by any public vector
- Telling vector: none in Round 0; a package with mandate.body removed and receipt_hash recomputed would tell (expected to fail at aep_signature first unless re-signed, so it needs a test signer key)

### C4. First-reader pass over the public texts (same lab)

**C4-01.** VERIFIER-SPEC-v1.md, 2 Canonical form ('object keys sorted')

- Question: What sort order applies to object keys?
- Readings: (a) Unicode code point order (Python sort); (b) UTF-16 code unit order (JS default sort, RFC 8785); (c) UTF-8 byte order
- Choice: None needed (this reader built no verifier). It is recorded because Python and the JS port split on it: Python ALLOW, JS DENY content_mutated.
- Telling vector: r1-09 (keys 'Ｔａｇ' U+FF34 and '📎' U+1F4CE; unscored)

**C4-02.** VERIFIER-SPEC-v1.md, 2 Numbers ('integers within ±(2⁵³−1)')

- Question: Is the bound inclusive?
- Readings: (a) inclusive: ±9007199254740991 is in the profile; (b) exclusive: it is out of the profile, verdict undefined
- Choice: Inclusive (the surface guess said ALLOW). Note that OUTCOMES.md ('outside the range from -(2^53 - 1) to 2^53 - 1') publicly adopts the inclusive reading.
- Telling vector: r1-01 (entry_seq 9007199254740991, offset -9007199254740991; unscored)

**C4-03.** VERIFIER-SPEC-v1.md, 1 / 4.1 Structure (duplicate member names not addressed)

- Question: What does a package with a duplicate 'nonce' member mean?
- Readings: (a) last wins (Python json, JS JSON.parse): nonce not consumed, ALLOW; (b) first wins: the nonce is consumed, replayed (corrected before sealing: the receipt hash covers the last nonce, so a first-wins verifier stops earlier, at content_mutated, as B3 says); (c) reject as malformed_aep
- Choice: ALLOW, and assumed unscored
- Telling vector: r1-05 (first nonce n-ecad884c… is in consumed, the last is not; unscored, no key value)

**C4-04.** VERIFIER-SPEC-v1.md, 2 Numbers ('non-integer number')

- Question: Is the JSON token 100.0 an integer?
- Readings: (a) a lexical non-integer (has a fraction part), so out of profile; (b) a mathematical integer value, so in profile; but then canonical rendering differs (Python '100.0', JS '100')
- Choice: Out of profile, unscored (surface guess ALLOW)
- Telling vector: r1-15 (amount 100.0; Python ALLOW, JS DENY content_mutated; unscored)

**C4-05.** VERIFIER-SPEC-v1.md, 5 Notes (nonce comparison 'by value and type')

- Question: Does a case variant or a prefix variant of the nonce count as consumed?
- Readings: (a) exact string equality only; (b) some normalisation (case-folding)
- Choice: Exact equality: ALLOW (matches the key)
- Telling vector: r1-17 (consumed holds the nonce in upper case, the nonce with one character changed, and the nonce with one character appended)

### C5. Builder of cell 1

**C5-01.** draft-mih-sokolov-scitt-payload-binding-06, Envelope Conventions (Full-Content Mode / Hash Envelope Mode) with Envelope Carriage

- Question: Which statement mode carries the JSON-side record?
- Readings: (a) Full-Content Mode, with cpb-refs citing the payload as an external artifact (the pattern of fixture pass-03 among the typed references in the CPB repository); (b) an RFC 9995 Hash Envelope over the JCS bytes plus cpb-refs citing the same payload (the layout of fixture pass-04 there, in which the reference cites a different artifact)
- Choice: (b): the COSE payload is the raw SHA-256 of the JCS bytes and the cpb-refs digest is the same value in hex. Both must match.
- Telling vector: c1-09 (JSON-side reference record)

**C5-02.** draft-mih-sokolov-scitt-payload-binding-06, Hash Envelope Mode ('The applicable payload profile MUST identify A')

- Question: How does the verifier learn the canonicalization A for the JSON-side Hash Envelope?
- Readings: (a) out of band from the profile alone; (b) from the cpb-refs type token, through its declared digest context
- Choice: declaration.json ties the profile to records that carry cpb-refs with type example-action-record. A record without cpb-refs is handled by the CDE rules.
- Telling vector: none in the set (it would need a JSON-side record without cpb-refs)

**C5-03.** draft-mih-sokolov-cose-deterministic-encodings-00, Verifying the Content Binding ('holds only a structured value')

- Question: In what form does the held structured value reach the verifier?
- Readings: (a) as CBOR (value_cbor, as in the CDE vectors); (b) as JSON text, mapped to the CBOR data model by a rule the cell defines
- Choice: (b): one shared JSON held value for both sides. The JSON-to-CBOR mapping is stated in declaration.json.
- Telling vector: c1-07 and every CBOR-side vector

**C5-04.** CPB -06 vs CDE -00, CPB Conventions 'Failed' and Cross-Profile Comparability; CDE Verifying the Content Binding

- Question: Held JSON text with a duplicate member name
- Readings: CPB -06: Failed (the obtained artifact is not input that the construction accepts). CDE -00 text: silent. CDE reference code: unverified (value-not-encodable).
- Choice: failed on the JSON side (held-value-rejected). On the CBOR side our verifier follows the CDE code (unverified), but no CBOR-side twin vector was built.
- Telling vector: c1-01 (a lenient parser gives verified)

**C5-05.** CPB -06 and CDE -00, CPB 'Signature-Valid'; CDE 'Signature validity is unaffected by any content-binding outcome'

- Question: Both drafts report the signature separately from the content binding, but the cell needs one outcome per vector
- Readings: (a) a bad signature makes the vector failed; (b) report the content-binding outcome and the signature separately
- Choice: (a), stated as a cell rule in the README
- Telling vector: c1-05 (the CPB library verifies its typed reference)

**C5-06.** RFC 9052 / RFC 9864 vs the CPB fixtures, COSE alg for Ed25519

- Question: Which algorithm value does the signer use?
- Readings: -8 EdDSA (as in the CPB typed-refs fixtures) or -19 Ed25519 (fully specified, RFC 9864)
- Choice: -8
- Telling vector: all records (a verifier that accepts only -19 rejects all of them)

**C5-07.** draft-mih-sokolov-cose-deterministic-encodings-00 / RFC 9995 Section 5.3, Verifying the Content Binding

- Question: CBOR header (271 = 1) with the digest taken over the JCS bytes
- Readings: A verifier holding the value re-creates the CBOR bytes: failed. A verifier holding the JCS bytes as the preimage: verified under RFC 9995.
- Choice: The verifier always holds the value, so failed
- Telling vector: c1-12

**C5-08.** CPB -06 Envelope Conventions vs CDE -00, RFC 9943 baseline (CWT Claims 15, kid)

- Question: Should the CBOR-side record carry CWT Claims and kid?
- Readings: Required for a CPB/SCITT statement; not required by CDE
- Choice: Included on both sides; no outcome depends on it
- Telling vector: none

**C5-09.** draft-mih-sokolov-scitt-payload-binding-06, Envelope Carriage (crit)

- Question: Must cpb-refs be listed in crit?
- Readings: The profile decides: advisory (omit from crit) or required (list in crit)
- Choice: Required and listed in crit, as the CPB fixtures do. 271 is not in crit, because CDE says a producer MUST NOT list it.
- Telling vector: c1-09 vs c1-07 headers

**C5-10.** RFC 8785 vs our tools, Number serialization

- Question: Held JSON that contains a float
- Readings: JCS accepts floats; our tools do not serialize them
- Choice: unverified (held-value-not-implemented), reading the CPB 'unimplemented' cause
- Telling vector: none in the set

**C5-11.** Cell 1 design, the vector with a changed value

- Question: When the held value and the record disagree, which of the 2 was changed?
- Readings: (a) a byte of the COSE payload (the digest); (b) a byte of the held content
- Choice: (b): the held amount is 4251 instead of 4250, and the record is intact. Reading (a) would repeat the bad-signature vector.
- Telling vector: c1-10

### C6. Builder of cell 2

**C6-01.** draft-bu-dawn-ard-discovery-00, 3.5 signature; Introduction

- Question: Which JWS serialization goes into the 'signature' string?
- Readings: A: compact, detached payload (RFC 7515 Appendix F) h..s; B: compact, embedded payload h.p.s; C: RFC 7797 unencoded detached payload (b64=false in crit), which is what PyJWT calls detached; D: JWS JSON serialization as a string
- Choice: Generate A and B; the verifier accepts both
- Telling vector: a2-07 (A) vs a2-03 (B); examples/entry-single-detached.json vs entry-single-embedded.json

**C6-02.** draft-bu-dawn-ard-discovery-00, 3.5 signature

- Question: With an embedded payload, must it be byte-equal to the JCS of the received manifest?
- Readings: A: re-compute JCS and require byte equality; B: check the JWS over the embedded bytes, then compare parsed values
- Choice: A (failed, signed-bytes-not-jcs)
- Telling vector: a2-02

**C6-03.** draft-bu-dawn-ard-discovery-00, 3.5 identity / signature (kid)

- Question: How does kid relate to identity?
- Readings: A: kid is a DID URL whose DID part equals identity, key taken from the identity's DID document; B: kid is resolved from anywhere and identity is checked separately. Also: assertionMethod required or any verificationMethod
- Choice: A, plus the key must be listed in assertionMethod
- Telling vector: a2-10

**C6-04.** draft-bu-dawn-ard-discovery-00, 3.5 first paragraph; 3.5.1 Signer Profile; CDDL

- Question: Where does the publisher manifest go when there are several manifests?
- Readings: A: publisher in trustManifest, others in trustManifests[]; B: all in trustManifests[], publisher found by identity. Both members at once is allowed by the CDDL
- Choice: Accept the union of both members; the vector uses trustManifests[] alone
- Telling vector: a2-03; examples/entry-two-manifests.json

**C6-05.** draft-bu-dawn-ard-discovery-00, 3.5.2 last paragraph; 3.2.3 digest; 6.4

- Question: What outcome for an attestations[].digest whose algorithm prefix the verifier does not implement?
- Readings: A: unverified (the check cannot run and the text defines no verdict); B: failed (6.4 MUST verify); C: verified (prefix ignored, hex compared)
- Choice: A, unverified (digest-alg-not-implemented)
- Telling vector: a2-06 (x-test256: + correct SHA-256 hex)

**C6-06.** draft-bu-dawn-ard-discovery-00, 3.5 issuedAt/expiresAt

- Question: Does expiresAt apply to a publisher manifest, and what does a verifier do past it?
- Readings: A: failed; B: no effect on a publisher manifest ('for periodic third-party evaluations'); C: unverified discovery hint (6.2 wording)
- Choice: A, failed (manifest-expired)
- Telling vector: a2-01

**C6-07.** draft-bu-dawn-ard-discovery-00, 3.5.2 Binding the Attestation; 6.4

- Question: Must the signed subject claim match the identifier, the digest, or both ('and/or')?
- Readings: A: both (or at least the digest); B: identifier alone is enough
- Choice: A: both identifier and entry digest must match
- Telling vector: a2-05 (record 2 names the right identifier and a previous artifact digest)

**C6-08.** draft-bu-dawn-ard-discovery-00, 3.5.2 ('each third-party attestation statement') vs 6.4 ('Signed attestations referenced in trustManifest.attestations')

- Question: Does the binding rule apply to attestations in the publisher's own manifest?
- Readings: A: every attestations[] item in any manifest; B: statements by third parties alone
- Choice: A
- Telling vector: a2-08 (transplant inside the publisher manifest)

**C6-09.** draft-bu-dawn-ard-discovery-00, 3.5.1 (checks a-c, 'MUST be rejected') vs 6.4 ('before honoring any audit or provenance claims')

- Question: Does a failed attestation pin or binding reject the whole entry, or only stop the attestation from being honored?
- Readings: A: the entry fails; B: the entry is verified for publisher authority and the attestation is not honored
- Choice: A (the cell needs one outcome per entry)
- Telling vector: a2-04, a2-05, a2-06, a2-08

**C6-10.** draft-bu-dawn-ard-discovery-00, 3.5.2

- Question: Whose signature on the attestation statement counts, and how is that key found?
- Readings: A: verifier's local trust policy; B: the identity of the carrying manifest; C: a signer named in the attestations[] item
- Choice: A: a locally configured key in context.json
- Telling vector: none in this cell (a record signed by an unknown key or by the publisher key would tell)

**C6-11.** draft-bu-dawn-ard-discovery-00, 3.5 subject (MUST) vs section 5 CDDL ('? subject'); trust-subject url

- Question: Is subject required, and is subject.url compared to the entry url?
- Readings: A: required (prose); B: optional (CDDL). url compared or not
- Choice: Required; url not compared
- Telling vector: none in this cell

**C6-12.** draft-bu-dawn-ard-discovery-00, 3.5.1 (a); 3.5 'version when present on the entry'

- Question: What does 'subject matches the parent entry' mean?
- Readings: A: exact string equality of each field present on either side; B: semantic comparison (hex case, media-type parameters)
- Choice: A
- Telling vector: none tells them apart (a2-09 differs in version, which both readings reject); an uppercase-hex subject.digest would

**C6-13.** draft-bu-dawn-ard-discovery-00, 3.2.1 type; 3.5 example vs CDDL displayName

- Question: Entry media type for the cell-1 text artifact, and displayName
- Readings: Use an agent-card media type as in the example, or the real type of the artifact; the 3.5 example omits displayName while the CDDL requires it
- Choice: type text/plain (the artifact is a text file); displayName included per the CDDL. Treated as a draft shortcut, not listed as a question
- Telling vector: none

### C7. Second reading of cells 1 and 2 (same lab)

**C7-01.** CPB -06 + RFC 8785 / RFC 7493, CPB Conventions 'Failed', 'Cross-Profile Comparability'; RFC 8785 3.1; RFC 7493 2.3

- Question: Held JSON text with a duplicate member name (same value) on the JSON side
- Readings: (a) failed: not input jcs accepts; (b) unverified; (c) verified: lenient parser, last wins, digest matches
- Choice: (a) failed, held-value-rejected (= sealed)
- Telling vector: cell1 c1-01

**C7-02.** CPB -06, Hash Envelope Mode + Typed Digest References

- Question: Is the cpb-refs cited artifact (type example-action-record) the held payload itself, or a separate artifact that must be obtained?
- Readings: (a) the held payload, so both the Hash Envelope digest and the cpb-refs digest must match; (b) a separate artifact, Unresolved(unavailable) if not supplied
- Choice: (a)
- Telling vector: none: all JSON-side vectors carry equal digests

**C7-03.** declaration.json json_to_cbor / CDE -00, held_value mapping; CDE Security Considerations

- Question: How does a JSON number such as 1.0 or 1e2 map to CBOR?
- Readings: integer (major 0/1); float; not mappable
- Choice: not mappable, so unverified (value-not-encodable)
- Telling vector: none

**C7-04.** CDE -00, Consistency with preimage-content-type

- Question: 271 present with an unrecognized value plus a non-CBOR 259
- Readings: unverified (failed applies only to 'an encoding the verifier recognizes'); failed (consistency)
- Choice: unverified
- Telling vector: none: c1-04 has 259 application/cbor

**C7-05.** CDE -00 + cell1 README rule 1, Verifying the Content Binding, last paragraph

- Question: Bad signature on a CBOR-side record
- Readings: failed (cell rule); content binding reported separately (CDE: signature validity is unaffected by the content-binding outcome)
- Choice: failed per the cell rule
- Telling vector: none on the CBOR side (c1-05 is JSON side)

**C7-06.** CDE -00 / cell1, Verifying the Content Binding

- Question: Held JSON with a duplicate name on the CBOR side
- Readings: failed; unverified
- Choice: failed
- Telling vector: none

**C7-07.** draft-bu-dawn-ard-discovery-00, 3.5 issuedAt / expiresAt

- Question: Expired publisher manifest
- Readings: failed; verified (expiresAt is described 'for periodic third-party evaluations', no verifier rule); unverified
- Choice: failed (= sealed)
- Telling vector: ard a2-01

**C7-08.** draft-bu-dawn-ard-discovery-00, 3.5 signature

- Question: Embedded JWS valid over non-JCS bytes that parse to the same manifest
- Readings: failed (must be computed over the JCS serialization); verified (JWS valid and parsed values equal)
- Choice: failed (= sealed)
- Telling vector: ard a2-02

**C7-09.** draft-bu-dawn-ard-discovery-00, 3.5.2 'identifier and/or the artifact's content digest'; 6.4

- Question: Attestation claim names the right identifier but a different artifact digest
- Readings: failed (each claim present must match; 6.4 says it must match the attestation subject); verified (identifier alone suffices)
- Choice: failed (= sealed)
- Telling vector: ard a2-05

**C7-10.** draft-bu-dawn-ard-discovery-00, 3.5.2 last paragraph; 3.2.3 digest

- Question: Unknown digest algorithm prefix on an attestation pin
- Readings: unverified; failed; verified (ignore the prefix, compare the hex)
- Choice: unverified (= sealed)
- Telling vector: ard a2-06

**C7-11.** draft-bu-dawn-ard-discovery-00, 3.5 identity, kid; 3.5.1 (b), (c)

- Question: kid belongs to a different DID than identity
- Readings: failed; verified (resolve kid from any known DID document)
- Choice: failed (= sealed)
- Telling vector: ard a2-10

**C7-12.** draft-bu-dawn-ard-discovery-00, 3.5 / DID resolution

- Question: Must the signing key be listed under assertionMethod, or is any verificationMethod enough?
- Readings: assertionMethod only; any verificationMethod
- Choice: assertionMethod
- Telling vector: none: all keys are listed in both

**C7-13.** draft-bu-dawn-ard-discovery-00, 3.5 / CDDL

- Question: Entry with both trustManifest and trustManifests; issuedAt in the future
- Readings: reject; accept
- Choice: failed for both
- Telling vector: none

Entries in part C: 71.
