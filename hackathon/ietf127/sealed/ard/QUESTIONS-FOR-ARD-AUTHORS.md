# Questions for the ARD authors (SEALED until the reveal)

Source: draft-bu-dawn-ard-discovery-00, section 3.5 with 3.5.1 and 3.5.2, the CDDL in section 5, and sections 6.1, 6.2 and 6.4. We read a saved copy of the -00 text.

Context: Tyche Institute built a small probe for the IETF 127 Hackathon: ARD entries with a `trustManifest`, an attestation that pins a signed COSE record, and 10 test vectors (`public/ard/vectors/a2-01` to `a2-10`). Where the text allowed two or more readings, we picked one and built a vector that tells the readings apart. These are questions, not findings. We may have missed text that settles them. The vector map is in `expected.json` beside this file.


---

## 1. Which JWS serialization goes into `signature`?

Section 3.5 (`signature`) says "A JSON Web Signature (JWS) [RFC7515] computed over the JCS serialization". The Introduction says "RFC 7515 detached JWS".

- Reading A: compact serialization with a detached payload (RFC 7515 Appendix F): `header..signature`. The verifier re-creates the payload from the manifest.
- Reading B: compact serialization with the payload embedded: `header.payload.signature`.
- Reading C: unencoded detached payload (RFC 7797, `"b64": false` listed in `crit`). Common JWS libraries implement "detached" this way.
- (Reading D: the JWS JSON serialization, as a string.)

Would you say which one is meant, or whether several are allowed?

Telling vectors: `examples/entry-single-detached.json` (A) and `examples/entry-single-embedded.json` (B); among the vectors, a2-07 (A) and a2-03 (B, two manifests). A verifier that implements one layout does not return `verified` for the other.

## 2. With an embedded payload, must it equal the JCS bytes of the manifest?

Section 3.5 (`signature`): the JWS is "computed over the JCS serialization of the trustManifest object with the signature member removed". This question exists only if Reading B of question 1 is allowed.

- Reading A: the verifier re-computes JCS from the received manifest and requires the embedded payload to be those exact bytes.
- Reading B: the verifier checks the JWS over whatever payload is embedded, then compares the parsed payload with the manifest as JSON values.

Telling vector: a2-02. The embedded payload is the same object as indented JSON in member insertion order. The JWS checks over those bytes. Reading A gives failed, Reading B gives verified.

## 3. How does `kid` relate to `identity`?

Section 3.5 (`identity`, `signature`): the protected header names `kid`; `identity` is "the cryptographic signer identifier (for example, did:web:example.com ...)". The example header begins `{"alg":"ES256","kid":"did:web:`.

- Reading A: `kid` is a DID URL, and its DID part must equal `identity` (for example `did:web:example.org#key-1`). The key comes from the DID document of `identity`.
- Reading B: `kid` is any key identifier; the verifier resolves it from wherever it can and checks `identity` separately (or not at all).
- Sub-question: must the key be listed under a particular verification relationship of the DID document (for example `assertionMethod`), or does any `verificationMethod` do?

Telling vector: a2-10. `identity` is `did:web:example.org`; the JWS is made with the key of `did:web:third-party.example.net` and `kid` says so. Reading A gives failed; Reading B gives verified (the signature is valid under the key `kid` names, and `identity` matches the publisher).

## 4. `trustManifest`, `trustManifests[]`, or both?

Section 3.5 (first paragraph): "a trustManifest object (or a trustManifests array when multiple parties ... attach separate signed manifests)". Section 3.5.1: the publisher manifest is "a trustManifest whose identity matches ... <publisher>"; a third party "MAY attach an additional trustManifest in trustManifests[]". The CDDL allows both members at once.

- Reading A: the publisher manifest stays in `trustManifest`; `trustManifests[]` holds the additional manifests.
- Reading B: when there are several manifests, all go in `trustManifests[]` (the publisher's included), and the verifier finds the publisher manifest by its `identity`.
- Sub-question: may an entry carry both members, and if so, may the publisher manifest appear in the array?

Telling vector: a2-03 (and `examples/entry-two-manifests.json`): `trustManifests[]` with the publisher manifest and a second manifest, no `trustManifest` member. Reading A gives failed or unverified (no publisher manifest where expected); Reading B gives verified.

## 5. What does a verifier do with a digest algorithm it does not implement?

Section 3.5.2 (last paragraph): digests use `<alg>:<hex>` "to support hash agility; sha256 is Mandatory-to-Implement". Section 3.2.3 (`digest`): implementations "MAY support additional collision-resistant hash algorithms". Section 6.4: consumers "MUST verify that the fetched document's digest matches attestations[].digest".

- Reading A: an unknown `<alg>` means the check cannot be done, so the entry has no verdict (we report `unverified`).
- Reading B: an unknown `<alg>` fails the MUST in 6.4, so the entry is rejected (`failed`).
- Reading C: a verifier compares the hex value and does not look at the prefix (`verified` here, since the hex is the correct SHA-256).
- Sub-question: is there a list or registry of `<alg>` names, or is any name allowed?

Telling vector: a2-06: `attestations[0].digest` is `x-test256:` followed by the correct SHA-256 hex.

## 6. Does `expiresAt` apply to a publisher manifest, and what happens after it?

Section 3.5 (`issuedAt`, `expiresAt`): "when the manifest was signed and, for periodic third-party evaluations, when the assertion expires". We found no verifier rule for a manifest past `expiresAt`.

- Reading A: an expired manifest fails; the entry is rejected.
- Reading B: `expiresAt` is meant for third-party manifests; on a publisher manifest it has no verifier effect.
- Reading C: the expired manifest is dropped, and the entry becomes an unverified discovery hint (section 6.2 wording).
- Sub-question: if a third-party manifest has expired and the publisher manifest is fine, is the entry still verified for publisher authority?

Telling vector: a2-01: a publisher manifest with `expiresAt` 2026-11-01T00:00:00Z, checked at 2026-11-14T12:00:00Z.

## 7. Identifier "and/or" digest: which one must the attestation statement name?

Section 3.5.2 (Binding the Attestation to the Target Artifact): the statement must "include a signed subject claim that identifies the resource's identifier and/or the artifact's content digest". Section 6.4 says "bind to the resource's identifier and/or the artifact's algorithm-prefixed digest".

- Reading A: the claim must match the entry digest (and the identifier, when it names one). An identifier alone does not stop a statement about an old version from being reused for a new one.
- Reading B: naming the identifier is enough.

Telling vector: a2-05: a signed record names the right identifier and the artifact digest of a previous version. Reading A gives failed; Reading B gives verified.

## 8. Does the subject binding apply to every attestation, or to third-party statements alone?

Section 3.5.2 says "each third-party attestation statement MUST ...". Section 6.4 says "Signed attestations referenced in trustManifest.attestations ... MUST".

- Reading A: every `attestations[]` item, in any manifest, must bind to the target.
- Reading B: the binding rule applies to statements made by third parties (for example in a Signer Profile manifest); items in the publisher's own manifest are covered by the publisher's signature over `subject`.

Telling vector: a2-08: the transplant case sits in the publisher's own manifest. The pin matches, and the statement names another agent. Reading A gives failed; Reading B can give verified.

## 9. Does a failed attestation reject the entry, or only the attestation?

Section 3.5.1 lists 3 checks, (a) subject, (b) identity, (c) signature, and says "Entries failing these checks MUST be rejected". Section 6.4 says consumers verify digests "before honoring any audit or provenance claims".

- Reading A: an attestation whose pin or binding fails makes the whole entry fail.
- Reading B: the entry still passes 3.5.1 (a) to (c); the attestation is not honored, and the entry is otherwise verified.

Telling vectors: a2-04 (pin mismatch), a2-05, a2-06 and a2-08. Under Reading B each of these would be "verified for publisher authority, attestation not honored". The cell needs one outcome per entry, so we chose Reading A.

## 10. Whose signature on the attestation statement counts?

Section 3.5.2: the statement must "be a direct cryptographic signature over the artifact or include a signed subject claim". The text does not say who must sign it, or how the verifier finds that key.

- Reading A: any signature the verifier can check by its own trust policy (we used a locally configured key).
- Reading B: the statement must be signed by the `identity` of the manifest that carries it.
- Reading C: the statement's signer must be named in the `attestations[]` item (for example by a member beside `type` and `uri`).

No vector in this cell tells these apart. A record signed by a key unknown to the verifier, or by the publisher key, would.

## 11. Is `subject` required?

Section 3.5 (`subject`) says "(Object, MUST)". The CDDL in section 5 has `? subject: trust-subject` (optional). `trust-subject` also has an optional `url`, which 3.5.1 (a) does not list among the fields to compare.

- Reading A: `subject` is required in every manifest (the prose).
- Reading B: `subject` is optional (the CDDL), for example in a third-party manifest.
- Sub-question: when `subject.url` is present, must it match the entry `url`?

No vector in this cell tells these apart. A manifest without `subject`, or with a `subject.url` that differs from the entry, would.

## 12. How exactly does `subject` "match" the entry?

Section 3.5.1 (a): "trustManifest.subject (identifier, type, digest, and version) matches the parent entry"; section 3.5: "version when present on the entry".

- Reading A: exact string equality of each field that is present on the entry; a field present on one side and absent on the other is a mismatch.
- Reading B: a semantic comparison (for example digest hex compared without regard to case, or media type compared with its parameters normalized).

Vector a2-09 differs in `version` (1.0.1 against 1.0.0), which both readings reject. No vector here tells the readings apart; a `subject.digest` in uppercase hex would.
