# Cell 2: a signed ARD trust manifest that points at a signed record over the cell-1 payload

IETF 127 Hackathon, San Francisco, 14 and 15 November 2026. Prepared by Tyche Institute.

## What this cell tests

ARD means Agent Resource Discovery. draft-bu-dawn-ard-discovery-00 is an individual Internet-Draft by other authors. We are not among them. The draft cites companion ARD documents. Its section 3.5 lets an ARD entry carry a `trustManifest`. That is a signed JSON object. It names the entry (`subject`) and lists hash-pinned evidence (`attestations[]`).

We built one ARD entry for the cell-1 test agent `urn:air:example.org:agent:refund-assistant`. Its `trustManifest` has one `attestations[]` item. That item pins a COSE_Sign1 record (CBOR Object Signing and Encryption, RFC 9052). The record carries the cell-1 payload in its CBOR (Concise Binary Object Representation) form. The `subject` block of that payload names the same identifier and the same artifact digest as the entry. So the attestation carries a signed subject claim, one of the 2 forms that section 3.5.2 allows.

The question for each vector: does the entry, with its manifest or manifests, check out under section 3.5 as you read it?

There are 10 vectors, `a2-01` to `a2-10`. Some should be accepted and some should not. The names and their order say nothing about which is which.

Our expected outcomes are the answer key of this cell. We fixed them in advance: their SHA-256 is line 3 of `../SEAL.sha256`. We publish the file after the pack closes (`../README.md`, section "The seal"). The seal fixes our answers. It does not hide them: our verifier `verify_manifest.py` computes them. So please build and run your own verifier first. If you ran ours first, tell us: your row keeps its label, and we add the note "ran Tyche code first".

Our answers come from our own verifier and our own reading of the draft. No outside reader has checked them.

## Honest boundaries

- **Who built this.** Tyche Institute built the entries, the manifests, the record, the vectors and the tools, from the -00 text of section 3.5. The ARD authors have not reviewed or endorsed any of it.
- **Implementation labels.** The 4 labels are defined in `../README.md`. `verify_manifest.py`, `sign_manifest.py` and `ardlib.py`: author (Tyche Institute wrote the vectors, not the draft). Any other code: tell us who wrote it, and we set the label. An implementation by an author of the ARD draft is a non-author row, marked "author of the draft".
- **The most we may say.** Our example fits the `attestations[]` slot as we read the text. Until a non-author checks it, we claim no more than that.
- **What a reader can see without a verifier.** Each vector is a small change from one of the examples. A careful reader can see each change without checking a signature. So tell us how you got each outcome: from a verifier, or from reading. A return made by reading shows less about the draft.
- **Test keys.** Every key here is a test key. We generated every one, and we use the private halves for nothing outside this test. The signatures are research reference signatures made with these test keys.
- **The second-manifest slot.** `examples/entry-two-manifests.json` uses the `trustManifests[]` array of section 3.5.1 with a second manifest over the same subject. Both keys are Tyche test keys. So this example shows that the slot exists. It shows nothing about a second party.
- **The record.** `evidence/action-record.cose` is a COSE_Sign1 record over the cell-1 payload (`../cell1/payload/payload.cbor`, byte for byte). We signed it with a separate Ed25519 test key. It is not one of the cell-1 vector records, so this cell says nothing about the cell-1 vectors. `evidence/action-record-2.cose` is a second record signed with the same test key.
- **Offline identity.** A `did:web` identity (DID means Decentralized Identifier) is resolved over HTTPS (Hypertext Transfer Protocol Secure). We cannot do that offline. So we ship the DID documents with the public JSON Web Keys (JWK) in `keys/did-web-local.json`. Treat that file as the result of resolution.
- **Example names.** `example.org` and `example.net` names are test names. We do not publish these entries at those names.
- **No claim of use.** We make no statement that anyone runs an implementation of ARD.

## Files

| Path | What it is |
|---|---|
| `vectors/a2-NN.json` | One ARD entry per vector. |
| `vectors/index.json` | The list of vectors, and the "now" for this cell. |
| `examples/entry-single-detached.json` | The example entry: one `trustManifest`, JWS with a detached payload. |
| `examples/entry-single-embedded.json` | The same entry, JWS with the payload embedded. |
| `examples/entry-two-manifests.json` | The same subject with `trustManifests[]`: a publisher manifest and a second manifest. |
| `evidence/action-record.cose` | The record that the attestation of the examples pins. |
| `evidence/action-record-2.cose` | A second record signed with the same test key. |
| `artifact/subject-artifact.txt` | The artifact of the refund-assistant entry (same bytes as `../cell1/artifact/`). |
| `artifact/other-artifact.txt` | The artifact of a second test entry. |
| `keys/did-web-local.json` | DID documents for `did:web:example.org` and `did:web:third-party.example.net`, with ES256 public keys. `third-party` is only a test host name: both keys are Tyche test keys. |
| `keys/evidence-test-key.jwk.json` | The Ed25519 public test key of the record. |
| `context.json` | What a verifier treats as fetched or resolved: "now", the DID documents, the record key, and a map from each `https://` address (URL, Uniform Resource Locator) to a local file. |
| `RETURN-TEMPLATE.json` | An empty return file. Copy it and fill in the copy. |
| `verify_manifest.py`, `sign_manifest.py`, `ardlib.py` | Our verifier and signer. |

### Formats in this cell

- `digest` strings are `<alg>:<hex>`, for example `sha256:` plus 64 lowercase hex digits.
- `signature` is a JSON Web Signature (JWS, RFC 7515) in compact serialization, ES256 (Elliptic Curve Digital Signature Algorithm, ECDSA, on the P-256 curve with SHA-256), signature value raw `r||s` (64 bytes). The protected header is `{"alg":"ES256","kid":...}`. The signing input is the RFC 8785 JSON Canonicalization Scheme (JCS) serialization of the `trustManifest` object with the `signature` member removed. 2 layouts appear:
  - payload detached (RFC 7515 Appendix F): `header..signature`. Re-attach `BASE64URL(JCS bytes)` to check it.
  - payload embedded: `header.payload.signature`.
- The record is a tagged COSE_Sign1, EdDSA (Edwards-curve Digital Signature Algorithm, alg -8), external_aad empty, protected header `{1: -8, 3: "application/cbor", 4: "ard-evidence-test-key"}` (kid as a byte string). Its payload is CBOR; member `subject` holds `identifier` and `digest`.
- "now" for every time check is `2026-11-14T12:00:00Z` (in `context.json` and `vectors/index.json`).

## Run it (about 15 minutes)

You need Python 3.9 or later and the package `cryptography`. Your own verifier needs nothing from us beyond the files.

```sh
# run these from this directory (ard/)
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install cryptography
```

**Step 1. Check the pinned files.**

```sh
sha256sum artifact/subject-artifact.txt evidence/action-record.cose
```

You should see:

```
2c87a2f26d64a675089441dc2db1eece6e6904c7edb18e6ce329cd698c7cc6fb  artifact/subject-artifact.txt
c6718e18a2a8c32606013ef35e17b569a33ec9d383856d567e7def148bbdfe57  evidence/action-record.cose
```

Line 1 is the entry `digest`. Line 2 is the `attestations[0].digest` of the examples.

**Step 2. See what the record names.**

```sh
python3 verify_manifest.py --show-record evidence/action-record.cose
```

You should see:

```
record          sha256:c6718e18a2a8c32606013ef35e17b569a33ec9d383856d567e7def148bbdfe57  (387 bytes)
protected       {"1": -8, "3": "application/cbor", "4": "ard-evidence-test-key"}
payload         269 bytes, sha256 ae533a625913f9909b9d63ade20905d7228e38688acaf8d1b5bebe7515c05a01
claim.subject   {"digest": "sha256:2c87a2f26d64a675089441dc2db1eece6e6904c7edb18e6ce329cd698c7cc6fb", "identifier": "urn:air:example.org:agent:refund-assistant"}
```

The payload SHA-256 equals the `cbor` SHA-256 in `../cell1/payload/KAT.json`. The `subject` names the entry identifier and the entry `digest`.

**Step 3. Run your verifier** on `vectors/` with `context.json`. Copy `RETURN-TEMPLATE.json` to `my-return.json` and fill in the copy. You may start with `examples/`: they are the entries we built as the intended case. The return format is the same as in cell 1, a JSON array:

```json
[
  {"id": "a2-01", "outcome": "verified | failed | unverified", "reason": "short text"}
]
```

The 3 outcome words are defined in `../OUTCOMES.md`. We compare the `outcome` values. The `reason` helps us find where readings differ. Use your own reason words.

**Step 4 (optional). Run our verifier** after you have your own return, and compare.

```sh
python3 verify_manifest.py --out tyche-return.json
python3 verify_manifest.py --checks --out tyche-return.json   # also prints each check: pass, fail or not_evaluated
```

Each command prints one row per vector (`id`, `outcome`, `reason`) and writes the return file.

**Step 5 (optional, after you have your own return). Check our verifier against your signer**, or our signer against your verifier. This makes a fresh ES256 test key for `did:web:example.org`, signs the example manifest with it, and checks the result:

```sh
python3 sign_manifest.py --new-key my-test-key.pem --did did:web:example.org --context-out my-context.json
python3 sign_manifest.py --entry examples/entry-single-detached.json --key my-test-key.pem \
    --kid did:web:example.org#test-key-1 --variant A --out my-entry.json
python3 verify_manifest.py --context my-context.json --entry my-entry.json
```

The last command prints:

```
now = 2026-11-14T12:00:00Z
my-entry                     verified    all-checks-pass
```

Use `--variant B` for the embedded payload. To check your own signer, put your public key in a copy of `keys/did-web-local.json` the same way. Then copy `context.json`, set its `did_documents` to your copy, and pass the new context with `--context`, as `my-context.json` does above.

**Step 6. Send your return** to the address on tyche.institute, or hand it to the Tyche table at the hackathon. Say which implementation produced it, who wrote it, and whether it comes from a verifier or from reading. We set the label (`../README.md`, section "Labels"). We publish no result about an implementation before its owner has reviewed it.

## What a result means

When your outcomes and ours agree, that is agreement on these 10 vectors, as both of us read section 3.5 of the -00 text. It is not a statement about ARD as a whole. Where they differ, our reading goes into a list of questions for the ARD authors. We publish that list with the answer key. Your reading goes into it only after you have reviewed the text, and without your name unless you consent in writing.
