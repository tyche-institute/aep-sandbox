# Cell 1: one payload, 2 declared encodings

IETF 127 Hackathon, San Francisco, 14 and 15 November 2026. Prepared by Tyche Institute.

## What this cell tests

We take one small payload. It describes one agent action. We encode it in 2 ways:

- **JSON side.** The RFC 8785 JSON Canonicalization Scheme (JCS) bytes.
- **CBOR side.** The Concise Binary Object Representation (CBOR) bytes under the core deterministic encoding of RFC 8949 Section 4.2.1.

Each side goes into a COSE_Sign1 record (CBOR Object Signing and Encryption, RFC 9052). Each record is an RFC 9995 Hash Envelope: the COSE payload is the SHA-256 digest of the encoded bytes. The protected header says which encoding the digest was taken over:

- JSON side: the `cpb-refs` header parameter of draft-mih-sokolov-scitt-payload-binding-06 (we call it CPB). It carries one reference: a type name, a digest algorithm and a digest. The type name points at an entry in `declaration.json`. That entry names `jcs`.
- CBOR side: the `deterministic-encodings` header parameter of draft-mih-sokolov-cose-deterministic-encodings-00 (we call it CDE), with value 1 (`core-deterministic`).

Both are individual Internet-Drafts.

The question for each vector: a verifier holds the payload as a JSON value, not the hashed bytes. Can it re-create the bytes from the header's declaration and match the digest?

There are 12 vectors, `c1-01` to `c1-12`. Some should be accepted and some should not. The names and their order say nothing about which is which.

Our expected outcomes are the answer key of this cell. We fixed them in advance: their SHA-256 is line 2 of `../SEAL.sha256`. We publish the file after the pack closes (`../README.md`, section "The seal"). The seal fixes our answers. It does not hide them: our verifier in `tools/` computes them. So please build and run your own verifier first. If you ran ours first, tell us: your row keeps its label, and we add the note "ran Tyche code first".

Our answers come from our own verifier and our own reading of the 2 drafts. No outside reader has checked them.

## Honest boundaries

- **Who built this.** Tyche Institute built the payload, the records, the vectors and the tools. A Tyche researcher co-authors both drafts. So a check at a co-author's table is at most a co-author cross-check. It is not a check by a non-author.
- **Implementation labels.** The 4 labels are defined in `../README.md`. `tools/verify_cell1.py` and `tools/sign_cell1.py`: author (Tyche Institute). The 2 draft repositories hold commits from Tyche Institute and from the co-author. So we label their reference code same-owner, the stricter label. Code that the co-author wrote alone: co-author. Any other code: tell us who wrote it, and we set the label.
- **Shared code.** The CBOR encoder and decoder in `tools/cell1lib.py` are adapted from the Python library in the CDE repository (`lib/python/cose_det_enc.py`). So on the CBOR side our verifier and that library share code. Agreement between those 2 shows less than agreement between 2 separately written codecs.
- **What a reader can see without a verifier.** Many vectors are small changes to one record or to the held value, and `payload/KAT.json` prints the digests. So comparing bytes predicts most outcomes. Tell us how you got each outcome: by verifying, or by comparing bytes. A return made by comparing bytes shows less about the drafts.
- **2 registries.** The 2 drafts keep separate registries. CPB has a canonicalization algorithm registry (it holds `jcs`). CDE has a deterministic encodings registry (value 1 is `core-deterministic`).
- **JCS is not a CDE value.** JCS is not a value of the CDE header parameter. We do not invent one. The JSON side declares JCS through CPB.
- **Test-only labels.** The CDE header label 271 is the value CDE -00 suggests. It is not assigned. We use it for this test. The `cpb-refs` label -65537 is a test-only private-use label, as in the CPB repository. It is not an IANA (Internet Assigned Numbers Authority) assignment.
- **Draft revisions.** The vectors are cut against CDE -00 and CPB -06. A later CDE revision may change the header value.
- **Keys and signatures.** The records are signed with a fresh Ed25519 test key. The signatures are research reference signatures made with this test key. The test public key is in `keys/`. We do not publish the private test key.
- **No claim of use.** We make no statement that anyone runs an implementation of these drafts.

## Files

| Path | What it is |
|---|---|
| `payload/payload.json` | The payload as a JSON value (the "held value"). Integers and strings, no floating-point numbers. |
| `payload/payload.jcs` | The RFC 8785 bytes of the payload. |
| `payload/payload.cbor` | The RFC 8949 Section 4.2.1 bytes of the payload. |
| `payload/KAT.json` | Known-answer values (KAT means known-answer test): lengths and SHA-256 of the 2 encodings and of the artifact. |
| `artifact/subject-artifact.txt` | A small artifact. Member `subject.digest` of the payload is `sha256:` plus its SHA-256 in hex, so a later manifest can bind to it. |
| `declaration.json` | The declarations the records rely on: the CPB digest context, the labels, the JSON-to-CBOR mapping, the signing parameters. |
| `keys/test-public-key.pem`, `.hex` | The Ed25519 test public key. |
| `vectors/c1-NN.cose` | One tagged COSE_Sign1 record per vector. |
| `vectors/c1-NN.held.json` | The JSON value the verifier holds for that vector. |
| `vectors/index.json` | The list of vectors and their files. |
| `RETURN-TEMPLATE.json` | An empty return file. Copy it and fill in the copy. |
| `tools/` | Our signer and verifier (Python 3 built-in modules plus `cryptography`; the small CBOR encoder and decoder are adapted from the Python library in the CDE repository, so `cbor2` is not needed). |
| `FOR-OTHER-IMPLEMENTERS.md` | How to make your own 2 records so that we can check yours. |

## Rules for a verifier in this cell

1. Check the signature (RFC 9052 Section 4.4, EdDSA, external_aad empty) with `keys/test-public-key.pem`. A signature that does not check makes the vector `failed`.
2. You hold the JSON value in `c1-NN.held.json`. You do not hold the hashed bytes. Re-create them from the value.
3. JSON side (the record carries `cpb-refs`): follow CPB -06 and `declaration.json`. Apply RFC 8785 to the held value.
4. CBOR side (no `cpb-refs`): follow CDE -00, section "Producer and Verifier Behavior", for a verifier that holds a structured value. Map the JSON value to CBOR as `declaration.json` says, then encode it.
5. Report one outcome per vector: `verified`, `failed` or `unverified`. These are the 3 CDE outcomes. They match `../OUTCOMES.md`. Add a short reason.

## Run it (about 10 minutes)

You need Python 3.9 or later and the `cryptography` package.

```sh
# run these from this directory (cell1/)
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install cryptography
```

**Step 1. Check the encodings.** Compare with `payload/KAT.json`.

```sh
sha256sum payload/payload.jcs payload/payload.cbor artifact/subject-artifact.txt
```

You should see:

```
1782e421322b5fd570528a61e63b88a3c6c7434f4ef0b5991ed30894fba2aa3e  payload/payload.jcs
ae533a625913f9909b9d63ade20905d7228e38688acaf8d1b5bebe7515c05a01  payload/payload.cbor
2c87a2f26d64a675089441dc2db1eece6e6904c7edb18e6ce329cd698c7cc6fb  artifact/subject-artifact.txt
```

To re-create both encodings from `payload/payload.json` with your own code, compare your bytes with these files.

**Step 2. Run your verifier** on `vectors/`. Copy `RETURN-TEMPLATE.json` to `my-return.json` and fill in the copy. The format is a JSON array:

```json
[
  {"id": "c1-01", "outcome": "verified | failed | unverified", "reason": "short text"}
]
```

We compare the `outcome` values. The `reason` helps us find where readings differ. Our verifier uses these reason words; you may use your own:
`signature-invalid`, `alg-not-implemented`, `cose-malformed`, `parameter-in-unprotected-header`, `crit-malformed`, `crit-not-understood`, `content-type-absent`, `content-type-mismatch`, `content-type-label-3-present`, `encoding-absent`, `encoding-not-implemented`, `value-not-encodable`, `held-value-rejected`, `held-value-not-implemented`, `cpb-refs-malformed`, `cpb-refs-not-critical`, `context-unresolved`, `context-not-implemented`, `digest-alg-mismatch`, `hash-alg-absent`, `representation-mismatch`, `hash-alg-not-implemented`, `recreated-digest-match`, `recreated-digest-mismatch`.

**Step 3 (optional). Run our verifier** after you have your own return, and compare.

```sh
python3 tools/verify_cell1.py --out tyche-return.json
python3 tools/verify_cell1.py --checks --out tyche-return.json   # also prints each check: pass, fail or not_evaluated
```

Each command prints one row per vector (`id`, `side`, `outcome`, `reason`) and writes the return file. Without `--out`, the file is `return.json`.

**Step 4. Send your return** to the address on tyche.institute, or hand it to the Tyche table at the hackathon. Say which implementation produced it, who wrote it, and whether you verified or compared bytes. We set the label (`../README.md`, section "Labels"). We publish no result about an implementation before its owner has reviewed it.

## What a result means

When your outcomes and ours agree, that is agreement on these 12 vectors under the rules above. It is not a statement about either draft as a whole. Where they differ, our reading goes into a list of questions for the draft authors. We publish that list with the answer key. Your reading goes into it only after you have reviewed the text, and without your name unless you consent in writing.
