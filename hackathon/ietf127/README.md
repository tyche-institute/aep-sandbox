# IETF 127 Hackathon pack: can a stranger check it?

Prepared by Tyche Institute for the IETF 127 Hackathon (San Francisco, 14 and 15 November
2026). Everything here is test material: test keys, test names, test signatures.

The pack asks one question in 3 places. 2 people read the same text. Each builds a verifier
alone. Do they get the same answer on the same bytes?

## What is here

| Path | What it is | Time to start |
|:--|:--|:--|
| `round1/` | Round 1 for verifiers of Action Evidence Packages (AEP): 22 vectors, one return file, an answer key fixed in advance | 15 minutes to set up; writing a verifier takes longer |
| `cell1/` | Cell 1: one payload in 2 declared encodings, JSON and CBOR; 12 vectors | 10 minutes |
| `ard/` | Cell 2: a signed ARD trust manifest that points at a signed record; 10 vectors | 15 minutes |
| `onebyte/` | A demonstration: one byte, 2 verdicts from 2 verifiers of one owner. It holds and runs the Tyche verifiers, so open it after your Round 1 return | 5 minutes |
| `tools/` | `score.py` scores one return; `explain.py` shows where a verifier stops. `explain.py` runs the Tyche verifier, so use it after your Round 1 return | 10 minutes |
| `OUTCOMES.md` | The 4 outcome words used in the pack | 1 minute |
| `SEAL.sha256` | Our commitments (next section) | |
| `timestamps/` | 2 time-stamp tokens over `SEAL.sha256` (next section) | |
| `MANIFEST.sha256` | SHA-256 of every other file in the pack | |
| `LICENSE` | The MIT License text (section "Licences") | |

Each directory has its own `README.md`, and each one stands alone. To check that the files
are whole, run this in the directory of this page:

```sh
sha256sum -c MANIFEST.sha256
```

Every line must end in `OK`.

## The seal

We fixed our own answers and our own predictions before the hackathon room opened.
`SEAL.sha256` holds the SHA-256 of 4 files that we keep back:

| Line | File | What it is |
|:--|:--|:--|
| 1 | `round1/expected.json` | the Round 1 answer key |
| 2 | `cell1/expected.json` | our expected outcomes for cell 1 |
| 3 | `ard/expected.json` | our expected outcomes for cell 2 |
| 4 | `guesses/GUESS-LEDGER.md` | our predictions: where a first reader may read a text differently from us |

One value stands for all 4 lines, the SHA-256 of `SEAL.sha256` itself:

```
8d213af4da148ed8779a9c4663a02e2b847f2748311cba08f973d33ab2fb7303
```

Check it:

```sh
sha256sum SEAL.sha256
```

**When it was fixed.** `timestamps/` holds 2 time-stamp tokens (RFC 3161) over `SEAL.sha256`,
from 2 public time-stamping services. Each token shows a time at which this exact file
already existed. `timestamps/README.md` gives the 2 times and the commands that check them.

**When it opens.** The pack closes on Sunday 22 November 2026 at 23:59 UTC (Coordinated
Universal Time). By Sunday 29 November 2026 we add the 4 files to this pack, in a directory
`sealed/`, at the 4 paths that `SEAL.sha256` lists. With them come the Round 1 generator, the
3 Tyche verdict files (Python verifier, JavaScript port, reading of the text), our findings
file and our lists of questions for draft authors. To check the 4 files then, from the directory of this page:

```sh
(cd sealed && sha256sum -c ../SEAL.sha256)
```

**What the seal does.** It stops us from changing our answers after returns arrive.

**What it does not do.** It does not hide the verdicts. Our own verifiers are public, and
they compute them. The seal keeps back only which Round 1 vectors are scored, our notes on
each vector, and our predictions. So the 3 tests rest on an honour rule: build from the text
first, and run our code after. If you read or ran our code first, tell us. Your row keeps its
label, and we add a note: "read Tyche code first" or "ran Tyche code first". A return that
is the output of our code carries the label of our verifier.

## Labels

Every result row carries one of 4 labels. A label says how the writer of an implementation
relates to us, the builders of the test:

| Label | Meaning |
|:--|:--|
| author | written by Tyche Institute, which wrote every vector in this pack and the Round 1 specification |
| same-owner | a second or later implementation by an owner who already has a row; the first row keeps its own label |
| co-author | written by someone who co-authors the text under test, or a related Internet-Draft, with a Tyche Institute researcher |
| non-author | none of the above |

2 implementations of one owner count as one party. Code that Tyche Institute wrote jointly
with someone else counts as Tyche code: author or same-owner. A label follows these facts.
It is not a choice. In cell 2 the text under test is not ours. An implementation by an author of the ARD
draft is a non-author row, and we add "author of the draft" to it.

## What this pack does not claim

- It certifies nothing. Agreement means agreement on these vectors under the named text.
- VERIFIER-SPEC-v1 is a Tyche sandbox specification, not an IETF draft. Every Internet-Draft
  named in the pack is an individual draft. None is a working group document.
- The authors of the ARD draft have not reviewed or endorsed the material in `ard/`.
- We publish no ranking. Results appear under codes, and each sender gets the report for
  their own return. A name appears next to a result only with the written consent of the
  person named. We publish no result about an implementation before its owner has reviewed
  it.
- Tyche Institute publishes research. It is not a trust service provider, and nothing here is
  a trust service. Every signature in the pack is a research reference signature made with a
  test key.

## Licences

Unless a file says otherwise, the files in this pack are under the MIT License (`LICENSE`).
There are 2 exceptions. The 3 scripts in `cell1/tools/` are under the Revised BSD License
(`cell1/tools/LICENSE`): part of their CBOR code comes from the CDE repository. The file
`onebyte/vendor/site/verify.mjs` is under the Apache License 2.0
(`onebyte/vendor/site/LICENSE`).

## Abbreviations

| Short form | Meaning |
|:--|:--|
| AEP | Action Evidence Package |
| ARD | Agent Resource Discovery |
| CBOR | Concise Binary Object Representation (RFC 8949) |
| CDE | our short name for draft-mih-sokolov-cose-deterministic-encodings |
| COSE | CBOR Object Signing and Encryption (RFC 9052) |
| CPB | Canonical Payload Binding, draft-mih-sokolov-scitt-payload-binding |
| DID | Decentralized Identifier |
| EdDSA | Edwards-curve Digital Signature Algorithm (RFC 8032) |
| ES256 | Elliptic Curve Digital Signature Algorithm (ECDSA) on the P-256 curve with SHA-256 |
| external_aad | externally supplied data in a COSE signature (RFC 9052, section 4.3); empty in this pack |
| IANA | Internet Assigned Numbers Authority |
| IETF | Internet Engineering Task Force |
| JCS | JSON Canonicalization Scheme (RFC 8785) |
| JSON | JavaScript Object Notation |
| JWK | JSON Web Key (RFC 7517) |
| JWS | JSON Web Signature (RFC 7515) |
| KAT | known-answer test |
| kid | key identifier |
| PEM | Privacy-Enhanced Mail, a text encoding for keys (RFC 7468) |
| RFC | Request for Comments |
| SHA-256 | Secure Hash Algorithm with a 256-bit result |
| UTC | Coordinated Universal Time |

## Contact

The address on tyche.institute, or the AEP entry on the IETF 127 Hackathon wiki.
