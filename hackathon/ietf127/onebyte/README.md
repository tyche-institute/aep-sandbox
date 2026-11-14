# onebyte: one byte, 2 verdicts

This directory reproduces Round 0 Finding 001 of the AEP (Action Evidence Package) sandbox.

**Round 1 participants:** this directory holds and runs the Tyche verifiers. Do not open
`vendor/site/verify.mjs` and do not run `onebyte.py` before you send your Round 1 return
(`../round1/RULES.md`, section 4).

Tyche Institute maintains 2 sandbox verifiers. Both have the same owner:

- the Python sandbox verifier (author implementation), in the aep-sandbox repository;
- the JavaScript sandbox port (same-owner implementation), `vendor/site/verify.mjs`.

Both read the same package, Round 0 vector r0-15. It carries the number `1e-07`.
The Python canonical JSON writes `1e-07`. The JavaScript one writes `1e-7`.
So the 2 verifiers hash different bytes, and they return different verdicts.

The script then measures what RFC 8785 (JSON Canonicalization Scheme) gives for the same
number, in Python and in Node. It reports only what it measures.

## What you need

- Python 3 with the package `cryptography` (the sandbox verifier needs it for Ed25519 signatures).
- Node 20 or later. We ran Node 22.22.3 and Python 3.12.3. We did not test Node 20.
- git, to fetch the sandbox.

If `python3 -c "import cryptography"` fails, make a virtual environment first:

```sh
python3 -m venv venv
. venv/bin/activate
pip install cryptography
```

## Run it (about 5 minutes)

From this directory:

```sh
git clone https://github.com/tyche-institute/aep-sandbox
git -C aep-sandbox checkout 23cc05eba5af
python3 onebyte.py --sandbox aep-sandbox
```

We ran this on 2026-11-14 with the sandbox at commit 23cc05eba5af. The output was:

```text
One byte: Round 0 Finding 001 of the AEP sandbox, reproduced
package r0-15-probe-float-1e-7.aep.json   now=1750000100   consumed=[]
Python 3.12.3, Node v22.22.3

Verdicts on the same package with the same inputs:
  Python sandbox verifier (author)          ALLOW
  JavaScript sandbox port (same-owner)      DENY:content_mutated

Canonical bytes of the receipt core, as each verifier computes them:
  Python       1541 bytes   sha256 6d587db98bed43dff170b8d81d16a88a0a3f058c2f82ccccdc926d26ccc2207e
  JavaScript   1540 bytes   sha256 98e04e02afa6667532889a90e08a321197894505b721cd0cf7bf52e7613aae8e
  first differing byte: offset 31 (counted from 0)
  Python       {"action":{"args":{"amount":1e-07,"currency":"EUR","ord
  JavaScript   {"action":{"args":{"amount":1e-7,"currency":"EUR","orde
                                              ^ offset 31
  The number: Python renders 1e-07, JavaScript renders 1e-7.

RFC 8785 (JSON Canonicalization Scheme) for the same number:
  Python, number rule reimplemented in this script   1e-7
  Node, JSON.stringify                               1e-7
  RFC 8785 receipt core, Python against Node: identical (1540 and 1540 bytes)
  RFC 8785 receipt core against the JavaScript sandbox port's bytes: identical
  RFC 8785 receipt core against the Python sandbox verifier's bytes: different

The sandbox canonical form is not RFC 8785. VERIFIER-SPEC-v1 (a Tyche sandbox
specification, not an IETF draft) keeps signed numbers to integers.
```

Add `--json` for the same result as JSON.

## What this shows

- Python writes `1e-07` and JavaScript writes `1e-7`. The bytes differ from offset 31 on.
- The package was signed over the Python bytes. So the JavaScript port recomputes a different
  receipt hash and stops at chain integrity with `content_mutated`.
- Our Python reimplementation of the RFC 8785 number rule and Node's `JSON.stringify` both
  give `1e-7`. For this number, RFC 8785 gives the same bytes in both languages.
- The sandbox canonical form is not RFC 8785. VERIFIER-SPEC-v1 keeps signed numbers to
  integers, and section 2 defines no verdict for a package with a non-integer number.

## How the RFC 8785 number is computed

- In Python we reimplemented the number rule of RFC 8785 section 3.2.2.3 (the ECMAScript
  Number-to-String algorithm) in `onebyte.py`, function `es_number`. We copied no code for it.
- In Node, `JSON.stringify` applies that algorithm itself (`onebyte.mjs`, function `jcs`).
- Optional cross-check: the CPB library in the scitt-payload-binding repository has a `jcs`
  function. Point `--cpb` at the `lib` directory of a checkout. It needs the Python package
  `rfc8785`, which this script does not need otherwise.

## Files

- `onebyte.py`: the script you run.
- `onebyte.mjs`: the Node half. `onebyte.py` calls it.
- `vendor/site/verify.mjs`: the JavaScript sandbox port, unmodified. Source: the
  tyche-institute-site repository, file `public/lab/aep-ctf/verify.mjs`, last changed in commit
  86f8f8e48477. It is the same file as `https://tyche.institute/lab/aep-ctf/verify.mjs`
  on 2026-11-14 (SHA-256 75e9e083b3794f3d76d68978754dfece8ea6e5eb306aeca479a10419a763376a).
  Licence: Apache License 2.0, in `vendor/site/LICENSE`. The comment at the top of the file
  is the port's own text. It calls the port "faithful" and names a parity test,
  `parity-test.mjs`, which is not in this pack. This directory shows one input on which the
  port and the Python verifier differ.

Contact: the address on tyche.institute, or the AEP entry on the IETF 127 Hackathon wiki.
