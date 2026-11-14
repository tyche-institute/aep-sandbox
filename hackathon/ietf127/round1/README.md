# AEP verifier Round 1: a sealed verdict round

Tyche Institute opens this round at the IETF 127 Hackathon (14 and 15 November 2026, San
Francisco). You write a verifier for Action Evidence Packages (AEP) from a short
specification. You run it on 22 test vectors. You send us one JSON file with your verdicts.
We score it against an answer key. Its SHA-256 was fixed in advance (`../README.md`, section
"The seal").

The specification is `VERIFIER-SPEC-v1.md` in this directory. It is a Tyche sandbox
specification, not an IETF draft. A verdict that matches ours is "agreement under
VERIFIER-SPEC-v1, a Tyche sandbox specification, not an IETF draft". It is not a
certificate of anything.

The full rules are in `RULES.md`. This page is the short path.

## What is here

| path | what it is |
|:--|:--|
| `VERIFIER-SPEC-v1.md` | the frozen specification (version 1, frozen 24 August 2026) |
| `VERIFIER-SPEC-v1.sha256` | its SHA-256, copied unchanged from the source repository |
| `vectors/r1-01.aep.json` ... `vectors/r1-22.aep.json` | the 22 test vectors |
| `vectors/cases.json` | the run inputs for each vector: `file`, `now`, `consumed` |
| `trusted_issuers.json` | the trust anchor list (issuer id to Ed25519 public key, hex) |
| `RULES.md` | the rules of the round |
| `MANIFEST.sha256` | SHA-256 of every other file in this directory |
| `make_manifest.py` | the script we used to write `MANIFEST.sha256`; do not run it to check the files |

The scoring tool is `../tools/score.py`. It runs on the Python 3 standard library.

Every key in the vectors is a test key. Every signature in them is a research reference
signature made with a test key. None of them authorises anything real.

## The 15-minute path

These steps get you set up in under 15 minutes. Writing the verifier takes longer.

**1. Check the files.** In this directory:

```sh
sha256sum -c MANIFEST.sha256
```

Every line must end in `OK`. To check the specification against its published hash:

```sh
sha256sum VERIFIER-SPEC-v1.md
cat VERIFIER-SPEC-v1.sha256
```

The 2 hashes must be the same: `591eafd1a704c7d3a67e9ea37b4d3e8f1f203715320654f9c5e2e4b3742bb97d`.
The `.sha256` file names the path the file has in the source repository
(`interlab/spec/VERIFIER-SPEC-v1.md`), so `sha256sum -c VERIFIER-SPEC-v1.sha256` does not
work from this directory. Compare the 2 hashes by eye instead.

**2. Read the specification.** Sections 2 (canonical form), 3 (receipt core), 4 (the ordered
checks) and 5 (notes) are what your verifier needs. It is 85 lines.

**3. Look at the inputs.**

```sh
python3 -m json.tool vectors/cases.json | head -20
python3 -m json.tool trusted_issuers.json
```

For each vector, `now` is the current time to use at check 5g (an integer, seconds), and
`consumed` is the set of nonces already used, for check 6. Compare nonces by value and
type, as section 5 of the specification says.

**4. Write your verifier.** Build it from the specification and the vectors. Do not run
or read the Tyche verifiers before you send your return (see "Clean-room rule" below). You
need SHA-256 and Ed25519 signature checking. In Python, the package `cryptography` has both.
Node has both in WebCrypto (we ran Node 22).

The specification does not name every member of a package. Where it is silent, read the
member names off the vectors, and tell us each place where you had to guess.

**5. Run it on every vector** with that vector's `now` and `consumed`, and write one return
file (format below).

**6. Check the format of your return** before you send it. From this directory:

```sh
python3 ../tools/score.py my-return.json --check-format vectors/cases.json
```

It prints `format OK: 22 rows, ...` or lists the problems. It does not score anything:
we publish the answer key only after the round closes.

**7. Send it** (see "Where to send a return").

## Return format

One JSON array, one object per vector, with these 3 members:

```json
[
  {"file": "example-a.aep.json", "verdict": "ALLOW", "reason": null},
  {"file": "example-b.aep.json", "verdict": "DENY", "reason": "expired"}
]
```

(The 2 rows above show the format only. Their file names are not in the round.)

- `file` is the file name as listed in `vectors/cases.json`.
- `verdict` is `ALLOW` or `DENY`.
- On `ALLOW`, `reason` is `null`.
- On `DENY`, `reason` is one of these 12 words: `malformed_aep`, `content_mutated`,
  `aep_sig_invalid`, `measurement_mismatch`, `malformed_mandate`, `issuer_not_listed`,
  `credential_sig_invalid`, `principal_sig_invalid`, `agent_binding_mismatch`,
  `scope_violation`, `expired`, `replayed`.
- Give a verdict for every vector, including any that you think is outside the
  specification's integer-only profile. If your verifier rejects a file, return the reason
  it gives.
- The format check ignores any other member. It reads a missing `reason` on `ALLOW` as
  `null`.

Please also send, in the same message or as a second file:

- which version of the specification you read (`VERIFIER-SPEC-v1`, SHA-256 above);
- whether you read or ran any Tyche verifier before you returned (see below);
- who, if anyone, reviewed your code;
- the language and the libraries you used;
- whether we may name you when we publish results. The default is no.

## Clean-room rule

Section 6 of the specification describes a clean-room lane. Build from VERIFIER-SPEC-v1 and
the vectors. Do not run or read the Tyche verifiers before you return. A copy of one is in
this pack: leave `../onebyte/` and `../tools/explain.py` until you have sent your return.
This is an honour rule: we cannot check it, and we do not try to.

A return made by running our code is still welcome. Tell us. It carries the label of the
Tyche verifier that was run, and it measures our own code, not the specification. If you
read or ran our code and then wrote your own verifier, tell us too. Your row keeps its own
label, and we add a note to it.

## What the seal does

The seal is a commitment. It stops us from changing the key after returns arrive. It does
not hide the key: the public Tyche verifiers compute the scored values. That is why the
clean-room rule matters.

## Where to send a return

Send the file to the address on tyche.institute, or hand it to the Tyche table at the
hackathon. You can also reach us through the AEP entry on the IETF 127 Hackathon wiki.

The round closes on Sunday 22 November 2026 at 23:59 UTC (Coordinated Universal Time). We
confirm each return when it arrives.

## What happens after

The answer key (`expected.json`) is sealed. Its SHA-256 commitment is:

```
38a07c9e8c91e15a99737cad9ec5e93397cbb3a1e05f3c22984f58be0a581745
```

The same value is line 1 of `../SEAL.sha256`, next to the commitments of the other parts of
this pack.

By Sunday 29 November 2026 we publish the key, the generator, the 3 Tyche verdict files
(Python verifier, JavaScript port, reading of the text) and our findings file. They go into this pack, under `../sealed/round1/`. You can then
check that the SHA-256 of the key equals the commitment above, and score your own return:

```sh
python3 ../tools/score.py my-return.json --key ../sealed/round1/expected.json
```

Each sender also gets the report for their own return from us. Before scoring, we replace
the sender's name on every return with a code. We publish no ranking. A name appears next to
a result only with the written consent of the person named.

## Practice on Round 0

Round 0 is the open practice set: its expected verdicts are published in its `cases.json`.
It lives in the public aep-sandbox repository of Tyche Institute (linked from
tyche.institute), directory `interlab/round0`. That repository also holds the Tyche Python
verifier (`verify.py`, `aep/`) and the Round 0 runners (`run_reference.py`, `run_port.mjs`,
`compare.py`). Before your Round 1 return, use only `interlab/round0/vectors/` and
`interlab/round0/trusted_issuers.json`. Do not open or run the rest. To score yourself on
Round 0:

```sh
python3 ../tools/score.py my-round0-return.json --round0-open path/to/interlab/round0/vectors/cases.json
```

Round 0 file names describe each vector, so it is good for debugging and says nothing about
a blind result.

## Scoring tool self-test

```sh
python3 ../tools/score.py --self-test
```

It ends with `self-test: PASS`.

## Older texts

The specification is frozen, so we do not edit it. Its opening lines say "Tyche Labs
interlaboratory comparison" and "independent implementation". Read them as "Tyche Institute
sandbox comparison" and as the 4 labels of `RULES.md`, section 9. Section 6 of the
specification says we publish each participant's statement verbatim. In Round 1 we publish
it only after the participant has reviewed it, and without names unless the person named
consents in writing.

The Round 0 texts in the aep-sandbox repository use older words too: "conformance",
"independently written", "interlaboratory comparison", "auditing" and "proficiency testing".
Round 1 does not describe itself in these words. Where the Round 0 texts differ from this
page or from `RULES.md`, the Round 1 texts govern.

"Finding 001" in section 2 of the specification is the number-rendering split between the 2
Tyche verifiers. `../onebyte/` reproduces it.
