# tools

## explain.py: how a verifier stops

The AEP (Action Evidence Package) sandbox verifier stops at the first check that fails.
Its list of checks ends there. `explain.py` makes the rest visible: after the first
failure, the later checks are reported as `not_evaluated`, not as passed.

VERIFIER-SPEC-v1 is a Tyche sandbox specification, not an IETF draft. Its section 4 orders 6
checks: structure, chain integrity, package signature, measurements, mandate chain (steps a to
g), replay. `explain.py` prints one row for each, plus the 7 mandate steps.

`explain.py` calls the unmodified sandbox verifier. It maps the reason the verifier returns to
the check that owns it, and reports. It never changes a verdict. The words it uses are defined
in `../OUTCOMES.md`.

### What you need

- Python 3 with the package `cryptography` (the sandbox verifier needs it). We ran Python 3.12.3.
- git, to fetch the sandbox.

If `python3 -c "import cryptography"` fails, make a virtual environment first:

```sh
python3 -m venv venv
. venv/bin/activate
pip install cryptography
```

### Run it (about 10 minutes)

**Round 1 participants:** `explain.py` runs the Tyche verifier, and the aep-sandbox checkout
holds its source (`verify.py`, `aep/`). Do not run `explain.py` and do not open that source
before you send your Round 1 return (`../round1/RULES.md`, section 4).

From this directory, fetch the sandbox at the commit we used:

```sh
git clone https://github.com/tyche-institute/aep-sandbox
git -C aep-sandbox checkout 23cc05eba5af
```

If you already have a checkout of aep-sandbox, pass its path as `--sandbox` instead.

1. A package that the sandbox verifier accepts:

```sh
python3 explain.py --sandbox aep-sandbox aep-sandbox/samples/good.aep.json
```

Every row is `pass`, the sandbox verdict is `ALLOW`, and the outcome is `verified`.

2. A package that exceeds its mandate:

```sh
python3 explain.py --sandbox aep-sandbox aep-sandbox/samples/exceed-scope.aep.json
```

Real output:

```text
package: exceed-scope.aep.json
  now=1750000100  consumed=[]
  1   structure                                    pass
  2   chain integrity                              pass
  3   package signature                            pass
  4   measurements                                 pass
  5   mandate chain                                fail  reason=scope_violation
    5a  credential and mandate bodies are objects    pass
    5b  issuer listed with this key                  pass
    5c  issuer signature on credential               pass
    5d  principal signature on mandate               pass
    5e  mandate names this agent                     pass
    5f  action inside scope                          fail  reason=scope_violation
    5g  not after expiry                             not_evaluated
  6   replay                                       not_evaluated
  sandbox verdict: DENY:scope_violation
  outcome: failed
```

3. The same accepted package, submitted again after its nonce was used:

```sh
python3 explain.py --sandbox aep-sandbox --consumed aep-nonce-0001 aep-sandbox/samples/good.aep.json
```

Row 6 (replay) is `fail  reason=replayed`, and the outcome is `failed`.

4. All 18 public Round 0 vectors, each with its own `now` and consumed nonces from `cases.json`:

```sh
python3 explain.py --sandbox aep-sandbox --cases aep-sandbox/interlab/round0/vectors/cases.json --trust aep-sandbox/interlab/round0/trusted_issuers.json
```

Add `--case r0-15` to run one entry. On r0-14 and r0-15 the sandbox verdict is `ALLOW`, but the
outcome is `unverified`. These packages carry a non-integer number. Section 2 of
VERIFIER-SPEC-v1 defines no verdict for them.

5. The sandbox attacks. `make attacks` writes the attack packages into `attacks/out/`:

```sh
(cd aep-sandbox && make attacks)
python3 explain.py --sandbox aep-sandbox aep-sandbox/attacks/out/*.aep.json
```

Add `--json` to any command for JSON output.

### Options

| Option | Meaning |
|---|---|
| `--sandbox PATH` | a checkout of aep-sandbox (required) |
| `--now N` | appraisal time, in seconds; default 1750000100, as in the sandbox's `verify.py` |
| `--consumed NONCE` | a consumed nonce, as a string; repeat the flag for more |
| `--consumed-json LIST` | consumed nonces as a JSON list, so a number stays a number |
| `--trust FILE` | trust anchor file; default `SANDBOX/keys/trusted_issuers.json` |
| `--cases FILE`, `--case NAME` | read `file`, `now` and `consumed` from a cases.json |
| `--json` | JSON output |

Exit status: 0 when every package got a sandbox verdict, 1 when a file could not be loaded.

### Limits

- `explain.py` derives the failing check from the reason string. It cross-checks that against
  the check list the verifier returns, and prints `PROBLEM:` if they disagree.
- If the sandbox verifier raises an exception, its `verify.py` reports `malformed_aep` at
  structure. `explain.py` keeps that verdict, but marks the check where the exception happened
  and adds a note.
- The number-profile test looks at the parsed JSON. A duplicate key is already gone at that point.

## score.py: score one return

`score.py` compares one return file with a key. It needs the Python 3 standard library only.

| Command | What it does |
|---|---|
| `python3 score.py RETURN --check-format ../round1/vectors/cases.json` | checks the format of a Round 1 return; scores nothing |
| `python3 score.py RETURN --round0-open aep-sandbox/interlab/round0/vectors/cases.json` | scores a return against the open Round 0 practice set |
| `python3 score.py RETURN --key ../sealed/round1/expected.json` | scores a Round 1 return, once the answer key is published |
| `python3 score.py --self-test` | runs the tool's own checks; ends with `self-test: PASS` |

With `--key` or `--round0-open`, add `--format json` for JSON output and `--out FILE` to
write the report to a file. `--check-format` prints to the terminal only and ignores both
options. The report covers one return. It is not a ranking.

Contact: the address on tyche.institute, or the AEP entry on the IETF 127 Hackathon wiki.
