# Released sealed material

Round 1 closed on Sunday 22 November 2026 at 23:59 UTC. This directory holds what the
rules (`../round1/RULES.md`, section 5) said would stay withheld until then. Released on
23 November 2026. No file outside this directory was changed, so `../SEAL.sha256`,
`../MANIFEST.sha256` and the time-stamp tokens in `../timestamps/` are as published on
14 November 2026.

## Round 1 (`round1/`)

| file | what it is |
|:--|:--|
| `expected.json` | the key: class, scored or not, verdict, reason and deciding clause for each of the 22 vectors |
| `generate_round1.py` | the generator of the vectors |
| `verdicts-python.json` | verdicts of the Tyche Python verifier |
| `verdicts-js.json` | verdicts of the Tyche JavaScript port |
| `verdicts-spec-reading.json` | verdicts from a reading of the specification text made at Tyche Institute |
| `findings.md` | the vectors without an assigned value, and 3 observations outside the corpus |

All 3 verdict files come from one owner. The key rests on no outside reading.

Check the commitment (run in `hackathon/ietf127/`):

```sh
sha256sum sealed/round1/expected.json
head -1 SEAL.sha256
```

Both lines must show `38a07c9e8c91e15a99737cad9ec5e93397cbb3a1e05f3c22984f58be0a581745`.

Score a return against the key:

```sh
python3 tools/score.py your-return.json --key sealed/round1/expected.json
```

18 vectors are scored. 4 are unscored: r1-01, r1-05, r1-09 and r1-15. `findings.md`
explains r1-05, r1-09 and r1-15: the specification leaves their verdict open.

## Not released

- The test signing keys and the ordering salt that the generator reads from `keys/` stay
  private: with them anyone could make valid-looking vectors. Without them the generator
  can be read but does not reproduce the vectors.
- Results of returns. Each sender sees the report on their own return first (rules,
  section 8).

## Still to come, by Sunday 29 November 2026

The other 3 files named in `../SEAL.sha256` (`cell1/expected.json`, `ard/expected.json`,
`guesses/GUESS-LEDGER.md`).
