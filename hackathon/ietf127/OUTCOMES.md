# Outcome words used in this pack

We use 4 words for results: 3 for a package, a record or an entry, and 1 for a single check.
`tools/explain.py` and the verifiers in `cell1/` and `ard/` print them in this sense. Round 1
returns use the sandbox words `ALLOW` and `DENY`. The mapping is below.

| Word | Applies to | Meaning |
|---|---|---|
| `verified` | a package | The verifier returned a verdict, every check passed, and the package is inside the profile of the specification. |
| `failed` | a package | The verifier returned a verdict, and one check failed. The reason names that check. |
| `unverified` | a package | No verdict can be relied on: the file could not be loaded, or the specification defines no verdict for the package. |
| `not_evaluated` | a check | The check gave no result: an earlier check had already failed, or the check could not be made (for example, the verifier does not implement an algorithm). It is neither a pass nor a failure. |

A single check reports `pass`, `fail` or `not_evaluated`.

## How the AEP sandbox verdicts map

The AEP (Action Evidence Package) sandbox verifier returns `ALLOW`, or `DENY` with a reason.
VERIFIER-SPEC-v1 is a Tyche sandbox specification, not an IETF draft. Its section 4 orders 6
checks: structure, chain integrity, package signature, measurements, mandate chain (steps a to
g), replay.

- `ALLOW` maps to `verified`: all 6 checks `pass`.
- `ALLOW` on a package that carries a non-integer number, or an integer outside the range
  from -(2^53 - 1) to 2^53 - 1, maps to `unverified`. Section 2 of VERIFIER-SPEC-v1 puts such
  a package outside the profile and defines no verdict for it. We still print the sandbox
  verdict unchanged.
- `DENY:<reason>` maps to `failed`: the check that owns the reason is `fail`, the checks
  before it are `pass`, and the checks after it are `not_evaluated`.
- A file that cannot be read or parsed as JSON gets no verdict. It maps to `unverified`.

The verifier stops at the first failure. So a `failed` package tells you nothing about its
later checks. `not_evaluated` says exactly that.

## Cells 1 and 2

In `cell1/` and `ard/` the same 3 words apply to a record or to an ARD (Agent Resource
Discovery) entry:

- `verified`: every check passed.
- `failed`: one check failed.
- `unverified`: a check could not be made, for example because the declared encoding is
  absent or not implemented.
