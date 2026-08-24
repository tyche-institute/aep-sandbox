"""numguard — reject numbers whose JSON serialisation is implementation-dependent.

Motivation (Tyche Labs FINDING-001, 2026-08-24): the AEP receipt core is signed over
canonical JSON, and Python's ``json.dumps`` and ECMAScript's ``JSON.stringify`` do NOT
agree on how to render every number.  RFC 8785 (JSON Canonicalization Scheme) §3.2.2.3
mandates the ECMAScript rule (ECMA-262 §7.1.12.1), so where the two differ it is CPython
that is non-conformant.  Measured divergence classes:

    class                        example    Python        ECMAScript / JCS
    exponent zero-padding        1e-7       1e-07         1e-7
    exponential threshold        1e-6       1e-06         0.000001
    exponential threshold        0.00001    1e-05         0.00001
    large-integer form           1e16       1e+16         10000000000000000
    integral float trailing .0   2.0        2.0           2
    integer precision > 2**53    123456789012345678
                                            (exact)       123456789012345680

Any of these inside a signed payload makes the same document verify differently in the two
reference implementations.  This module does NOT change any verdict: it is a producer-side
guard, so that Round-0 assigned values stay sealed.  Verifier behaviour changes, if any,
belong to a later round with a new commitment.

Policy implemented here (the conservative option): a signed payload may carry only integers
in the exactly-representable range shared by both runtimes, i.e. |n| <= 2**53 - 1.  Floats
are rejected outright rather than canonicalised, because canonicalising them correctly means
reimplementing the ECMAScript number-to-string algorithm (Ryu/V8), which is a much larger
commitment than this format needs.
"""

from __future__ import annotations

MAX_SAFE_INTEGER = 2**53 - 1


class UnsafeNumber(ValueError):
    """Raised for a number whose canonical JSON form is implementation-dependent."""


def check(obj, path: str = "") -> None:
    """Walk *obj* and raise UnsafeNumber on the first number outside the safe space."""
    if isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise UnsafeNumber(
            f"{path or '<root>'}: float {obj!r} is not portable across canonical JSON "
            f"implementations (RFC 8785 mandates the ECMAScript form; CPython differs). "
            f"Use an integer, or a string carrying a fixed-point decimal."
        )
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INTEGER:
            raise UnsafeNumber(
                f"{path or '<root>'}: integer {obj} exceeds 2**53-1 and loses precision "
                f"when parsed by an ECMAScript JSON parser."
            )
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            check(v, f"{path}/{k}")
        return
    if isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            check(v, f"{path}[{i}]")
        return


def is_safe(obj) -> bool:
    try:
        check(obj)
    except UnsafeNumber:
        return False
    return True
