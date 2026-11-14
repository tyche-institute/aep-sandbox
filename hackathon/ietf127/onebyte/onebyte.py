#!/usr/bin/env python3
"""onebyte.py - reproduce Round 0 Finding 001 of the AEP sandbox: one byte, 2 verdicts.

The Python sandbox verifier (author implementation) and the JavaScript sandbox port
(same-owner implementation) read the same package, r0-15. Their canonical JSON renders the
number 1e-07 differently, so they compute different bytes and return different verdicts.
This script shows both verdicts, the first differing byte offset and both strings. Then it
measures what RFC 8785 (JSON Canonicalization Scheme) gives for the same number in Python
and in Node.

  python3 onebyte.py --sandbox PATH_TO_AEP_SANDBOX [--json] [--node node] [--cpb PATH]

Needs: Python 3 with the package "cryptography" (the sandbox verifier needs it), and Node 20
or later. --cpb is optional (see README.md).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VECTOR = "r0-15-probe-float-1e-7.aep.json"


# --------------------------------------------------------------------------------------
# RFC 8785 in Python. The number rule is REIMPLEMENTED here, not copied: RFC 8785 section
# 3.2.2.3 uses the ECMAScript Number-to-String algorithm (ECMA-262, Number::toString).
# Python's repr(float) gives the shortest digit string that round-trips; we lay those
# digits out with the ECMAScript rules.
# --------------------------------------------------------------------------------------
def es_number(x) -> str:
    if isinstance(x, bool):
        raise TypeError("not a number")
    if isinstance(x, int):
        x = float(x)  # RFC 8785 treats every JSON number as an IEEE 754 double
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not JSON")
    if x == 0:
        return "0"  # also -0
    if x < 0:
        return "-" + es_number(-x)
    r = repr(x)
    mant, _, exp = r.partition("e")
    exp = int(exp) if exp else 0
    ip, _, fp = mant.partition(".")
    digits = (ip + fp).lstrip("0")
    e = exp - len(fp)
    stripped = digits.rstrip("0")
    e += len(digits) - len(stripped)
    s, k = stripped, len(stripped)
    n = k + e  # value = s * 10^(n-k)
    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e1 = n - 1
    sign = "+" if e1 >= 0 else "-"
    head = s if k == 1 else s[0] + "." + s[1:]
    return f"{head}e{sign}{abs(e1)}"


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\t\n\f\r":
            out.append({"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}[ch])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return es_number(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(x) for k, x in items) + "}"
    raise TypeError(type(v).__name__)


# --------------------------------------------------------------------------------------
def first_diff(a: bytes, b: bytes):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return None if len(a) == len(b) else min(len(a), len(b))


def window(b: bytes, off: int, before=32, after=24) -> str:
    lo = max(0, off - before)
    return b[lo:off + after].decode("utf-8", "replace"), off - lo


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Reproduce Round 0 Finding 001 (one byte).")
    ap.add_argument("--sandbox", required=True, help="path to a checkout of aep-sandbox")
    ap.add_argument("--node", default="node", help="Node executable (20 or later)")
    ap.add_argument("--verify-mjs", default=os.path.join(HERE, "vendor", "site", "verify.mjs"),
                    help="the JavaScript sandbox port (default: the vendored copy)")
    ap.add_argument("--cpb", help="optional: the lib/ directory of a scitt-payload-binding "
                    "checkout, to also run its jcs function (needs the rfc8785 package)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()

    sb = os.path.abspath(args.sandbox)
    vec_dir = os.path.join(sb, "interlab", "round0", "vectors")
    pkg_path = os.path.join(vec_dir, VECTOR)
    trust_path = os.path.join(sb, "interlab", "round0", "trusted_issuers.json")
    with open(os.path.join(vec_dir, "cases.json"), encoding="utf-8") as fh:
        case = next(c for c in json.load(fh) if c["file"] == VECTOR)
    now, consumed = int(case["now"]), set(case.get("consumed", []))

    # Python sandbox verifier, unmodified, with the same fail-closed guard as verify.py.
    sys.path.insert(0, sb)
    from aep import mandate, package  # noqa: E402
    from aep.canonical import canonical_bytes  # noqa: E402

    aep = package.load(pkg_path)
    with open(trust_path, encoding="utf-8") as fh:
        trust = mandate.TrustStore.from_dict(json.load(fh))
    try:
        py = package.verify_aep(aep, trust, now=now, consumed=consumed)
    except Exception:  # noqa: BLE001
        py = {"verdict": "DENY", "reason": "malformed_aep", "checks": []}
    py_core = canonical_bytes(package._receipt_core(aep))

    # JavaScript sandbox port, unmodified, in Node.
    proc = subprocess.run([args.node, os.path.join(HERE, "onebyte.mjs"), args.verify_mjs,
                           trust_path, pkg_path, str(now)], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"node failed with exit status {proc.returncode}")
    js = json.loads(proc.stdout)
    js_core = js["canonical_core"].encode("utf-8")

    off = first_diff(py_core, js_core)
    amount = aep["action"]["args"]["amount"]
    py_jcs_core = jcs(package._receipt_core(aep)).encode("utf-8")
    node_jcs_core = js["rfc8785_core"].encode("utf-8")
    cpb_amount = cpb_core = None
    if args.cpb:
        sys.path.insert(0, os.path.abspath(args.cpb))
        from cpb.canonicalize import jcs as cpb_jcs  # noqa: E402
        cpb_amount = cpb_jcs(amount).decode("utf-8")
        cpb_core = cpb_jcs(package._receipt_core(aep))

    def tag(r):
        return r["verdict"] + (f":{r['reason']}" if r.get("reason") else "")

    rep = {
        "package": VECTOR, "now": now, "consumed": sorted(consumed),
        "python_verdict": tag(py), "javascript_verdict": tag(js),
        "python_core_len": len(py_core), "javascript_core_len": len(js_core),
        "python_core_sha256": sha(py_core), "javascript_core_sha256": sha(js_core),
        "first_diff_offset": off,
        "python_amount": canonical_bytes(amount).decode(), "javascript_amount": js["amount_sandbox"],
        "rfc8785_amount_python": es_number(amount), "rfc8785_amount_node": js["amount_rfc8785"],
        "rfc8785_core_python_sha256": sha(py_jcs_core), "rfc8785_core_node_sha256": sha(node_jcs_core),
        "rfc8785_core_python_len": len(py_jcs_core), "rfc8785_core_node_len": len(node_jcs_core),
        "rfc8785_cores_identical": py_jcs_core == node_jcs_core,
        "rfc8785_core_equals_javascript_core": node_jcs_core == js_core,
        "rfc8785_core_equals_python_core": py_jcs_core == py_core,
        "cpb_jcs_amount": cpb_amount,
        "cpb_jcs_core_identical_to_node": (cpb_core == node_jcs_core) if cpb_core is not None else None,
        "python": sys.version.split()[0], "node": js["node"],
    }
    if args.json:
        print(json.dumps(rep, indent=2))
        return 0

    print("One byte: Round 0 Finding 001 of the AEP sandbox, reproduced")
    print(f"package {VECTOR}   now={now}   consumed={sorted(consumed)}")
    print(f"Python {rep['python']}, Node {rep['node']}")
    print()
    print("Verdicts on the same package with the same inputs:")
    print(f"  Python sandbox verifier (author)          {rep['python_verdict']}")
    print(f"  JavaScript sandbox port (same-owner)      {rep['javascript_verdict']}")
    print()
    print("Canonical bytes of the receipt core, as each verifier computes them:")
    print(f"  Python       {len(py_core)} bytes   sha256 {rep['python_core_sha256']}")
    print(f"  JavaScript   {len(js_core)} bytes   sha256 {rep['javascript_core_sha256']}")
    if off is None:
        print("  identical")
    else:
        pw, pc = window(py_core, off)
        jw, jc = window(js_core, off)
        print(f"  first differing byte: offset {off} (counted from 0)")
        print(f"  Python       {pw}")
        print(f"  JavaScript   {jw}")
        print(f"               {' ' * pc}^ offset {off}")
        print(f"  The number: Python renders {rep['python_amount']}, JavaScript renders "
              f"{rep['javascript_amount']}.")
    print()
    print("RFC 8785 (JSON Canonicalization Scheme) for the same number:")
    print(f"  Python, number rule reimplemented in this script   {rep['rfc8785_amount_python']}")
    print(f"  Node, JSON.stringify                               {rep['rfc8785_amount_node']}")
    if cpb_amount is not None:
        print(f"  Python, jcs function of the CPB library            {cpb_amount}")
    same = "identical" if rep["rfc8785_cores_identical"] else "DIFFERENT"
    print(f"  RFC 8785 receipt core, Python against Node: {same} "
          f"({len(py_jcs_core)} and {len(node_jcs_core)} bytes)")
    print("  RFC 8785 receipt core against the JavaScript sandbox port's bytes: "
          + ("identical" if node_jcs_core == js_core else "different"))
    print("  RFC 8785 receipt core against the Python sandbox verifier's bytes: "
          + ("identical" if py_jcs_core == py_core else "different"))
    if cpb_core is not None:
        print("  RFC 8785 receipt core, CPB jcs against Node: "
              + ("identical" if rep["cpb_jcs_core_identical_to_node"] else "DIFFERENT"))
    print()
    print("The sandbox canonical form is not RFC 8785. VERIFIER-SPEC-v1 (a Tyche sandbox")
    print("specification, not an IETF draft) keeps signed numbers to integers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
