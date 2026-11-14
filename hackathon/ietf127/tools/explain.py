#!/usr/bin/env python3
"""explain.py - show how the AEP sandbox verifier stops.

The sandbox Python verifier (aep/package.py, verify_aep) returns at the first failed
check, and its check list ends there. This wrapper calls that verifier unmodified,
maps the reason it returns to the ordered checks of VERIFIER-SPEC-v1 section 4, and prints
one row per check: pass, fail (with the reason) or not_evaluated.

It never changes a verdict. It only reports what the sandbox verifier returned.

Round 1 participants: this script runs the Tyche verifier. Do not run it before you send
your Round 1 return (round1/RULES.md, section 4).

VERIFIER-SPEC-v1 is a Tyche sandbox specification, not an IETF draft.

Usage:
  python3 explain.py --sandbox PATH PACKAGE.json [PACKAGE.json ...]
        [--now N] [--consumed NONCE] [--consumed-json LIST] [--trust FILE] [--json]
  python3 explain.py --sandbox PATH --cases cases.json [--case NAME] [--trust FILE] [--json]

Exit status: 0 when every package got a verdict from the sandbox verifier,
1 when at least one package could not be loaded or the arguments were wrong.
Needs: Python 3 standard library, plus the package "cryptography" (the sandbox needs it).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

NOW_DEFAULT = 1_750_000_100  # same default as the sandbox's verify.py
MAX_SAFE = 2 ** 53 - 1

# VERIFIER-SPEC-v1 section 4, in order. (number, sandbox check name, label)
CHECKS = [
    ("1", "structure", "structure"),
    ("2", "chain_integrity", "chain integrity"),
    ("3", "aep_signature", "package signature"),
    ("4", "measurements", "measurements"),
    ("5", "mandate", "mandate chain"),
    ("6", "replay", "replay"),
]
# Section 4, step 5, sub-steps a to g, in order.
MANDATE_STEPS = [
    ("5a", "malformed_mandate", "credential and mandate bodies are objects"),
    ("5b", "issuer_not_listed", "issuer listed with this key"),
    ("5c", "credential_sig_invalid", "issuer signature on credential"),
    ("5d", "principal_sig_invalid", "principal signature on mandate"),
    ("5e", "agent_binding_mismatch", "mandate names this agent"),
    ("5f", "scope_violation", "action inside scope"),
    ("5g", "expired", "not after expiry"),
]
# Reason -> the check that returns it (section 4).
REASON_TO_CHECK = {
    "malformed_aep": "structure",
    "content_mutated": "chain_integrity",
    "aep_sig_invalid": "aep_signature",
    "measurement_mismatch": "measurements",
    "replayed": "replay",
}
for _n, _reason, _l in MANDATE_STEPS:
    REASON_TO_CHECK[_reason] = "mandate"


def load_sandbox(path: str):
    """Import aep.package and aep.mandate from the given sandbox checkout, and only there."""
    path = os.path.abspath(path)
    if not os.path.isfile(os.path.join(path, "aep", "package.py")):
        raise SystemExit(f"--sandbox {path}: no aep/package.py there")
    sys.path.insert(0, path)
    from aep import mandate, package  # noqa: E402

    got = os.path.dirname(os.path.dirname(os.path.abspath(package.__file__)))
    if got != path:
        raise SystemExit(f"imported aep from {got}, expected {path}")
    return package, mandate


def out_of_profile(obj, where="$"):
    """Paths of numbers outside the VERIFIER-SPEC-v1 section 2 profile
    (non-integers, or integers beyond +/-(2^53-1)). Booleans are not numbers here."""
    found = []
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return found
    if isinstance(obj, float):
        found.append(where)
    elif isinstance(obj, int):
        if abs(obj) > MAX_SAFE:
            found.append(where)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            found += out_of_profile(v, f"{where}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += out_of_profile(v, f"{where}[{i}]")
    return found


def run_verifier(package, aep, trust, now, consumed):
    """Call the unmodified sandbox verifier. If it raises, apply the same fail-closed
    guard as the sandbox's verify.py (DENY, malformed_aep) and recover, from the
    traceback, which checks had already passed and where the exception happened."""
    try:
        return package.verify_aep(aep, trust, now=now, consumed=consumed), None
    except Exception as exc:  # noqa: BLE001 - mirror verify.py's guard
        passed = []
        tb = exc.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code is package.verify_aep.__code__:
                passed = list(tb.tb_frame.f_locals.get("checks", []))
            tb = tb.tb_next
        info = {"exception": type(exc).__name__,
                "passed_before_exception": [n for n, ok in passed if ok]}
        return {"verdict": "DENY", "reason": "malformed_aep",
                "checks": passed}, info


def explain(package, aep, trust, now, consumed):
    result, exc_info = run_verifier(package, aep, trust, now, consumed)
    verdict, reason = result["verdict"], result["reason"]
    returned = [(n, bool(ok)) for n, ok in result.get("checks", [])]
    problems = []

    if verdict == "ALLOW":
        failing = None
    elif exc_info is not None:
        # The sandbox CLI reports this as "[FAIL] structure". We report the check in
        # which the exception happened: the first check not yet passed.
        done = set(exc_info["passed_before_exception"])
        failing = next(c for _, c, _ in CHECKS if c not in done)
    else:
        failing = REASON_TO_CHECK.get(reason)
        if failing is None:
            problems.append(f"reason {reason!r} is not in VERIFIER-SPEC-v1 section 4")
        if returned and returned[-1] != (failing, False):
            problems.append(f"verifier's last check {returned[-1]} does not match "
                            f"the reason {reason!r}")

    rows, state = [], "pass"
    for num, name, label in CHECKS:
        if name == failing:
            row = {"step": num, "check": name, "label": label, "outcome": "fail",
                   "reason": reason}
            if exc_info is not None:
                row["note"] = (f"verifier raised {exc_info['exception']} here; the "
                               "sandbox verify.py reports malformed_aep at structure")
            state = "not_evaluated"
        else:
            row = {"step": num, "check": name, "label": label, "outcome": state}
        if name == "mandate":
            row["substeps"] = mandate_substeps(row["outcome"], reason, exc_info)
        rows.append(row)

    # Cross-check: every check the verifier reported as passed is "pass" here.
    for n, ok in returned:
        mine = next(r["outcome"] for r in rows if r["check"] == n)
        if ok and mine != "pass":
            problems.append(f"verifier passed {n} but this report says {mine}")

    profile = out_of_profile(aep)
    if verdict == "ALLOW":
        outcome = "unverified" if profile else "verified"
    else:
        outcome = "failed"
    return {
        "sandbox_verdict": verdict,
        "sandbox_reason": reason,
        "outcome": outcome,
        "out_of_number_profile": profile,
        "checks": rows,
        "exception": exc_info,
        "problems": problems,
    }


def mandate_substeps(outcome5, reason, exc_info):
    subs = []
    if outcome5 == "pass":
        state, failing = "pass", None
    elif outcome5 == "not_evaluated":
        state, failing = "not_evaluated", None
    elif exc_info is not None:
        # Exception inside the mandate check: the sub-step is not known, so we list none.
        return []
    else:
        state, failing = "pass", reason
    for num, r, label in MANDATE_STEPS:
        if r == failing:
            subs.append({"step": num, "label": label, "outcome": "fail", "reason": r})
            state = "not_evaluated"
        else:
            subs.append({"step": num, "label": label, "outcome": state})
    return subs


def render_text(name, now, consumed, rep):
    lines = [f"package: {name}",
             f"  now={now}  consumed={json.dumps(sorted(consumed, key=repr))}"]
    tag = rep["sandbox_verdict"] + (f":{rep['sandbox_reason']}" if rep["sandbox_reason"] else "")
    for row in rep["checks"]:
        extra = f"  reason={row['reason']}" if row["outcome"] == "fail" else ""
        lines.append(f"  {row['step']}   {row['label']:<44} {row['outcome']}{extra}")
        if row.get("note"):
            lines.append(f"      note: {row['note']}")
        for s in row.get("substeps", []):
            extra = f"  reason={s['reason']}" if s["outcome"] == "fail" else ""
            lines.append(f"    {s['step']}  {s['label']:<44} {s['outcome']}{extra}")
    lines.append(f"  sandbox verdict: {tag}")
    out = f"  outcome: {rep['outcome']}"
    if rep["out_of_number_profile"]:
        out += ("  (numbers outside the VERIFIER-SPEC-v1 section 2 profile at "
                + ", ".join(rep["out_of_number_profile"]) + ")")
    lines.append(out)
    for p in rep["problems"]:
        lines.append(f"  PROBLEM: {p}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Show how the AEP sandbox verifier stops. Round 1 participants: do not run this before you send your Round 1 return.")
    ap.add_argument("packages", nargs="*", help="package files (.aep.json)")
    ap.add_argument("--sandbox", required=True, help="path to a checkout of aep-sandbox")
    ap.add_argument("--trust", help="trust anchor file (default: SANDBOX/keys/trusted_issuers.json)")
    ap.add_argument("--now", type=int, default=NOW_DEFAULT,
                    help=f"appraisal time (default {NOW_DEFAULT}, as in verify.py)")
    ap.add_argument("--consumed", action="append", default=[], metavar="NONCE",
                    help="a consumed nonce, as a string; repeat the flag for more")
    ap.add_argument("--consumed-json", help="consumed nonces as a JSON list (keeps types)")
    ap.add_argument("--cases", help="a cases.json: list of {file, now, consumed}")
    ap.add_argument("--case", help="with --cases: only entries whose file name starts with this")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()

    package, mandate = load_sandbox(args.sandbox)
    trust_path = args.trust or os.path.join(os.path.abspath(args.sandbox), "keys",
                                            "trusted_issuers.json")
    with open(trust_path, encoding="utf-8") as fh:
        trust = mandate.TrustStore.from_dict(json.load(fh))

    jobs = []  # (display name, path, now, consumed)
    if args.cases:
        if args.packages:
            ap.error("give either package files or --cases, not both")
        base = os.path.dirname(os.path.abspath(args.cases))
        with open(args.cases, encoding="utf-8") as fh:
            cases = json.load(fh)
        for c in cases:
            if args.case and not c["file"].startswith(args.case):
                continue
            jobs.append((c["file"], os.path.join(base, c["file"]), int(c["now"]),
                         set(c.get("consumed", []))))
        if not jobs:
            ap.error("no matching entry in --cases")
    else:
        if not args.packages:
            ap.error("give at least one package file, or --cases")
        consumed = set(args.consumed)
        if args.consumed_json:
            consumed |= set(json.loads(args.consumed_json))
        for p in args.packages:
            jobs.append((os.path.basename(p), p, args.now, consumed))

    reports, status = [], 0
    for name, path, now, consumed in jobs:
        try:
            aep = package.load(path)
        except (OSError, ValueError) as exc:
            rep = {"sandbox_verdict": None, "sandbox_reason": None, "outcome": "unverified",
                   "load_error": f"{type(exc).__name__}: {exc}", "checks": [],
                   "problems": []}
            status = 1
        else:
            rep = explain(package, aep, trust, now, consumed)
        rep = {"package": name, "now": now, "consumed": sorted(consumed, key=repr),
               "trust": os.path.basename(trust_path), **rep}
        reports.append(rep)
        if not args.json:
            if rep.get("load_error"):
                print(f"package: {name}\n  could not load: {rep['load_error']}\n"
                      "  outcome: unverified")
            else:
                print(render_text(name, now, consumed, rep))
            print()
    if args.json:
        json.dump(reports if len(reports) > 1 else reports[0], sys.stdout, indent=2,
                  ensure_ascii=False)
        print()
    return status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0)
