#!/usr/bin/env python3
"""score.py - score one verdict return against a key file.

Runs on the Python 3 standard library.

  Round 1 (after the key is released):
    python3 score.py RETURN.json --key expected.json
  Round 0, OPEN practice mode (the key is the public design_expectation of each vector):
    python3 score.py RETURN.json --round0-open path/to/interlab/round0/vectors/cases.json
  Output format (default Markdown on standard output):
    --format md | json        --out FILE
  Check a return's format before you send it (no key needed, nothing is scored):
    python3 score.py RETURN.json --check-format path/to/round1/vectors/cases.json
  Built-in self-test (synthetic key, no files needed):
    python3 score.py --self-test

A RETURN is a JSON array of {"file": ..., "verdict": "ALLOW"|"DENY", "reason": ...}.
On ALLOW, reason is null. On DENY, reason is one of the 12 words of the vocabulary below.
A return that uses any other reason, any other verdict, or lists a file twice is refused
(exit code 2) and nothing is scored.

The tool scores one return at a time. It does not rank and does not compare participants.

Exit codes: 0 = scored, format OK, or self-test passed. 2 = return or key refused, or a bad
option. 1 = no return file, no mode, or a failed self-test.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys

VOCAB = (
    "malformed_aep", "content_mutated", "aep_sig_invalid", "measurement_mismatch",
    "malformed_mandate", "issuer_not_listed", "credential_sig_invalid",
    "principal_sig_invalid", "agent_binding_mismatch", "scope_violation", "expired",
    "replayed",
)
Z95 = 1.959963984540054


class Refused(Exception):
    pass


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #
def label(verdict, reason) -> str:
    if verdict is None:
        return "(none)"
    return "ALLOW" if verdict == "ALLOW" else f"DENY:{reason}"


def validate_return(rows) -> dict:
    """Return {file: (verdict, reason)} or raise Refused with every problem listed."""
    if not isinstance(rows, list):
        raise Refused(["the return must be a JSON array"])
    problems, out = [], {}
    for i, r in enumerate(rows):
        where = f"item {i}"
        if not isinstance(r, dict):
            problems.append(f"{where}: not a JSON object")
            continue
        f = r.get("file")
        if not isinstance(f, str) or not f:
            problems.append(f"{where}: 'file' must be a non-empty string")
            continue
        where = f"item {i} ({f})"
        v, reason = r.get("verdict"), r.get("reason")
        if v not in ("ALLOW", "DENY"):
            problems.append(f"{where}: verdict {v!r} is not ALLOW or DENY")
            continue
        if v == "ALLOW" and reason is not None:
            problems.append(f"{where}: ALLOW must carry reason null, got {reason!r}")
            continue
        if v == "DENY" and reason not in VOCAB:
            problems.append(f"{where}: reason {reason!r} is outside the 12-word vocabulary")
            continue
        if f in out:
            problems.append(f"{where}: file listed more than once")
            continue
        out[f] = (v, reason)
    if problems:
        raise Refused(problems)
    return out


def load_key(rows) -> dict:
    """Round 1 key: [{file, class, scored, verdict, reason, ...}]."""
    if not isinstance(rows, list):
        raise Refused(["the key must be a JSON array"])
    key = {}
    for r in rows:
        f = r["file"]
        v, reason = r.get("verdict"), r.get("reason")
        if v is not None and v not in ("ALLOW", "DENY"):
            raise Refused([f"key {f}: bad verdict {v!r}"])
        if v == "DENY" and reason not in VOCAB:
            raise Refused([f"key {f}: bad reason {reason!r}"])
        if r.get("scored") and v is None:
            raise Refused([f"key {f}: scored entry without a verdict"])
        key[f] = {"scored": bool(r.get("scored")), "verdict": v, "reason": reason,
                  "class": r.get("class")}
    return key


_DE = re.compile(r"^\s*(ALLOW|DENY:([a-z_]+))(?![a-z_:])")


def load_round0_open(rows) -> dict:
    """Round 0 OPEN practice key, built from the public design_expectation in cases.json.

    Scored vectors must carry a plain 'ALLOW' or 'DENY:<reason>'. For unscored probes the
    leading token is used when present ('ALLOW (both) ...'); a probe whose expectation
    starts with anything else (for example 'DIVERGENCE') has no key value.
    """
    key = {}
    for r in rows:
        f = r["file"]
        m = _DE.match(r.get("design_expectation", ""))
        v = reason = None
        if m:
            v = "ALLOW" if m.group(1) == "ALLOW" else "DENY"
            reason = m.group(2)
            if v == "DENY" and reason not in VOCAB:
                v = reason = None
        if r.get("scored") and v is None:
            raise Refused([f"round0 {f}: scored vector without a readable expectation"])
        key[f] = {"scored": bool(r.get("scored")), "verdict": v, "reason": reason,
                  "class": r.get("class")}
    return key


# --------------------------------------------------------------------------- #
# Scoring                                                                      #
# --------------------------------------------------------------------------- #
def wilson(k: int, n: int, z: float = Z95):
    if n == 0:
        return (None, None)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def score(ret: dict, key: dict, mode: str) -> dict:
    per, mism, missing = [], [], []
    k = n = vmatch = 0
    confusion: dict = {}
    for f in sorted(key):
        e = key[f]
        got = ret.get(f)
        exp_l = label(e["verdict"], e["reason"])
        got_l = label(*got) if got else "(not returned)"
        if e["scored"]:
            n += 1
            exact = got is not None and got == (e["verdict"], e["reason"])
            vonly = got is not None and got[0] == e["verdict"]
            k += exact
            vmatch += vonly
            confusion.setdefault(exp_l, {}).setdefault(got_l, 0)
            confusion[exp_l][got_l] += 1
            status = "match" if exact else ("not returned" if got is None else "mismatch")
            if got is None:
                missing.append(f)
            elif not exact:
                mism.append({"file": f, "expected": exp_l, "returned": got_l,
                             "verdict_matches": vonly})
        else:
            status = "unscored"
            if got is None:
                missing.append(f)
        per.append({"file": f, "scored": e["scored"], "expected": exp_l if e["scored"]
                    or e["verdict"] else "(no key value)", "returned": got_l,
                    "status": status})
    lo, hi = wilson(k, n)
    return {
        "mode": mode,
        "scored_vectors": n,
        "exact_matches": k,
        "verdict_only_matches": vmatch,
        "verdict_only_all_deny": sum(1 for f in key if key[f]["scored"]
                                     and key[f]["verdict"] == "DENY"),
        "wilson95": [lo, hi],
        "per_vector": per,
        "confusion": confusion,
        "mismatches": mism,
        "not_returned": missing,
        "unknown_files": sorted(set(ret) - set(key)),
    }


def fmt_pct(x):
    return "n/a" if x is None else f"{100 * x:.1f} %"


def to_markdown(s: dict) -> str:
    L = [f"# Score report ({s['mode']})", ""]
    lo, hi = s["wilson95"]
    L += [f"- Exact matches (verdict and reason): **{s['exact_matches']} of "
          f"{s['scored_vectors']}** scored vectors",
          f"- Wilson 95 % interval for {s['exact_matches']} of {s['scored_vectors']}: "
          f"{fmt_pct(lo)} to {fmt_pct(hi)}",
          f"- Verdict-only matches (ALLOW or DENY right, reason ignored): "
          f"{s['verdict_only_matches']} of {s['scored_vectors']}",
          f"- For comparison, a return of DENY for every vector would get "
          f"{s['verdict_only_all_deny']} of {s['scored_vectors']} verdict-only matches",
          f"- Vectors not returned: {len(s['not_returned'])}",
          f"- Files in the return that are not in the key: {len(s['unknown_files'])}",
          "", "This report scores one return. It is not a ranking.", "",
          "## Per vector", "", "| file | scored | expected | returned | status |",
          "|:--|:--|:--|:--|:--|"]
    for r in s["per_vector"]:
        L.append(f"| {r['file']} | {'yes' if r['scored'] else 'no'} | {r['expected']} | "
                 f"{r['returned']} | {r['status']} |")
    cols = sorted({c for row in s["confusion"].values() for c in row})
    L += ["", "## Confusion table (scored vectors; rows = expected, columns = returned)", ""]
    if cols:
        L.append("| expected | " + " | ".join(cols) + " |")
        L.append("|:--|" + "--:|" * len(cols))
        for exp_l in sorted(s["confusion"]):
            row = s["confusion"][exp_l]
            L.append(f"| {exp_l} | " + " | ".join(str(row.get(c, 0)) for c in cols) + " |")
    L += ["", "## Mismatches", ""]
    if s["mismatches"]:
        L += ["| file | expected | returned | verdict right |", "|:--|:--|:--|:--|"]
        for m in s["mismatches"]:
            L.append(f"| {m['file']} | {m['expected']} | {m['returned']} | "
                     f"{'yes' if m['verdict_matches'] else 'no'} |")
    else:
        L.append("None.")
    L += ["", "## Not returned", ""]
    L.append(", ".join(s["not_returned"]) if s["not_returned"] else "None.")
    if s["unknown_files"]:
        L += ["", "## Files not in the key (ignored)", "", ", ".join(s["unknown_files"])]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
# Self-test                                                                    #
# --------------------------------------------------------------------------- #
def self_test() -> int:
    key_rows = [{"file": f"t-{i:02d}", "scored": True, "verdict": "DENY", "reason": r}
                for i, r in enumerate(VOCAB, 1)]
    key_rows += [{"file": "t-13", "scored": True, "verdict": "ALLOW", "reason": None},
                 {"file": "t-14", "scored": True, "verdict": "ALLOW", "reason": None},
                 {"file": "t-15", "scored": False, "verdict": None, "reason": None}]
    key = load_key(key_rows)
    perfect = [{"file": r["file"], "verdict": r["verdict"] or "ALLOW", "reason": r["reason"]}
               for r in key_rows]
    checks = []
    s = score(validate_return(perfect), key, "self-test")
    checks.append(("perfect return scores 14 of 14", s["exact_matches"] == 14
                   and s["scored_vectors"] == 14 and not s["mismatches"]))
    always_deny = [{"file": r["file"], "verdict": "DENY", "reason": "malformed_aep"}
                   for r in key_rows[:-1]]
    s = score(validate_return(always_deny), key, "self-test")
    checks.append(("always DENY:malformed_aep scores 1 of 14, verdict-only 12",
                   s["exact_matches"] == 1 and s["verdict_only_matches"] == 12
                   and s["verdict_only_all_deny"] == 12
                   and s["not_returned"] == ["t-15"]))
    swapped = [dict(x) for x in perfect]
    swapped[9]["reason"], swapped[10]["reason"] = "expired", "scope_violation"
    s = score(validate_return(swapped), key, "self-test")
    checks.append(("two swapped reasons score 12 of 14 and appear in the confusion table",
                   s["exact_matches"] == 12
                   and s["confusion"]["DENY:scope_violation"].get("DENY:expired") == 1))
    lo, hi = wilson(10, 13)
    checks.append(("Wilson 10 of 13 = 0.4974 .. 0.9182",
                   abs(lo - 0.49744) < 1e-4 and abs(hi - 0.91820) < 1e-4))
    lo, hi = wilson(0, 5)
    checks.append(("Wilson 0 of 5 starts at 0", lo == 0.0 and abs(hi - 0.43449) < 1e-4))
    for bad, why in ((
            [{"file": "t-01", "verdict": "DENY", "reason": "bad_signature"}], "outside vocab"),
            ([{"file": "t-01", "verdict": "ALLOW", "reason": "expired"}], "ALLOW with reason"),
            ([{"file": "t-01", "verdict": "DENY:expired", "reason": None}], "bad verdict"),
            ([perfect[0], perfect[0]], "duplicate file")):
        try:
            validate_return(bad)
            checks.append((f"refuses {why}", False))
        except Refused:
            checks.append((f"refuses {why}", True))
    r0 = load_round0_open([
        {"file": "a", "scored": True, "design_expectation": "DENY:expired"},
        {"file": "b", "scored": True, "design_expectation": "ALLOW"},
        {"file": "c", "scored": False, "design_expectation": "ALLOW (both) - control"},
        {"file": "d", "scored": False, "design_expectation": "DIVERGENCE - x"}])
    checks.append(("round0 open key parsing", r0["a"]["reason"] == "expired"
                   and r0["b"]["verdict"] == "ALLOW" and r0["c"]["verdict"] == "ALLOW"
                   and r0["d"]["verdict"] is None))
    md = to_markdown(score(validate_return(perfect), key, "self-test"))
    checks.append(("markdown renders", "14 of 14" in md))
    bad = 0
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        bad += not ok
    print("self-test:", "PASS" if not bad else f"{bad} FAILED")
    return 0 if not bad else 1


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ret", nargs="?", help="the return to score (JSON array)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--key", help="a Round 1 style key file (expected.json)")
    g.add_argument("--round0-open", metavar="CASES_JSON",
                   help="Round 0 open practice mode: use the public design_expectation "
                        "in interlab/round0/vectors/cases.json as the key")
    g.add_argument("--check-format", metavar="CASES_JSON",
                   help="only check the return's format and that it covers every file "
                        "listed in this cases.json; nothing is scored")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--out", help="write the report here instead of standard output")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.ret or not (a.key or a.round0_open or a.check_format):
        ap.print_usage(sys.stderr)
        print("need a return file and one of --key, --round0-open or --check-format",
              file=sys.stderr)
        return 1
    if a.check_format:
        try:
            with open(a.ret, encoding="utf-8") as fh:
                ret = validate_return(json.load(fh))
            with open(a.check_format, encoding="utf-8") as fh:
                files = [c["file"] for c in json.load(fh)]
        except Refused as exc:
            print("FORMAT PROBLEMS:", file=sys.stderr)
            for p in exc.args[0]:
                print(f"  - {p}", file=sys.stderr)
            return 2
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            print(f"could not read input: {exc}", file=sys.stderr)
            return 2
        missing = [f for f in files if f not in ret]
        extra = sorted(set(ret) - set(files))
        for f in missing:
            print(f"  missing: {f}", file=sys.stderr)
        for f in extra:
            print(f"  not in cases.json: {f}", file=sys.stderr)
        if missing or extra:
            print(f"FORMAT PROBLEMS: {len(missing)} missing, {len(extra)} unknown",
                  file=sys.stderr)
            return 2
        print(f"format OK: {len(ret)} rows, every file in cases.json is present, "
              f"every reason is in the vocabulary")
        return 0
    try:
        with open(a.ret, encoding="utf-8") as fh:
            ret = validate_return(json.load(fh))
        if a.key:
            with open(a.key, encoding="utf-8") as fh:
                key = load_key(json.load(fh))
            mode = "key: " + a.key.replace("\\", "/").split("/")[-1]
        else:
            with open(a.round0_open, encoding="utf-8") as fh:
                key = load_round0_open(json.load(fh))
            mode = "Round 0 open practice (design_expectation as key)"
    except Refused as exc:
        print("REFUSED - nothing was scored:", file=sys.stderr)
        for p in exc.args[0]:
            print(f"  - {p}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"REFUSED - could not read input: {exc}", file=sys.stderr)
        return 2
    s = score(ret, key, mode)
    text = to_markdown(s) if a.format == "md" else json.dumps(s, indent=2) + "\n"
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
