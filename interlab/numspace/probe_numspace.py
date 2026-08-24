#!/usr/bin/env python3
"""Measure where CPython's json.dumps and ECMAScript's JSON.stringify disagree.

Evidence generator for Tyche Labs FINDING-001. Deterministic; no wall clock.
Writes numspace-divergence.json next to this file and prints a table.
"""
import json, subprocess, pathlib

VALUES = ["0.1","0.5","1.5","3.14159","2.0","100.0","0.0001","0.00001","1e-5","1e-6",
          "1e-7","5e-324","1e16","1e20","1e21","1e100","123456789012345678",
          "9007199254740992","9007199254740993"]

HERE = pathlib.Path(__file__).resolve().parent

def js_render(values):
    src = ("const v=%s;console.log(JSON.stringify(v.map(x=>JSON.stringify(JSON.parse(x)))));"
           % json.dumps(values))
    out = subprocess.run(["node", "-e", src], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)

def main():
    js = js_render(VALUES)
    rows, diverging = [], 0
    for v, j in zip(VALUES, js):
        p = json.dumps(json.loads(v))
        same = p == j
        if not same:
            diverging += 1
        rows.append({"input": v, "python": p, "ecmascript": j, "agree": same})
    (HERE / "numspace-divergence.json").write_text(
        json.dumps({"values": rows, "diverging": diverging, "total": len(rows)},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    w = max(len(r["python"]) for r in rows) + 2
    print(f"{'input':22s} {'CPython json.dumps':{w}s} {'ECMAScript (= RFC 8785)':{w}s} verdict")
    for r in rows:
        print(f"{r['input']:22s} {r['python']:{w}s} {r['ecmascript']:{w}s} "
              f"{'agree' if r['agree'] else '*** DIVERGES'}")
    print(f"\ndiverging: {diverging}/{len(rows)}")

if __name__ == "__main__":
    main()
