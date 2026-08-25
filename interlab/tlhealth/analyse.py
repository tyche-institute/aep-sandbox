#!/usr/bin/env python3
"""Series analysis — what a run cannot tell you and a series can.

A single observation cannot distinguish a broken endpoint from a busy one. This reads
every run and reports, per endpoint: how often it was observed, how often it was reachable,
and whether it FLAPPED - changed state between consecutive observations. Flapping matters
more than a single failure: a persistent failure is a defect, a flapping one is either an
overloaded server or an instrument that is too aggressive, and the two must not be reported
alike.
"""
from __future__ import annotations
import json, pathlib, sys
from collections import defaultdict

runs_dir = pathlib.Path(__file__).resolve().parent / "runs"
runs = sorted(p for p in runs_dir.glob("*.json") if p.name != "latest.json")
if not runs:
    print("no runs"); sys.exit(1)

hist: dict[str, list[tuple[str, str]]] = defaultdict(list)
for p in runs:
    d = json.loads(p.read_text(encoding="utf-8"))
    for r in d["results"]:
        hist[f"{r['population']}|{r['name']}"].append((d["started_utc"], r["class"]))

print(f"runs: {len(runs)}   from {json.loads(runs[0].read_text())['started_utc'][:16]}"
      f"  to {json.loads(runs[-1].read_text())['started_utc'][:16]}")
print()

always_ok, never_ok, flapping = [], [], []
for key, obs in sorted(hist.items()):
    classes = [c for _, c in obs]
    ok = sum(1 for c in classes if c == "ok")
    transitions = sum(1 for a, b in zip(classes, classes[1:]) if a != b)
    if ok == len(classes):
        always_ok.append(key)
    elif ok == 0:
        never_ok.append((key, classes[-1], len(classes)))
    else:
        flapping.append((key, ok, len(classes), transitions, classes))

print(f"ALWAYS reachable : {len(always_ok)}")
print(f"NEVER reachable  : {len(never_ok)}")
for k, c, n in never_ok:
    print(f"    {k.split('|',1)[1][:64]:66s} {c}  ({n}/{n} observations)")
print(f"FLAPPED          : {len(flapping)}")
for k, ok, n, t, classes in flapping:
    print(f"    {k.split('|',1)[1][:64]:66s} ok {ok}/{n}, {t} transition(s)")
    print(f"        {' '.join('.' if c=='ok' else 'x' for c in classes)}")

print()
print("Reading: a dot is a reachable observation, an x is not. A row of x means a")
print("persistent defect; a mixed row means either an unstable endpoint or an instrument")
print("that is too aggressive, and only a longer series separates those two.")
