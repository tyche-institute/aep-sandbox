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

# Keyed on the URL, never on the label. A label is ours and can be repointed; the URL is the
# thing measured. On 25.08.2026 the label mb_uy covered two different addresses - one we had
# reconstructed and one the regional list actually declares - and keying on the label would
# have merged a 404 at our address with a 200 at theirs and reported Uruguay as flapping.
# That would have been an intermittent fault manufactured by the instrument, which is the
# same class of error as the parallel workers that invented Hungary's timeouts.
hist: dict[str, list[tuple[str, str]]] = defaultdict(list)
labels: dict[str, set[str]] = defaultdict(set)
for p in runs:
    d = json.loads(p.read_text(encoding="utf-8"))
    for r in d["results"]:
        hist[f"{r['population']}|{r['url']}"].append((d["started_utc"], r["class"]))
        labels[r["url"]].add(r["name"])

# A label that moved between addresses is reported, not silently tolerated.
moved = defaultdict(set)
for url, names in labels.items():
    for n in names:
        moved[n].add(url)
repointed = {n: us for n, us in moved.items() if len(us) > 1}

first = json.loads(runs[0].read_text())
last = json.loads(runs[-1].read_text())
print(f"runs: {len(runs)}   from {first['started_utc'][:16]}  to {last['started_utc'][:16]}")

# A run count is not a duration. 25 observations sound like weeks and were one night, and a
# reader who is not told the window will assume the flattering reading.
import datetime as _dt
_a = _dt.datetime.fromisoformat(first["started_utc"].replace("Z", "+00:00"))
_b = _dt.datetime.fromisoformat(last["started_utc"].replace("Z", "+00:00"))
_h = (_b - _a).total_seconds() / 3600
print(f"window: {_h:.1f} hours   ({len(runs)} observations)")
if _h < 72:
    print("NOTE: under three days. A persistent failure here is persistent WITHIN THIS WINDOW;")
    print("      distinguishing a defect from a long outage needs a longer series.")

# Classifier versions present. Aggregating across a change silently would compare counts that
# do not mean the same thing.
_vers = {json.loads(p.read_text()).get("classifier_version", 1) for p in runs}
if len(_vers) > 1:
    print(f"WARNING: {len(_vers)} classifier versions in this series: {sorted(_vers)}.")
    print("         Counts are not comparable across the break without re-classification.")
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

if repointed:
    print()
    print(f"LABELS REPOINTED : {len(repointed)}  (counted per address, never merged)")
    for n, us in sorted(repointed.items()):
        print(f"    {n}")
        for u in sorted(us):
            print(f"        {u[:88]}")

print()
print("Reading: a dot is a reachable observation, an x is not. A row of x means a")
print("persistent defect; a mixed row means either an unstable endpoint or an instrument")
print("that is too aggressive, and only a longer series separates those two.")
print("Histories are keyed on the address measured, so a target we repointed mid-series")
print("appears as two short histories rather than one flapping endpoint.")
