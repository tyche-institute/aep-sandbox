#!/usr/bin/env python3
"""Self-test for numguard: every measured divergence class must be rejected."""
import json, pathlib, sys
from numguard import check, is_safe, UnsafeNumber, MAX_SAFE_INTEGER

HERE = pathlib.Path(__file__).resolve().parent
data = json.loads((HERE / "numspace-divergence.json").read_text(encoding="utf-8"))

fails = 0
for row in data["values"]:
    parsed = json.loads(row["input"])
    safe = is_safe({"amount": parsed})
    # A value the two runtimes render differently MUST be rejected by the guard.
    if not row["agree"] and safe:
        print(f"FAIL  {row['input']}: diverges but guard accepts it"); fails += 1
    # Integers inside the safe range must be accepted.
    if isinstance(parsed, int) and abs(parsed) <= MAX_SAFE_INTEGER and not safe:
        print(f"FAIL  {row['input']}: safe integer rejected"); fails += 1

for ok in [{"a": 1}, {"a": [1, 2, 3]}, {"a": {"b": MAX_SAFE_INTEGER}}, {"a": True}, {"a": "1.5"}]:
    if not is_safe(ok):
        print(f"FAIL  {ok}: should be accepted"); fails += 1
for bad in [{"a": 1.0}, {"a": 0.1}, {"a": MAX_SAFE_INTEGER + 1}, {"a": [{"b": 2.5}]}]:
    if is_safe(bad):
        print(f"FAIL  {bad}: should be rejected"); fails += 1

print(f"\nnumguard self-test: {'FAILED' if fails else 'OK'} ({fails} failure(s))")
sys.exit(1 if fails else 0)
