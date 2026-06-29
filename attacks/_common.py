"""Shared helpers for the attack scripts.

Each attack reads a legitimately-minted sample, mutates it the way a real adversary would,
writes the result to attacks/out/, and runs the *real* verify.py CLI on it so you see the
exact verdict an auditor would. Nothing here needs the private trust-anchor keys — that is
the point: you are attacking from the outside.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

ATTACK_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(ATTACK_DIR)
sys.path.insert(0, ROOT)  # so `import aep...` works when run from anywhere

GOOD = os.path.join(ROOT, "samples", "good.aep.json")
EXCEED = os.path.join(ROOT, "samples", "exceed-scope.aep.json")
LEDGER = os.path.join(ROOT, "samples", "ledger.jsonl")
OUT = os.path.join(ATTACK_DIR, "out")
VERIFY = os.path.join(ROOT, "verify.py")


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_good() -> dict:
    return load_json(GOOD)


def save(obj, name: str) -> str:
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return path


def run_verify(path: str, *extra: str) -> int:
    """Invoke the real verify.py and stream its output. Returns the exit code."""
    cmd = [sys.executable, VERIFY, *extra, path]
    print(f"$ python3 verify.py {' '.join([*extra, os.path.relpath(path, ROOT)])}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def banner(title: str) -> None:
    print(f"\n=== {title} ===")
