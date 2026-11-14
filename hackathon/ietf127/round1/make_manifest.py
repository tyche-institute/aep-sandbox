#!/usr/bin/env python3
"""make_manifest.py - the script we used to write MANIFEST.sha256.

Do not run it to check the files: it OVERWRITES MANIFEST.sha256 with the hashes of the files
as they are now. To check the files, run in this directory:

    sha256sum -c MANIFEST.sha256

The script lists every file under the directory it lives in (except MANIFEST.sha256 itself
and Python cache files), sorted by path, in the format that sha256sum reads. Standard
library only. It takes no arguments.
"""
import hashlib
import os
import sys

if len(sys.argv) > 1:
    sys.exit("make_manifest.py takes no arguments, and it overwrites MANIFEST.sha256.\n"
             "To check the files, run: sha256sum -c MANIFEST.sha256")

HERE = os.path.dirname(os.path.abspath(__file__))
SKIP_DIRS = {"__pycache__"}

rows = []
for root, dirs, files in os.walk(HERE):
    dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
    for name in files:
        rel = os.path.relpath(os.path.join(root, name), HERE).replace(os.sep, "/")
        if rel == "MANIFEST.sha256" or name.endswith(".pyc"):
            continue
        with open(os.path.join(root, name), "rb") as fh:
            rows.append((rel, hashlib.sha256(fh.read()).hexdigest()))
rows.sort()
with open(os.path.join(HERE, "MANIFEST.sha256"), "w", encoding="ascii", newline="\n") as fh:
    for rel, digest in rows:
        fh.write(f"{digest}  {rel}\n")
print(f"MANIFEST.sha256: {len(rows)} files")
