"""Layer 1 — the *unsigned* hash-chain ledger (integrity only).

Each receipt records one agent action and carries prev_hash -> receipt_hash, a plain
sha256 chain. This is deliberately the WEAK layer, kept so you can feel the difference
between a hash-chain and a signature:

  * edit one field and leave its receipt_hash  -> verify catches it (CONTENT MUTATED)
  * delete / reorder a receipt                 -> verify catches it (BROKEN LINK)
  * rewrite a field AND recompute every hash    -> verify PASSES.  <-- the lesson.

There is no key here. A hash-chain only stops an attacker who cannot recompute it; anyone
who can write the file can forge the whole history. The signed governed AEP (package.py)
is what fixes this. See attacks/forge_rechain.py.
"""

from __future__ import annotations

import json

from .canonical import canonical_bytes, sha256_hex

GENESIS = "0" * 64


def _receipt_core(rec: dict) -> dict:
    """The hashed body — everything except the chain output field itself."""
    return {k: v for k, v in rec.items() if k != "receipt_hash"}


def receipt_hash(rec: dict) -> str:
    return sha256_hex(canonical_bytes(_receipt_core(rec)))


def mint(actions: list[dict]) -> list[dict]:
    """Build a hash-chained ledger from a list of action dicts."""
    chain: list[dict] = []
    prev = GENESIS
    for seq, action in enumerate(actions):
        rec = {
            "seq": seq,
            "action": action,
            "prev_hash": prev,
        }
        rec["receipt_hash"] = receipt_hash(rec)
        prev = rec["receipt_hash"]
        chain.append(rec)
    return chain


def verify(chain: list[dict]) -> tuple[bool, list[str]]:
    """Re-walk the chain. Returns (ok, problems[]) naming each break found."""
    problems: list[str] = []
    prev = GENESIS
    for rec in chain:
        seq = rec.get("seq")
        recomputed = receipt_hash(rec)
        if recomputed != rec.get("receipt_hash"):
            problems.append(
                f"seq={seq}: CONTENT MUTATED "
                f"(stored {str(rec.get('receipt_hash'))[:16]}... != "
                f"recomputed {recomputed[:16]}...)"
            )
        if rec.get("prev_hash") != prev:
            problems.append(
                f"seq={seq}: BROKEN LINK "
                f"(prev_hash {str(rec.get('prev_hash'))[:16]}... != "
                f"expected {prev[:16]}...)"
            )
        prev = rec.get("receipt_hash")
    return (len(problems) == 0, problems)


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def dump(chain: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for rec in chain:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
