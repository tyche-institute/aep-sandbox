#!/usr/bin/env python3
"""Attack: rewrite a record AND recompute every hash (a full re-chain forge).

This is the attack that *defeats* a bare hash-chain and *fails* against a signature — the
single most important lesson in the sandbox. We run it against both layers back to back:

  * Layer 1 (unsigned ledger): rewrite an action, recompute the whole sha256 chain.
    Expected: chain intact -> the forgery is UNDETECTED. A hash-chain only stops an
    attacker who cannot recompute it.

  * Layer 2 (signed governed AEP): rewrite the action, recompute receipt_hash.
    Expected: DENY:aep_sig_invalid -> you cannot re-sign without the agent's private key.
"""

import os

import _common
from _common import LEDGER, banner, load_good, run_verify, save
from aep import ledger, package  # _common put the repo root on sys.path

# --- Layer 1: re-chain forge on the unsigned ledger -------------------------------------
banner("forge_rechain (Layer 1: unsigned ledger) — rewrite + recompute every hash")
chain = ledger.load(LEDGER)
chain[2]["action"]["args"]["amount"] = 999999          # inflate a refund
prev = ledger.GENESIS
for rec in chain:                                      # attacker re-chains the whole file
    rec["prev_hash"] = prev
    rec["receipt_hash"] = ledger.receipt_hash(rec)
    prev = rec["receipt_hash"]
os.makedirs(_common.OUT, exist_ok=True)
forged_ledger = os.path.join(_common.OUT, "forged_ledger.jsonl")
ledger.dump(chain, forged_ledger)
rc1 = run_verify(forged_ledger, "--ledger")
print(f"-> exit {rc1} (expected 0 / chain intact == forgery UNDETECTED — the Layer-1 lesson)")

# --- Layer 2: same trick on the signed governed AEP -------------------------------------
banner("forge_rechain (Layer 2: signed AEP) — rewrite action + recompute receipt_hash")
aep = load_good()
aep["action"]["args"]["amount"] = 999999
aep["measurements"]["action_sha256"] = package.digest(aep["action"])  # fix measurements too
aep["receipt_hash"] = package.receipt_hash(aep)                       # recompute the chain
path = save(aep, "forge_rechain.aep.json")
rc2 = run_verify(path)
print(f"-> exit {rc2} (expected 2 / DENY:aep_sig_invalid — no agent key, no valid signature)")
