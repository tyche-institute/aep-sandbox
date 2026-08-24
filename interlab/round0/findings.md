# Round-0 (Track B) — reference-divergence findings

Every row here is a case where the two independent reference implementations (Python `aep-sandbox` and the JS CTF port) returned **different** verdicts on the **same** vector. Per the interlab design, a divergence between references is a corpus defect published as a finding — it is recorded, never patched away by editing a verifier. Such a vector is **excluded from the assigned values** and cannot be scored until the divergence is resolved upstream.


**Total vectors:** 18  |  **Agreements (assigned):** 17  |  **Disagreements:** 1 (0 in scored classes, 1 in probe class).


## r0-15-probe-float-1e-7.aep.json

- **class:** probe (probe / unscored)
- **Python reference:** `ALLOW`
- **JS port:** `DENY:content_mutated`
- **design note:** float 1e-07: Python canonical '1e-07' vs JS '1e-7' -> JS recomputes a different receipt_hash and fails chain_integrity
- **canonical receipt-core bytes differ** — first divergence at byte offset 31 (Python len 1541, JS len 1540):

  ```text
  python: …ction":{"args":{"amount":1e-07,"currency":"EUR","order_i…
  js    : …ction":{"args":{"amount":1e-7,"currency":"EUR","order_id…
  ```
  The signer (Python) hashed/signed over its canonical bytes; the port recomputes a *different* canonical string for the same parsed object, so its recomputed `receipt_hash` cannot match the stored one and it stops at `chain_integrity` with `content_mutated`.
