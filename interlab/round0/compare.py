#!/usr/bin/env python3
"""compare.py — join the two reference verdict sets and split them into:

  * assigned-values.json — every case where the Python reference and the JS port AGREE.
    This is the sealed ground truth for the round; its SHA-256 is the precommit (see
    RULES-draft.md). Each entry is {file, class, scored, now, consumed, verdict, reason}.

  * findings.md — every case where the two references DISAGREE. Per the design doc, a
    disagreement between the two references is a CORPUS DEFECT, published as a finding, not
    quietly resolved. For each we show the exact canonical-bytes difference (the two receipt-
    core canonical strings and the first position they diverge).

A disagreement is NEVER fixed by editing a verifier — it is recorded. Run the two runners
first (run_reference.py, run_port.mjs).

  python3 interlab/round0/compare.py
"""

from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "vectors")
PY = os.path.join(HERE, "verdicts-python.json")
JS = os.path.join(HERE, "verdicts-js.json")
ASSIGNED = os.path.join(HERE, "assigned-values.json")
FINDINGS = os.path.join(HERE, "findings.md")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def first_diff(a: str | None, b: str | None) -> int:
    if a is None or b is None:
        return 0
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n  # one is a prefix of the other


def window(s: str | None, i: int, radius: int = 28) -> str:
    if s is None:
        return "<none>"
    lo = max(0, i - radius)
    hi = min(len(s), i + radius)
    pre = "…" if lo > 0 else ""
    post = "…" if hi < len(s) else ""
    return pre + s[lo:hi] + post


def main() -> int:
    cases = {c["file"]: c for c in load(os.path.join(VEC, "cases.json"))}
    py = {r["file"]: r for r in load(PY)}
    js = {r["file"]: r for r in load(JS)}

    assigned, disagreements = [], []
    for fname, c in cases.items():
        p, j = py[fname], js[fname]
        agree = (p["verdict"] == j["verdict"]) and (p["reason"] == j["reason"])
        if agree:
            assigned.append({
                "file": fname,
                "class": c["class"],
                "scored": c["scored"],
                "now": c["now"],
                "consumed": c["consumed"],
                "verdict": p["verdict"],
                "reason": p["reason"],
            })
        else:
            disagreements.append((fname, c, p, j))

    with open(ASSIGNED, "w", encoding="utf-8") as fh:
        json.dump(assigned, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    # findings.md
    lines = []
    lines.append("# Round-0 (Track B) — reference-divergence findings\n")
    lines.append(
        "Every row here is a case where the two independent reference implementations "
        "(Python `aep-sandbox` and the JS CTF port) returned **different** verdicts on the "
        "**same** vector. Per the interlab design, a divergence between references is a "
        "corpus defect published as a finding — it is recorded, never patched away by "
        "editing a verifier. Such a vector is **excluded from the assigned values** and "
        "cannot be scored until the divergence is resolved upstream.\n")
    scored_div = [d for d in disagreements if d[1]["scored"]]
    lines.append(
        f"\n**Total vectors:** {len(cases)}  |  **Agreements (assigned):** {len(assigned)}  "
        f"|  **Disagreements:** {len(disagreements)} "
        f"({len(scored_div)} in scored classes, {len(disagreements) - len(scored_div)} in "
        f"probe class).\n")

    if not disagreements:
        lines.append("\n_No divergences._\n")
    for fname, c, p, j in disagreements:
        i = first_diff(p.get("canonical_core"), j.get("canonical_core"))
        pv = p["verdict"] + (f":{p['reason']}" if p["reason"] else "")
        jv = j["verdict"] + (f":{j['reason']}" if j["reason"] else "")
        lines.append(f"\n## {fname}\n")
        lines.append(f"- **class:** {c['class']} ({'scored' if c['scored'] else 'probe / unscored'})")
        lines.append(f"- **Python reference:** `{pv}`")
        lines.append(f"- **JS port:** `{jv}`")
        lines.append(f"- **design note:** {c['note']}")
        cp, cj = p.get("canonical_core"), j.get("canonical_core")
        if cp != cj:
            lines.append(
                f"- **canonical receipt-core bytes differ** — first divergence at byte "
                f"offset {i} (Python len {len(cp) if cp else 0}, JS len "
                f"{len(cj) if cj else 0}):")
            lines.append("")
            lines.append("  ```text")
            lines.append(f"  python: {window(cp, i)}")
            lines.append(f"  js    : {window(cj, i)}")
            lines.append("  ```")
            lines.append(
                "  The signer (Python) hashed/signed over its canonical bytes; the port "
                "recomputes a *different* canonical string for the same parsed object, so "
                "its recomputed `receipt_hash` cannot match the stored one and it stops at "
                "`chain_integrity` with `content_mutated`.")
        else:
            lines.append(
                "- canonical receipt-core bytes are **identical**; the divergence is not in "
                "canonicalisation but in a later check's semantics (see design note).")
        lines.append("")

    with open(FINDINGS, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"[compare] {len(cases)} vectors: {len(assigned)} agree, "
          f"{len(disagreements)} disagree")
    for fname, c, p, j in disagreements:
        pv = p["verdict"] + (f":{p['reason']}" if p["reason"] else "")
        jv = j["verdict"] + (f":{j['reason']}" if j["reason"] else "")
        print(f"  DIVERGENCE  {fname}  python={pv}  js={jv}")
    print(f"[compare] wrote {ASSIGNED} and {FINDINGS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
