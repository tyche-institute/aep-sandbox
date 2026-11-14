#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Cell 1 verifier (Tyche Institute, IETF 127 Hackathon).

For each vector it reads one COSE_Sign1 record and one held JSON value, and
reports one outcome: verified, failed or unverified, with a reason.

Usage (from the cell1 directory):
    python3 tools/verify_cell1.py                      # all vectors, writes return.json
    python3 tools/verify_cell1.py --out my-return.json
    python3 tools/verify_cell1.py --record R.cose --held payload/payload.json --pubkey K.pem

Built-in Python 3 modules plus the "cryptography" package.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cell1lib as L  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VERIFIED, FAILED, UNVERIFIED = "verified", "failed", "unverified"

# Applicable Content Types of CDE value 1 (CDE -00, IANA Considerations).
CDE1_TYPES = {"application/cbor", "application/cbor-seq", "application/cose",
              "application/cose-key", "application/cose-key-set", "application/cose-x509",
              "application/cwt", "application/multipart-core"}
CDE1_SUFFIXES = ("+cbor", "+cbor-seq", "+cose", "+cwt", "+sd-cwt")
CONTENT_FORMATS = {60: "application/cbor", 61: "application/cwt", 62: "application/multipart-core",
                   63: "application/cbor-seq", 50: "application/json",
                   16: "application/cose", 17: "application/cose", 18: "application/cose",
                   96: "application/cose", 97: "application/cose", 98: "application/cose",
                   101: "application/cose-key", 102: "application/cose-key-set",
                   258: "application/swid+cbor"}
CDE_IMPLEMENTED = {1}
UNDERSTOOD_CRIT = {L.LABEL_ALG, L.LABEL_CRIT, L.LABEL_KID, L.LABEL_CWT, L.LABEL_HASH_ALG,
                   L.LABEL_PREIMAGE_CT, L.LABEL_LOCATION, L.LABEL_CDE, L.LABEL_CPB_REFS}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def cde1_matches(ct) -> bool:
    if is_int(ct):
        ct = CONTENT_FORMATS.get(ct)
    if not isinstance(ct, str):
        return False
    mt = ct.split(";", 1)[0].strip().lower()
    if mt in CDE1_TYPES:
        return True
    if "/" not in mt:
        return False
    sub = mt.split("/", 1)[1]
    plus = sub.rfind("+")
    return plus > 0 and sub[plus:] in CDE1_SUFFIXES


class Report:
    def __init__(self):
        self.checks = []  # (name, pass|fail|not_evaluated, note)

    def add(self, name, state, note=""):
        self.checks.append((name, state, note))


def verify_one(record_bytes: bytes, held_bytes: bytes, pubkey, declaration: dict):
    """Return (outcome, reason, side, report)."""
    rep = Report()
    order = ["structure", "signature", "header-placement", "encoding-declaration",
             "held-value", "content-binding"]

    def stop(outcome, reason, side, failed_check):
        seen = {c[0] for c in rep.checks}
        rep.add(failed_check, "fail" if outcome == FAILED else "not_evaluated", reason)
        seen.add(failed_check)
        for name in order:
            if name not in seen:
                rep.add(name, "not_evaluated")
        return outcome, reason, side, rep

    # 1. structure
    try:
        rec = L.parse_sign1(record_bytes)
    except L.CBORError as exc:
        return stop(FAILED, "cose-malformed", "?", "structure")
    hdr, unp = rec.protected, rec.unprotected
    side = "json" if hdr.has(L.LABEL_CPB_REFS) else "cbor"
    rep.add("structure", "pass")

    # 2. signature (RFC 9052 Section 4.4). Cell rule: a bad signature fails the vector.
    if hdr.get(L.LABEL_ALG) != L.ALG_EDDSA:
        return stop(UNVERIFIED, "alg-not-implemented", side, "signature")
    if not L.check_signature(rec, pubkey):
        return stop(FAILED, "signature-invalid", side, "signature")
    rep.add("signature", "pass")

    # 3. header placement and crit
    for label in (L.LABEL_CDE, L.LABEL_CPB_REFS, L.LABEL_HASH_ALG, L.LABEL_PREIMAGE_CT, L.LABEL_LOCATION):
        if unp.has(label):
            return stop(FAILED, "parameter-in-unprotected-header", side, "header-placement")
    crit = hdr.get(L.LABEL_CRIT)
    if hdr.has(L.LABEL_CRIT):
        if not isinstance(crit, list) or not crit:
            return stop(FAILED, "crit-malformed", side, "header-placement")
        for label in crit:
            if label not in UNDERSTOOD_CRIT or not hdr.has(label):
                return stop(FAILED, "crit-not-understood", side, "header-placement")
    rep.add("header-placement", "pass")

    # 4. encoding declaration.
    # CDE -00 "Consistency with preimage-content-type": runs before the other content checks when label 271 is present.
    if hdr.has(L.LABEL_CDE):
        enc = hdr.get(L.LABEL_CDE)
        if not hdr.has(L.LABEL_PREIMAGE_CT):
            return stop(FAILED, "content-type-absent", side, "encoding-declaration")
        if is_int(enc) and enc in CDE_IMPLEMENTED and not cde1_matches(hdr.get(L.LABEL_PREIMAGE_CT)):
            return stop(FAILED, "content-type-mismatch", side, "encoding-declaration")

    if side == "json":
        return _verify_cpb(rec, held_bytes, declaration, rep, stop)
    return _verify_cde(rec, held_bytes, rep, stop)


def _verify_cpb(rec, held_bytes, declaration, rep, stop):
    hdr = rec.protected
    side = "json"
    cpb = declaration["cpb"]
    # cpb-refs closed map (CPB -06, Envelope Carriage)
    refs = hdr.get(L.LABEL_CPB_REFS)
    if not isinstance(refs, list) or not 1 <= len(refs) <= 64:
        return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
    parsed, seen = [], set()
    for item in refs:
        if not isinstance(item, L.CMap):
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        keys = item.labels()
        if any(not is_int(k) or k not in (1, 2, 3, 4) for k in keys) or not all(item.has(k) for k in (1, 3, 4)):
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        t, p, a, d = item.get(1), item.get(2), item.get(3), item.get(4)
        if not (isinstance(t, str) and 1 <= len(t.encode()) <= 255):
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        if item.has(2) and not (isinstance(p, str) and 1 <= len(p.encode()) <= 64):
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        if not (isinstance(a, str) and 1 <= len(a.encode()) <= 32):
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        if not (isinstance(d, (str, bytes)) and 1 <= len(d.encode() if isinstance(d, str) else d) <= 128):
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        ident = (t, p, a, type(d).__name__, d)
        if ident in seen:
            return stop(FAILED, "cpb-refs-malformed", side, "encoding-declaration")
        seen.add(ident)
        parsed.append((t, p if item.has(2) else None, a, d))
    if cpb.get("profile_requires_cpb_refs"):
        crit = hdr.get(L.LABEL_CRIT)
        if not isinstance(crit, list) or L.LABEL_CPB_REFS not in crit:
            return stop(FAILED, "cpb-refs-not-critical", side, "encoding-declaration")
    # context selection
    selected = []
    for t, p, a, d in parsed:
        decls = [x for x in cpb["artifact_types"] if x["type"] == t]
        if len(decls) != 1:
            return stop(UNVERIFIED, "context-unresolved", side, "encoding-declaration")
        ctxs = decls[0]["contexts"]
        if len(ctxs) == 1:
            ctx = ctxs[0]
            if p is not None and p != ctx["purpose"]:
                return stop(UNVERIFIED, "context-unresolved", side, "encoding-declaration")
        else:
            m = [c for c in ctxs if p is not None and c["purpose"] == p]
            if len(m) != 1:
                return stop(UNVERIFIED, "context-unresolved", side, "encoding-declaration")
            ctx = m[0]
        if a != ctx["digest_alg"]:
            return stop(FAILED, "digest-alg-mismatch", side, "encoding-declaration")
        if ctx["representation"] != "bare-hex" or not isinstance(d, str) or not HEX64.match(d):
            return stop(FAILED, "representation-mismatch", side, "encoding-declaration")
        if ctx["algorithm"] != "jcs" or ctx.get("exclusion_set"):
            return stop(UNVERIFIED, "context-not-implemented", side, "encoding-declaration")
        selected.append(d)
    # Hash Envelope Mode checks (CPB -06, Hash Envelope Mode; RFC 9995)
    if hdr.has(L.LABEL_CTYPE) or rec.unprotected.has(L.LABEL_CTYPE):
        return stop(FAILED, "content-type-label-3-present", side, "encoding-declaration")
    if not hdr.has(L.LABEL_HASH_ALG):
        return stop(FAILED, "hash-alg-absent", side, "encoding-declaration")
    if not hdr.has(L.LABEL_PREIMAGE_CT):
        return stop(FAILED, "content-type-absent", side, "encoding-declaration")
    if hdr.get(L.LABEL_HASH_ALG) != L.SHA256:
        return stop(UNVERIFIED, "hash-alg-not-implemented", side, "encoding-declaration")
    rep.add("encoding-declaration", "pass", "cpb-refs selects jcs")
    # held value
    try:
        value = L.read_json_strict(held_bytes)
        pre = L.jcs(value)
    except L.HeldValueError:
        return stop(FAILED, "held-value-rejected", side, "held-value")
    except L.HeldValueNotImplemented:
        return stop(UNVERIFIED, "held-value-not-implemented", side, "held-value")
    rep.add("held-value", "pass")
    digest = hashlib.sha256(pre).digest()
    if rec.payload != digest or any(d != digest.hex() for d in selected):
        return stop(FAILED, "recreated-digest-mismatch", side, "content-binding")
    rep.add("content-binding", "pass")
    return VERIFIED, "recreated-digest-match", side, rep


def _verify_cde(rec, held_bytes, rep, stop):
    hdr = rec.protected
    side = "cbor"
    # CDE -00 "Verifying the Content Binding": a verifier holding a structured value
    if not hdr.has(L.LABEL_CDE):
        return stop(UNVERIFIED, "encoding-absent", side, "encoding-declaration")
    enc = hdr.get(L.LABEL_CDE)
    if not (is_int(enc) and enc in CDE_IMPLEMENTED):
        return stop(UNVERIFIED, "encoding-not-implemented", side, "encoding-declaration")
    if hdr.get(L.LABEL_HASH_ALG) != L.SHA256:
        return stop(UNVERIFIED, "hash-alg-not-implemented", side, "encoding-declaration")
    rep.add("encoding-declaration", "pass", "label 271 = 1")
    try:
        value = L.read_json_strict(held_bytes)
        pre = L.cbor_encode(L.json_to_cbor_model(value))
    except (L.HeldValueError, L.HeldValueNotImplemented, L.CBORError):
        # CDE -00 is silent here; we follow its reference code ("value-not-encodable").
        return stop(UNVERIFIED, "value-not-encodable", side, "held-value")
    rep.add("held-value", "pass")
    if hashlib.sha256(pre).digest() != rec.payload:
        return stop(FAILED, "recreated-digest-mismatch", side, "content-binding")
    rep.add("content-binding", "pass")
    return VERIFIED, "recreated-digest-match", side, rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vectors", default=os.path.join(HERE, "vectors"))
    ap.add_argument("--pubkey", default=os.path.join(HERE, "keys", "test-public-key.pem"))
    ap.add_argument("--declaration", default=os.path.join(HERE, "declaration.json"))
    ap.add_argument("--out", default="return.json", help="return file to write")
    ap.add_argument("--record", help="verify one COSE_Sign1 file instead of the vector set")
    ap.add_argument("--held", help="held JSON value for --record")
    ap.add_argument("--id", default="own-record", help="id to print for --record")
    ap.add_argument("--checks", action="store_true", help="print each check as pass, fail or not_evaluated")
    args = ap.parse_args(argv)

    pubkey = L.load_public_key(args.pubkey)
    declaration = json.load(open(args.declaration, encoding="utf-8"))
    if args.record:
        if not args.held:
            ap.error("--record needs --held")
        items = [(args.id, args.record, args.held)]
    else:
        index = json.load(open(os.path.join(args.vectors, "index.json"), encoding="utf-8"))
        items = [(v["id"], os.path.join(args.vectors, v["record"]), os.path.join(args.vectors, v["held"]))
                 for v in index["vectors"]]

    out = []
    print(f"{'id':<12} {'side':<5} {'outcome':<11} reason")
    for vid, rpath, hpath in items:
        outcome, reason, side, rep = verify_one(open(rpath, "rb").read(), open(hpath, "rb").read(),
                                                pubkey, declaration)
        print(f"{vid:<12} {side:<5} {outcome:<11} {reason}")
        if args.checks:
            for name, state, note in rep.checks:
                print(f"{'':<12}   {name:<22} {state:<14} {note}")
        out.append({"id": vid, "outcome": outcome, "reason": reason})
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"wrote {args.out} ({len(out)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
