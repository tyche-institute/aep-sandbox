#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Make the 2 cell 1 records for one JSON payload (Tyche Institute).

  JSON side: an RFC 9995 Hash Envelope over the RFC 8785 (JCS) bytes, plus a
             CPB typed reference in "cpb-refs" (test-only private-use label
             -65537) whose digest is the same SHA-256 as lowercase hex.
  CBOR side: an RFC 9995 Hash Envelope over the RFC 8949 Section 4.2.1 core
             deterministic bytes, with label 271 = 1 (CDE -00 suggested
             value; not assigned; test-only).

Usage (from the cell1 directory):
    python3 tools/sign_cell1.py --new-key my-key.pem --payload payload/payload.json --out-dir my-records
    python3 tools/sign_cell1.py --key my-key.pem     --payload payload/payload.json --out-dir my-records

--new-key writes a fresh Ed25519 test key (private PEM) and the public PEM
next to it. Built-in Python 3 modules plus the "cryptography" package.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cell1lib as L  # noqa: E402

DEFAULT_ISS = "https://issuer.example"
DEFAULT_SUB = "urn:air:example.org:agent:refund-assistant"
DEFAULT_TYPE = "example-action-record"


def build_headers(kid: bytes, iss: str, sub: str, ref_type: str, jcs_digest_hex: str):
    cwt = {1: iss, 2: sub}
    json_side = {
        L.LABEL_ALG: L.ALG_EDDSA,
        L.LABEL_CRIT: [L.LABEL_CPB_REFS],
        L.LABEL_KID: kid,
        L.LABEL_CWT: cwt,
        L.LABEL_HASH_ALG: L.SHA256,
        L.LABEL_PREIMAGE_CT: "application/json",
        L.LABEL_CPB_REFS: [{1: ref_type, 3: "SHA-256", 4: jcs_digest_hex}],
    }
    cbor_side = {
        L.LABEL_ALG: L.ALG_EDDSA,
        L.LABEL_KID: kid,
        L.LABEL_CWT: cwt,
        L.LABEL_HASH_ALG: L.SHA256,
        L.LABEL_PREIMAGE_CT: "application/cbor",
        L.LABEL_CDE: 1,
    }
    return json_side, cbor_side


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--key", help="Ed25519 private key, PEM (PKCS#8, no password)")
    g.add_argument("--new-key", help="write a fresh Ed25519 test key to this PEM path")
    ap.add_argument("--payload", required=True, help="the held JSON payload")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--kid", default="my-test-key")
    ap.add_argument("--iss", default=DEFAULT_ISS)
    ap.add_argument("--sub", default=DEFAULT_SUB)
    ap.add_argument("--type", default=DEFAULT_TYPE, help="CPB artifact type token")
    args = ap.parse_args(argv)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if args.new_key:
        key = Ed25519PrivateKey.generate()
        with open(args.new_key, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        pub_path = os.path.splitext(args.new_key)[0] + ".pub.pem"
        with open(pub_path, "wb") as fh:
            fh.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
        print(f"wrote test key {args.new_key} and public key {pub_path}")
    else:
        key = L.load_private_key(args.key)

    value = L.read_json_strict(open(args.payload, "rb").read())
    jcs_bytes = L.jcs(value)
    cbor_bytes = L.cbor_encode(L.json_to_cbor_model(value))
    jcs_d = hashlib.sha256(jcs_bytes).digest()
    cbor_d = hashlib.sha256(cbor_bytes).digest()
    jh, ch = build_headers(args.kid.encode(), args.iss, args.sub, args.type, jcs_d.hex())

    os.makedirs(args.out_dir, exist_ok=True)
    out = {
        "json-side.cose": L.sign1(jh, jcs_d, key),
        "cbor-side.cose": L.sign1(ch, cbor_d, key),
        "payload.jcs": jcs_bytes,
        "payload.cbor": cbor_bytes,
    }
    for name, data in out.items():
        with open(os.path.join(args.out_dir, name), "wb") as fh:
            fh.write(data)
    print(f"JCS bytes  {len(jcs_bytes):4d}  sha256 {jcs_d.hex()}")
    print(f"CBOR bytes {len(cbor_bytes):4d}  sha256 {cbor_d.hex()}")
    print(f"wrote {', '.join(out)} in {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
