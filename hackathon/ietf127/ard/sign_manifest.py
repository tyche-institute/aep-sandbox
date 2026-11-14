#!/usr/bin/env python3
"""Sign the trustManifest of an ARD entry with an ES256 test key.

Written by Tyche Institute for the IETF 127 Hackathon, from the text of
section 3.5 of draft-bu-dawn-ard-discovery-00 (an individual Internet-Draft by
other authors). Implementation label: author (Tyche Institute).

What it signs: the RFC 8785 (JCS) bytes of the trustManifest object with the
"signature" member removed. The JWS (RFC 7515) protected header is
{"alg":"ES256","kid":<kid>}; the signature is raw r||s (64 bytes).

  --variant A   compact serialization, detached payload (RFC 7515 Appendix F):
                BASE64URL(header) + ".." + BASE64URL(signature)
  --variant B   compact serialization, payload embedded:
                BASE64URL(header) + "." + BASE64URL(JCS bytes) + "." + ...

Usage:
  python3 sign_manifest.py --new-key my-test-key.pem --did did:web:example.org \\
      --context-out my-context.json
  python3 sign_manifest.py --entry in.json --key my-test-key.pem \\
      --kid did:web:example.org#test-key-1 --variant A --out out.json
  (add --index N to sign trustManifests[N] instead of trustManifest)
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ardlib as L  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


def new_key(path, did, context_out=None):
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    kid = did + "#test-key-1"
    doc = {"id": did,
           "verificationMethod": [{"id": kid, "type": "JsonWebKey",
                                   "controller": did,
                                   "publicKeyJwk": L.public_jwk(priv.public_key())}],
           "assertionMethod": [kid]}
    print("wrote private test key %s (kid %s)" % (path, kid))
    if not context_out:
        print(json.dumps({did: doc}, indent=2))
        return
    # copy context.json and the DID documents, with this key for this DID
    with open(os.path.join(HERE, "context.json"), "rb") as f:
        ctx = L.load_json_strict(f.read())
    with open(os.path.join(HERE, ctx["did_documents"]), "rb") as f:
        docs = L.load_json_strict(f.read())
    docs["documents"][did] = doc
    out_dir = os.path.dirname(os.path.abspath(context_out))
    docs_path = os.path.splitext(os.path.abspath(context_out))[0] + "-did-documents.json"
    with open(docs_path, "w") as f:
        json.dump(docs, f, indent=2)
    rel = lambda p: os.path.relpath(os.path.join(HERE, p), out_dir)  # noqa: E731
    ctx["did_documents"] = os.path.relpath(docs_path, out_dir)
    ctx["attestation_keys"] = {k: rel(v) for k, v in ctx["attestation_keys"].items()}
    ctx["local_files"] = {k: rel(v) for k, v in ctx["local_files"].items()}
    ctx["preimages"] = {k: rel(v) for k, v in ctx["preimages"].items()}
    with open(context_out, "w") as f:
        json.dump(ctx, f, indent=2)
    print("wrote %s and %s" % (context_out, docs_path))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--new-key", help="write a fresh P-256 test key (PEM) here")
    ap.add_argument("--did", default="did:web:example.org")
    ap.add_argument("--context-out",
                    help="with --new-key: write a copy of context.json that uses the new key")
    ap.add_argument("--entry")
    ap.add_argument("--key")
    ap.add_argument("--kid")
    ap.add_argument("--variant", choices=["A", "B"], default="A")
    ap.add_argument("--index", type=int,
                    help="sign trustManifests[INDEX] instead of trustManifest")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.new_key:
        new_key(a.new_key, a.did, a.context_out)
        return 0
    if not (a.entry and a.key and a.kid and a.out):
        ap.error("--entry, --key, --kid and --out are needed to sign")
    with open(a.entry, "rb") as f:
        entry = L.load_json_strict(f.read())
    priv = L.load_private_pem(a.key)
    if a.index is None:
        entry["trustManifest"] = L.sign_manifest(entry["trustManifest"], priv,
                                                 a.kid, a.variant)
    else:
        entry["trustManifests"][a.index] = L.sign_manifest(
            entry["trustManifests"][a.index], priv, a.kid, a.variant)
    with open(a.out, "w") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote %s (variant %s)" % (a.out, a.variant))
    return 0


if __name__ == "__main__":
    sys.exit(main())
