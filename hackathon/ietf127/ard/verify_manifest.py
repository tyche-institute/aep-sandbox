#!/usr/bin/env python3
"""Check ARD entries that carry a trustManifest (or trustManifests[]).

Written by Tyche Institute for the IETF 127 Hackathon, from the text of
section 3.5 of draft-bu-dawn-ard-discovery-00 (an individual Internet-Draft by
other authors). Not reviewed or endorsed by the ARD authors. All keys are
test keys.
Implementation label: author (Tyche Institute).

Usage:
  python3 verify_manifest.py                       # all vectors, print rows
  python3 verify_manifest.py --out return.json     # also write the return file
  python3 verify_manifest.py --checks              # print every check
  python3 verify_manifest.py --entry examples/entry-single-detached.json
  python3 verify_manifest.py --show-record evidence/action-record.cose

Outcome words: verified, failed, unverified (see ../OUTCOMES.md).
A check reports pass, fail or not_evaluated. The earliest check that does not
pass decides: fail gives "failed"; a check that cannot run gives "unverified".
"""

import argparse
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ardlib as L  # noqa: E402


class Stop(Exception):
    """Raised by a check that does not pass."""

    def __init__(self, outcome, reason, detail=""):
        super().__init__(reason)
        self.outcome, self.reason, self.detail = outcome, reason, detail


def fail(reason, detail=""):
    raise Stop("failed", reason, detail)


def cannot(reason, detail=""):
    raise Stop("unverified", reason, detail)


def parse_time(s):
    if not isinstance(s, str):
        raise ValueError("not a string")
    t = s[:-1] + "+00:00" if s.endswith("Z") else s
    d = datetime.datetime.fromisoformat(t)
    if d.tzinfo is None:
        raise ValueError("no time zone")
    return d


class Context:
    def __init__(self, path):
        self.base = os.path.dirname(os.path.abspath(path))
        with open(path, "rb") as f:
            c = L.load_json_strict(f.read())
        self.now = parse_time(c["now"])
        with open(self._p(c["did_documents"]), "rb") as f:
            self.did_docs = L.load_json_strict(f.read())["documents"]
        self.att_keys = {}
        for kid, p in c.get("attestation_keys", {}).items():
            with open(self._p(p), "rb") as f:
                self.att_keys[kid] = L.jwk_public_key(L.load_json_strict(f.read()))
        self.files = {u: self._p(p) for u, p in c.get("local_files", {}).items()}
        self.preimages = {u: self._p(p) for u, p in c.get("preimages", {}).items()}

    def _p(self, p):
        return os.path.normpath(os.path.join(self.base, p))

    def fetch(self, uri):
        p = self.files.get(uri)
        if p is None or not os.path.isfile(p):
            return None
        with open(p, "rb") as f:
            return f.read()

    def key_for(self, identity, kid):
        doc = self.did_docs.get(identity)
        if doc is None:
            return None
        for vm in doc.get("verificationMethod", []):
            if vm.get("id") == kid and vm.get("controller") == identity:
                if kid not in doc.get("assertionMethod", []):
                    return None
                return L.jwk_public_key(vm["publicKeyJwk"])
        return None


class Run:
    def __init__(self):
        self.checks = []  # (name, status, detail)

    def check(self, name, fn):
        try:
            detail = fn()
        except Stop as s:
            self.checks.append((name, "fail" if s.outcome == "failed"
                                else "not_evaluated",
                                s.reason + (": " + s.detail if s.detail else "")))
            raise
        self.checks.append((name, "pass", detail or ""))


def publisher_of(urn):
    parts = urn.split(":") if isinstance(urn, str) else []
    if len(parts) != 5 or parts[0] != "urn" or parts[1] != "air" or not all(parts[2:]):
        return None
    return parts[2]


def verify_entry(entry_bytes, ctx):
    run = Run()
    st = {}

    # 1. entry structure (section 3.2.1, 3.3, CDDL in section 5)
    def c_entry():
        try:
            e = L.load_json_strict(entry_bytes)
        except (ValueError, L.JsonInputError) as x:
            cannot("entry-unreadable", str(x))
        if not isinstance(e, dict):
            cannot("entry-unreadable", "not a JSON object")
        for k in ("identifier", "displayName", "type"):
            if not isinstance(e.get(k), str):
                fail("entry-malformed", "missing " + k)
        if ("url" in e) == ("data" in e):
            fail("entry-malformed", "needs exactly one of url or data")
        pub = publisher_of(e["identifier"])
        if pub is None:
            fail("entry-malformed", "identifier is not urn:air:<publisher>:<ns>:<name>")
        ms = []
        if "trustManifest" in e:
            ms.append(e["trustManifest"])
        if "trustManifests" in e:
            if not isinstance(e["trustManifests"], list) or not e["trustManifests"]:
                fail("entry-malformed", "trustManifests is not a non-empty array")
            ms.extend(e["trustManifests"])
        if not ms:
            cannot("no-trust-manifest", "an unsigned entry is a discovery hint")
        if "url" in e and "digest" not in e:
            fail("entry-digest-absent", "url without digest (section 3.5.2)")
        st.update(entry=e, publisher=pub, manifests=ms)
        return "%d manifest(s); publisher %s" % (len(ms), pub)

    try:
        run.check("entry structure", c_entry)
        e = st["entry"]
        for i, m in enumerate(st["manifests"]):
            verify_manifest_obj(run, i, m, e, ctx)

        # publisher binding (section 3.5.1 b): one manifest's identity binds
        def c_pub():
            want = "did:web:" + st["publisher"]
            if not any(m["identity"] == want for m in st["manifests"]):
                fail("no-publisher-manifest", "no manifest with identity " + want)
            return want

        run.check("publisher binding", c_pub)

        # artifact digest (section 6.4, bullet 1)
        def c_art():
            if "url" not in e:
                return "inline data: not checked"
            alg, hx = parse_alg(e["digest"])
            body = ctx.fetch(e["url"])
            if body is None:
                cannot("artifact-unavailable", e["url"])
            if L.DIGESTS[alg](body).hexdigest() != hx.lower():
                fail("artifact-digest-mismatch")
            return e["digest"]

        run.check("artifact digest", c_art)

        for i, m in enumerate(st["manifests"]):
            for j, a in enumerate(m.get("attestations", [])):
                verify_attestation(run, "m%d a%d" % (i, j), a, e, ctx)
    except Stop as s:
        return s.outcome, s.reason, run.checks
    return "verified", "all-checks-pass", run.checks


def parse_alg(d):
    try:
        alg, hx = L.parse_digest(d)
    except ValueError as x:
        fail("digest-malformed", str(x))
    if alg not in L.DIGESTS:
        cannot("digest-alg-not-implemented", alg)
    return alg, hx


def verify_manifest_obj(run, i, m, e, ctx):
    tag = "m%d " % i

    def c_struct():
        if not isinstance(m, dict):
            fail("manifest-malformed", "not an object")
        for k in ("identity", "signature"):
            if not isinstance(m.get(k), str):
                fail("manifest-malformed", "missing " + k)
        if not isinstance(m.get("subject"), dict):
            fail("manifest-malformed", "missing subject")
        if not isinstance(m.get("attestations", []), list):
            fail("manifest-malformed", "attestations is not an array")
        return m["identity"]

    run.check(tag + "structure", c_struct)

    # signature (section 3.5, "signature")
    def c_sig():
        try:
            header, h64, p64, embedded, sig = L.jws_parse(m["signature"])
        except ValueError as x:
            fail("jws-malformed", str(x))
        if header.get("alg") != "ES256":
            cannot("jws-alg-not-implemented", str(header.get("alg")))
        crit = header.get("crit")
        if crit is not None:
            cannot("jws-crit-not-implemented", str(crit))
        kid = header.get("kid")
        if not isinstance(kid, str):
            fail("kid-absent")
        if kid.split("#", 1)[0] != m["identity"]:
            fail("kid-not-bound-to-identity", "%s vs %s" % (kid, m["identity"]))
        pub = ctx.key_for(m["identity"], kid)
        if pub is None:
            cannot("key-unresolved", kid)
        want = L.manifest_signing_bytes(m)
        signed64 = p64 if embedded is not None else L.b64u(want)
        if not L.es256_verify(pub, (h64 + "." + signed64).encode("ascii"), sig):
            fail("signature-invalid")
        if embedded is not None and embedded != want:
            fail("signed-bytes-not-jcs",
                 "embedded payload is not the JCS of the manifest")
        return "%s, %s payload" % (kid, "embedded" if embedded is not None
                                   else "detached")

    run.check(tag + "signature", c_sig)

    # time (section 3.5, issuedAt / expiresAt) against the stated "now"
    def c_time():
        out = []
        for k in ("issuedAt", "expiresAt"):
            if k in m:
                try:
                    t = parse_time(m[k])
                except ValueError as x:
                    fail("timestamp-malformed", "%s: %s" % (k, x))
                if k == "issuedAt" and t > ctx.now:
                    fail("issued-in-future")
                if k == "expiresAt" and t <= ctx.now:
                    fail("manifest-expired", m[k])
                out.append(k)
        return ", ".join(out) or "no timestamps"

    run.check(tag + "time", c_time)

    # subject matches the parent entry (section 3.5.1 a)
    def c_subj():
        s = m["subject"]
        for k in ("identifier", "type", "digest", "version"):
            if k in e or k in s:
                if s.get(k) != e.get(k):
                    fail("subject-entry-mismatch", k)
        return s["identifier"]

    run.check(tag + "subject", c_subj)


ATT_MEDIA = ('application/cose; cose-type="cose-sign1"', "application/cose")


def verify_attestation(run, tag, a, e, ctx):
    st = {}

    # pin: attestations[].digest over the external document (3.5.2, 6.4)
    def c_pin():
        if not isinstance(a, dict) or not isinstance(a.get("uri"), str) \
                or not isinstance(a.get("type"), str):
            fail("attestation-malformed")
        body = ctx.fetch(a["uri"])
        if "digest" in a:
            alg, hx = parse_alg(a["digest"])
            if body is None:
                cannot("attestation-unavailable", a["uri"])
            if L.DIGESTS[alg](body).hexdigest() != hx.lower():
                fail("attestation-digest-mismatch")
        elif body is None:
            cannot("attestation-unavailable", a["uri"])
        st["body"] = body
        return a.get("digest", "no digest")

    run.check(tag + " pin", c_pin)

    # binding: the attestation statement names the target (3.5.2, 6.4)
    def c_bind():
        if a.get("mediaType") not in ATT_MEDIA:
            cannot("attestation-format-not-implemented", str(a.get("mediaType")))
        try:
            prot_b, prot, unprot, payload, sig = L.cose_sign1_parse(st["body"])
        except (L.CborError, UnicodeDecodeError) as x:
            fail("attestation-malformed", str(x))
        kid = prot.get(4, unprot.get(4))
        kid = kid.decode("utf-8", "replace") if isinstance(kid, bytes) else kid
        pub = ctx.att_keys.get(kid)
        if pub is None:
            cannot("attestation-key-unknown", str(kid))
        if prot.get(1) != -8:
            cannot("attestation-alg-not-implemented", str(prot.get(1)))
        if not L.ed25519_verify(pub, L.cose_sig_structure(prot_b, payload), sig):
            fail("attestation-signature-invalid")
        if 258 in prot:  # RFC 9995 Hash Envelope: payload is a digest
            if prot[258] != -16:
                cannot("attestation-hash-alg-not-implemented", str(prot[258]))
            p = ctx.preimages.get(a["uri"])
            if p is None or not os.path.isfile(p):
                cannot("attestation-preimage-unavailable", a["uri"])
            with open(p, "rb") as f:
                content = f.read()
            if hashlib.sha256(content).digest() != payload:
                fail("attestation-preimage-mismatch")
            ctype = prot.get(259)
        else:
            content = payload
            ctype = prot.get(3)
        if ctype != "application/cbor":
            cannot("attestation-content-not-implemented", str(ctype))
        try:
            claim = L.cbor_decode(content)
        except (L.CborError, UnicodeDecodeError) as x:
            fail("attestation-malformed", str(x))
        subj = claim.get("subject") if isinstance(claim, dict) else None
        if not isinstance(subj, dict):
            fail("attestation-subject-absent")
        if subj.get("identifier") != e["identifier"] or \
                subj.get("digest") != e.get("digest"):
            fail("attestation-subject-mismatch",
                 "statement names %s" % subj.get("identifier"))
        return "statement names %s and %s" % (subj["identifier"], subj["digest"])

    run.check(tag + " binding", c_bind)


def show_record(path):
    with open(path, "rb") as f:
        data = f.read()
    prot_b, prot, unprot, payload, sig = L.cose_sign1_parse(data)
    show = {k: (v.decode("utf-8", "replace") if isinstance(v, bytes) else v)
            for k, v in prot.items()}
    print("record          %s  (%d bytes)" % (L.digest_string(data), len(data)))
    print("protected       %s" % json.dumps(show, sort_keys=True))
    print("payload         %d bytes, sha256 %s"
          % (len(payload), hashlib.sha256(payload).hexdigest()))
    if 258 not in prot:
        claim = L.cbor_decode(payload)
        print("claim.subject   %s" % json.dumps(claim.get("subject"), sort_keys=True))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--context", default=os.path.join(HERE, "context.json"))
    ap.add_argument("--vectors", default=os.path.join(HERE, "vectors"))
    ap.add_argument("--entry", action="append",
                    help="check this entry file instead of the vectors")
    ap.add_argument("--out", help="write the return file (JSON array)")
    ap.add_argument("--checks", action="store_true", help="print every check")
    ap.add_argument("--show-record", help="print a COSE_Sign1 record and its claim")
    args = ap.parse_args()
    if args.show_record:
        return show_record(args.show_record)

    ctx = Context(args.context)
    if args.entry:
        items = [(os.path.splitext(os.path.basename(p))[0], p) for p in args.entry]
    else:
        with open(os.path.join(args.vectors, "index.json"), "rb") as f:
            idx = L.load_json_strict(f.read())
        items = [(v["id"], os.path.join(args.vectors, v["file"]))
                 for v in idx["vectors"]]

    rows = []
    print("now = %s" % ctx.now.isoformat().replace("+00:00", "Z"))
    for vid, path in items:
        with open(path, "rb") as f:
            outcome, reason, checks = verify_entry(f.read(), ctx)
        rows.append({"id": vid, "outcome": outcome, "reason": reason})
        print("%-28s %-11s %s" % (vid, outcome, reason))
        if args.checks:
            for name, status, detail in checks:
                print("    %-22s %-14s %s" % (name, status, detail))
            if outcome != "verified":
                print("    %-22s %-14s %s" % ("(later checks)", "not_evaluated",
                                              "an earlier check did not pass"))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(rows, f, indent=2)
            f.write("\n")
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
