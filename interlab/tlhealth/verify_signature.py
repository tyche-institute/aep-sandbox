#!/usr/bin/env python3
"""verify_signature.py — does this trusted list's own signature actually check out?

Until now the instrument recorded whether a signature BLOCK was present, which is a
statement about the file's shape and not about its authenticity. That gap mattered twice.
When four copies of the MERCOSUR regional list disagreed by 110 days we could say only
that each "carries a signature block", and a reader could reasonably have heard "each is
validly signed" — a claim we had not checked. And the Icelandic archaeology turns on
whether an archived copy is evidence or merely a plausible file; the answer there was that
all 28 recovered versions verify, which is what makes the corpus worth depositing.

WHAT THIS CHECKS, precisely: that the XML signature over the document verifies against the
public key in the certificate embedded in that same signature, and that the digest covers
the document as delivered. It is a self-consistency check — the document has not been
altered since it was signed.

WHAT IT DOES NOT CHECK, and must never be reported as: that the signing certificate is
trusted, that it chains to anything, that it was valid at signing time, or that the signer
was authorised to sign a national trusted list. That last one is a scheme question and the
EU LOTL answers it by declaring which certificates a scheme operator may use. Conflating
"the bytes are intact" with "this list is authentic" would be exactly the kind of
overstatement this instrument exists to avoid.
"""
from __future__ import annotations
import sys

RESULT_INTACT = "intact"          # signature verifies against its own embedded certificate
RESULT_BROKEN = "broken"          # a signature is present and does not verify
RESULT_ABSENT = "no_signature"    # no signature element at all
RESULT_UNSUPPORTED = "unsupported"  # present, but this checker cannot evaluate it


def verify(raw: bytes) -> dict:
    out = {"signature": RESULT_ABSENT, "detail": ""}
    if b"Signature" not in raw:
        return out
    try:
        from lxml import etree
        from signxml import XMLVerifier
    except ImportError as e:
        return {"signature": RESULT_UNSUPPORTED, "detail": f"library missing: {e}"}

    try:
        doc = etree.fromstring(raw)
    except Exception as e:
        return {"signature": RESULT_UNSUPPORTED, "detail": f"not parseable as XML: {str(e)[:90]}"}

    sig = doc.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    if sig is None:
        return out

    # Hand the embedded certificate over EXPLICITLY rather than letting the library select
    # and police it. Letting it choose reported the European Commission's own list of lists
    # as "broken" — the complaints were about certificate KeyUsage and certificate selection,
    # never about the digest. A checker that calls a valid national artefact broken is a
    # false-accusation generator, and this one nearly shipped as one.
    import re as _re
    ns = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
    certs = doc.findall(".//ds:X509Certificate", ns)
    if not certs or not (certs[0].text or "").strip():
        return {"signature": RESULT_UNSUPPORTED,
                "detail": "signature present but carries no X509Certificate to check against"}
    # Verify AS AT THE DOCUMENT'S OWN ISSUE DATE, not as at now. An archived list from 2014
    # was signed with a certificate that expired in 2018, and asking "is that certificate
    # valid today" answers a question nobody posed: the document can be perfectly intact and
    # the certificate long expired. Checking historical artefacts against the present clock
    # would report 25 of 28 Icelandic versions as broken and invite the exact opposite of the
    # truth — that web archives do not preserve signed artefacts. They do; we were holding
    # the clock wrong.
    when = None
    m = _re.search(rb"<(?:\w+:)?ListIssueDateTime>([^<]+)<", raw)
    if m:
        try:
            import datetime as _dt
            when = _dt.datetime.fromisoformat(m.group(1).decode().strip().replace("Z", "+00:00"))
        except Exception:
            when = None

    # A signature may carry several certificates and the signer's is not always first.
    # Try each, and accept if any verifies — the question is whether the document is intact
    # under the key that signed it, not whether we guessed the order.
    last = ""
    for node in certs:
        if not (node.text or "").strip():
            continue
        pem = ("-----BEGIN CERTIFICATE-----\n"
               + _re.sub(r"\s", "", node.text)
               + "\n-----END CERTIFICATE-----\n")
        try:
            kw = dict(x509_cert=pem, expect_references=None, ignore_ambiguous_key_info=True)
            if when is not None:
                try:
                    from signxml import SignatureConfiguration
                    kw["expect_config"] = SignatureConfiguration(verification_time=when)
                except Exception:
                    pass
            XMLVerifier().verify(doc, **kw)
            return {"signature": RESULT_INTACT,
                    "detail": f"verified as at {when.date()}" if when else ""}
        except Exception as e:
            last = str(e)[:160]
    try:
        raise RuntimeError(last or "no embedded certificate verified the signature")
    except Exception as e:
        msg = str(e)[:140]
        # A checker that cannot handle a construct must say so rather than call it broken:
        # reporting "broken" about a national trusted list because our library lacks a
        # transform would be a false accusation dressed as a measurement.
        lowered = msg.lower()
        if any(k in lowered for k in ("unsupported", "not implemented", "unknown algorithm",
                                      "cannot", "no module", "unsupported transform")):
            return {"signature": RESULT_UNSUPPORTED, "detail": msg}
        return {"signature": RESULT_BROKEN, "detail": msg}


if __name__ == "__main__":
    for path in sys.argv[1:]:
        r = verify(open(path, "rb").read())
        print(f"{r['signature']:12s} {path}  {r['detail'][:80]}")
