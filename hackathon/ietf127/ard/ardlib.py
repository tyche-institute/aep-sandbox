"""Shared code for the ARD cell: JCS, ES256 JWS, a small CBOR codec, COSE_Sign1.

Written by Tyche Institute for the IETF 127 Hackathon, for a test.
Needs Python 3 built-in modules and the package "cryptography".

JCS here is RFC 8785 for the values a trustManifest holds in this cell:
objects, arrays, strings, true, false, null and integers with magnitude up to
2^53 - 1. Floating-point numbers raise an error; we did not implement the
ECMAScript number serialization.
"""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

MAX_SAFE = 2 ** 53 - 1


# ---------------------------------------------------------------- JSON input

class JsonInputError(ValueError):
    pass


def _no_dup_pairs(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise JsonInputError("duplicate member name: %r" % k)
        obj[k] = v
    return obj


def _no_float(text):
    raise JsonInputError("floating-point number not supported: %s" % text)


def _no_const(text):
    raise JsonInputError("non-JSON constant: %s" % text)


def load_json_strict(data):
    """Parse JSON text (bytes or str); reject duplicate names, floats, NaN."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(
        data,
        object_pairs_hook=_no_dup_pairs,
        parse_float=_no_float,
        parse_constant=_no_const,
    )


# ---------------------------------------------------------------- RFC 8785

def _jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise JsonInputError("lone surrogate in string")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if abs(v) > MAX_SAFE:
            raise JsonInputError("integer outside the I-JSON range")
        out.append(str(v))
    elif isinstance(v, float):
        raise JsonInputError("floating-point number not supported")
    elif isinstance(v, str):
        out.append(_jcs_string(v))
    elif isinstance(v, list):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _jcs(item, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            out.append(_jcs_string(k))
            out.append(":")
            _jcs(v[k], out)
        out.append("}")
    else:
        raise JsonInputError("type not supported: %r" % type(v))


def jcs(value):
    """RFC 8785 serialization as UTF-8 bytes."""
    out = []
    _jcs(value, out)
    return "".join(out).encode("utf-8")


def manifest_signing_bytes(manifest):
    """JCS of the trustManifest object with the "signature" member removed."""
    m = {k: v for k, v in manifest.items() if k != "signature"}
    return jcs(m)


# ---------------------------------------------------------------- base64url

def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s):
    if not isinstance(s, str) or any(c in s for c in "=+/ \n"):
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- keys

def jwk_public_key(jwk):
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(b64u_dec(jwk["x"]), "big")
        y = int.from_bytes(b64u_dec(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
    raise ValueError("JWK type not supported")


def public_jwk(pub):
    if isinstance(pub, ec.EllipticCurvePublicKey):
        n = pub.public_numbers()
        return {"kty": "EC", "crv": "P-256",
                "x": b64u(n.x.to_bytes(32, "big")),
                "y": b64u(n.y.to_bytes(32, "big"))}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(serialization.Encoding.Raw,
                               serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
    raise ValueError("key type not supported")


def load_private_pem(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ---------------------------------------------------------------- ES256 JWS

def _es256_sign(priv, data):
    try:
        alg = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        der = priv.sign(data, alg)
    except (TypeError, UnsupportedAlgorithm):  # older cryptography: random k
        der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")  # raw r||s


def es256_verify(pub, data, raw_sig):
    if len(raw_sig) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw_sig[:32], "big"),
                               int.from_bytes(raw_sig[32:], "big"))
    try:
        pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def jws_sign(priv, kid, payload, variant):
    """Variant A: compact, detached payload (RFC 7515 Appendix F): h..s.
    Variant B: compact, embedded payload: h.p.s"""
    header = jcs({"alg": "ES256", "kid": kid})
    h = b64u(header)
    p = b64u(payload)
    sig = _es256_sign(priv, (h + "." + p).encode("ascii"))
    if variant == "A":
        return h + ".." + b64u(sig)
    if variant == "B":
        return h + "." + p + "." + b64u(sig)
    raise ValueError("variant must be A or B")


def jws_parse(token):
    """Return (header dict, header b64, payload b64 (may be empty),
    embedded payload bytes or None, sig)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWS compact serialization")
    hdr_b = b64u_dec(parts[0])
    header = load_json_strict(hdr_b)
    if not isinstance(header, dict):
        raise ValueError("protected header is not an object")
    payload = b64u_dec(parts[1]) if parts[1] else None
    return header, parts[0], parts[1], payload, b64u_dec(parts[2])


def sign_manifest(manifest, priv, kid, variant):
    """Return a copy of manifest with "signature" set."""
    m = {k: v for k, v in manifest.items() if k != "signature"}
    m["signature"] = jws_sign(priv, kid, manifest_signing_bytes(m), variant)
    return m


# ---------------------------------------------------------------- digests

DIGESTS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384,
           "sha512": hashlib.sha512}


def digest_string(data, alg="sha256"):
    return alg + ":" + DIGESTS[alg](data).hexdigest()


def parse_digest(s):
    """Return (alg, hex) or raise ValueError when not <alg>:<hex>."""
    if not isinstance(s, str) or ":" not in s:
        raise ValueError("not <alg>:<hex>")
    alg, hx = s.split(":", 1)
    if not alg or not hx or any(c not in "0123456789abcdefABCDEF" for c in hx):
        raise ValueError("not <alg>:<hex>")
    return alg, hx


# ---------------------------------------------------------------- CBOR

class CborError(ValueError):
    pass


def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor_encode(v):
    """Deterministic encoding (RFC 8949 Section 4.2.1) of int, bytes, str,
    list, dict (keys sorted bytewise by their encoding), bool, None."""
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor_encode(i) for i in v)
    if isinstance(v, dict):
        items = sorted((cbor_encode(k), cbor_encode(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise CborError("type not supported: %r" % type(v))


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def _dec(b, i):
    if i >= len(b):
        raise CborError("truncated")
    ib = b[i]
    major, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        ln = 1 << (ai - 24)
        if i + ln > len(b):
            raise CborError("truncated")
        n = int.from_bytes(b[i:i + ln], "big")
        i += ln
    else:
        raise CborError("indefinite length or reserved value not supported")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(b):
            raise CborError("truncated")
        raw = b[i:i + n]
        return (raw if major == 2 else raw.decode("utf-8")), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = _dec(b, i)
            out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = _dec(b, i)
            if isinstance(k, (list, dict, Tag)):
                raise CborError("map key type not supported")
            if k in out:
                raise CborError("duplicate map key")
            x, i = _dec(b, i)
            out[k] = x
        return out, i
    if major == 6:
        x, i = _dec(b, i)
        return Tag(n, x), i
    if major == 7:
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
        raise CborError("simple value or float not supported")
    raise CborError("bad major type")


def cbor_decode(b):
    v, i = _dec(b, 0)
    if i != len(b):
        raise CborError("trailing bytes")
    return v


# ---------------------------------------------------------------- COSE_Sign1

def cose_sign1_parse(data):
    """Return (protected bstr, protected map, unprotected map, payload, sig)."""
    v = cbor_decode(data)
    if isinstance(v, Tag):
        if v.tag != 18:
            raise CborError("tag is not 18 (COSE_Sign1)")
        v = v.value
    if not (isinstance(v, list) and len(v) == 4):
        raise CborError("not a COSE_Sign1 array")
    prot_b, unprot, payload, sig = v
    if not isinstance(prot_b, bytes) or not isinstance(unprot, dict) \
            or not isinstance(payload, bytes) or not isinstance(sig, bytes):
        raise CborError("COSE_Sign1 member types")
    prot = cbor_decode(prot_b) if prot_b else {}
    if not isinstance(prot, dict):
        raise CborError("protected header is not a map")
    return prot_b, prot, unprot, payload, sig


def cose_sig_structure(prot_b, payload, external_aad=b""):
    return cbor_encode(["Signature1", prot_b, external_aad, payload])


def cose_sign1_ed25519(priv, prot_map, payload):
    prot_b = cbor_encode(prot_map)
    sig = priv.sign(cose_sig_structure(prot_b, payload))
    return cbor_encode_tag(18, [prot_b, {}, payload, sig])


def cbor_encode_tag(tag, value):
    return _head(6, tag) + cbor_encode(value)


def ed25519_verify(pub, data, sig):
    try:
        pub.verify(sig, data)
        return True
    except InvalidSignature:
        return False
