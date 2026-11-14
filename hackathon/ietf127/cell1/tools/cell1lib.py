# SPDX-License-Identifier: BSD-3-Clause
"""Small helpers for IETF 127 Hackathon cell 1 (Tyche Institute).

Built-in Python 3 modules plus the "cryptography" package. Nothing else.

What is here:
  * a tiny CBOR encoder that writes RFC 8949 Section 4.2.1 core deterministic
    encoding, and a strict CBOR decoder (rejects duplicate map keys,
    trailing bytes, reserved additional information);
  * a tiny RFC 8785 (JCS) writer for objects, arrays, strings, integers,
    true, false and null (it refuses floating-point numbers);
  * a strict JSON reader (rejects duplicate member names, NaN, Infinity,
    lone surrogates);
  * COSE_Sign1 (RFC 9052) signing and signature checking with Ed25519.

The CBOR encoder and decoder are adapted from lib/python/cose_det_enc.py in the
cose-deterministic-encodings repository (Revised BSD License). The copyright notice and the
licence text are in the file LICENSE in this directory. cbor2 is not needed.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

# --------------------------------------------------------------------------
# CBOR
# --------------------------------------------------------------------------


class CBORError(ValueError):
    pass


class Tag:
    def __init__(self, number: int, value: Any):
        self.number = number
        self.value = value

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Tag) and other.number == self.number and other.value == self.value

    def __repr__(self) -> str:
        return f"Tag({self.number}, {self.value!r})"


class Simple:
    def __init__(self, value: int):
        self.value = value

    def __repr__(self) -> str:
        return f"Simple({self.value})"


class CMap(list):
    """A decoded CBOR map as (key, value) pairs in wire order.

    A list, so that keys Python would merge (1, 1.0, True) stay apart.
    """

    def get(self, key: Any, default: Any = None) -> Any:
        for k, v in self:
            if type(k) is type(key) and k == key:
                return v
        return default

    def has(self, key: Any) -> bool:
        return any(type(k) is type(key) and k == key for k, _ in self)

    def labels(self) -> list:
        return [k for k, _ in self]


def _head(major: int, arg: int) -> bytes:
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg < 0x100:
        return bytes([mt | 24, arg])
    if arg < 0x10000:
        return bytes([mt | 25]) + struct.pack(">H", arg)
    if arg < 0x100000000:
        return bytes([mt | 26]) + struct.pack(">I", arg)
    if arg < 0x10000000000000000:
        return bytes([mt | 27]) + struct.pack(">Q", arg)
    raise CBORError("integer does not fit in 64 bits")


def cbor_encode(value: Any) -> bytes:
    """Encode under RFC 8949 Section 4.2.1 (core deterministic encoding).

    Shortest heads, definite lengths, map keys sorted by the bytewise
    lexicographic order of their encoded form. Floating-point values are
    refused: cell 1 carries none.
    """
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, float):
        raise CBORError("floating-point values are outside cell 1")
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (dict, CMap)):
        pairs = value.items() if isinstance(value, dict) else value
        enc = sorted((cbor_encode(k), cbor_encode(v)) for k, v in pairs)
        for (a, _), (b, _) in zip(enc, enc[1:]):
            if a == b:
                raise CBORError("duplicate map key")
        return _head(5, len(enc)) + b"".join(k + v for k, v in enc)
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, Tag):
        return _head(6, value.number) + cbor_encode(value.value)
    raise CBORError(f"cannot encode {type(value).__name__}")


def cbor_decode(data: bytes) -> Any:
    """Decode exactly one well-formed, valid CBOR data item.

    Accepts any serialization RFC 8949 allows (COSE does not require
    deterministic encoding). Rejects duplicate map keys and trailing bytes.
    """
    value, end = _dec(data, 0, 0)
    if end != len(data):
        raise CBORError("trailing bytes after the data item")
    return value


def _take(data: bytes, pos: int, n: int) -> bytes:
    if pos + n > len(data):
        raise CBORError("truncated data item")
    return data[pos:pos + n]


def _dec(data: bytes, pos: int, depth: int) -> tuple[Any, int]:
    if depth > 32:
        raise CBORError("nesting too deep")
    ib = _take(data, pos, 1)[0]
    pos += 1
    major, ai = ib >> 5, ib & 0x1F
    if major == 7 and ai in (25, 26, 27):
        n, fmt = {25: (2, ">e"), 26: (4, ">f"), 27: (8, ">d")}[ai]
        return struct.unpack(fmt, _take(data, pos, n))[0], pos + n
    if ai < 24:
        arg = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        arg = int.from_bytes(_take(data, pos, n), "big")
        pos += n
    elif ai == 31 and major in (2, 3, 4, 5):
        arg = None
    else:
        raise CBORError("reserved or invalid additional information")
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg is None:
            parts = []
            while _take(data, pos, 1)[0] != 0xFF:
                if data[pos] >> 5 != major or data[pos] & 0x1F == 31:
                    raise CBORError("bad chunk in indefinite-length string")
                part, pos = _dec(data, pos, depth + 1)
                parts.append(part)
            pos += 1
            return (b"".join(parts) if major == 2 else "".join(parts)), pos
        raw = _take(data, pos, arg)
        pos += arg
        if major == 2:
            return bytes(raw), pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError as exc:
            raise CBORError("invalid UTF-8 in text string") from exc
    if major in (4, 5):
        out: Any = CMap() if major == 5 else []
        count = 0
        while (arg is None and _take(data, pos, 1)[0] != 0xFF) or (arg is not None and count < arg):
            item, pos = _dec(data, pos, depth + 1)
            if major == 5:
                val, pos = _dec(data, pos, depth + 1)
                item = (item, val)
            out.append(item)
            count += 1
        if arg is None:
            pos += 1
        if major == 5:
            keys = [_key_identity(k) for k, _ in out]
            if len(set(keys)) != len(keys):
                raise CBORError("duplicate map key")
        return out, pos
    if major == 6:
        inner, pos = _dec(data, pos, depth + 1)
        return Tag(arg, inner), pos
    if ai == 24 and arg < 32:
        raise CBORError("simple value below 32 in two bytes")
    if arg in (20, 21, 22):
        return (False, True, None)[arg - 20], pos
    return Simple(arg), pos


def _key_identity(key: Any) -> Any:
    try:
        return ("enc", cbor_encode(key))
    except CBORError:
        return ("repr", type(key).__name__, repr(key))


# --------------------------------------------------------------------------
# JSON: strict reading, JCS writing, JSON-to-CBOR data model
# --------------------------------------------------------------------------


class HeldValueError(ValueError):
    """The held JSON text is not input that the construction accepts."""


class HeldValueNotImplemented(ValueError):
    """The held JSON text uses a feature these tools do not implement."""


MAX_SAFE = 2 ** 53 - 1


def _pairs_no_dup(pairs: list) -> dict:
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise HeldValueError(f"duplicate member name {k!r}")
        seen.add(k)
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise HeldValueError(f"{name} is not JSON")


def _float_seen(text: str) -> Any:
    raise HeldValueNotImplemented(f"number {text} is not an integer; cell 1 tools do not serialize floats")


def _check_strings(v: Any) -> None:
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise HeldValueError("string holds a lone surrogate") from exc
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_strings(k)
            _check_strings(x)
    elif isinstance(v, list):
        for x in v:
            _check_strings(x)
    elif isinstance(v, bool) or v is None:
        pass
    elif isinstance(v, int):
        if abs(v) > MAX_SAFE:
            raise HeldValueNotImplemented("integer beyond 2^53 - 1 in size")


def read_json_strict(raw: bytes) -> Any:
    """Parse JSON text with the rules RFC 8785 inherits from I-JSON (RFC 7493)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HeldValueError("JSON text is not UTF-8") from exc
    if text.startswith("﻿"):
        raise HeldValueError("byte order mark")
    try:
        value = json.loads(text, object_pairs_hook=_pairs_no_dup,
                           parse_constant=_reject_constant, parse_float=_float_seen)
    except json.JSONDecodeError as exc:
        raise HeldValueError(f"not JSON: {exc}") from exc
    _check_strings(value)
    return value


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x08:
            out.append("\\b")
        elif o == 0x09:
            out.append("\\t")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0C:
            out.append("\\f")
        elif o == 0x0D:
            out.append("\\r")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value: Any) -> bytes:
    """RFC 8785 bytes for values without floating-point numbers."""
    def w(v: Any) -> str:
        if v is True:
            return "true"
        if v is False:
            return "false"
        if v is None:
            return "null"
        if isinstance(v, int):
            if abs(v) > MAX_SAFE:
                raise HeldValueNotImplemented("integer beyond 2^53 - 1 in size")
            return str(v)
        if isinstance(v, float):
            raise HeldValueNotImplemented("floating-point number")
        if isinstance(v, str):
            return _jcs_string(v)
        if isinstance(v, list):
            return "[" + ",".join(w(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v, key=lambda k: k.encode("utf-16-be"))  # UTF-16 code units
            return "{" + ",".join(_jcs_string(k) + ":" + w(v[k]) for k in keys) + "}"
        raise HeldValueError(f"{type(v).__name__} is not JSON")
    return w(value).encode("utf-8")


def json_to_cbor_model(value: Any) -> Any:
    """Cell 1 mapping: JSON object -> CBOR map with text keys, string -> text
    string, integer -> major type 0 or 1, array -> array, true/false/null ->
    simple values 21/20/22. Python values already have this shape."""
    return value


# --------------------------------------------------------------------------
# COSE_Sign1 with Ed25519
# --------------------------------------------------------------------------

ALG_EDDSA = -8
LABEL_ALG, LABEL_CRIT, LABEL_CTYPE, LABEL_KID, LABEL_CWT = 1, 2, 3, 4, 15
LABEL_HASH_ALG, LABEL_PREIMAGE_CT, LABEL_LOCATION = 258, 259, 260
LABEL_CDE = 271          # CDE -00 suggested value for TBD_1; not assigned; test-only
LABEL_CPB_REFS = -65537  # test-only private-use label, as in the CPB repository
SHA256 = -16


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 9052 Section 4.4: ["Signature1", protected, external_aad, payload]."""
    return cbor_encode(["Signature1", protected, external_aad, payload])


def sign1(protected_map: dict, payload: bytes, private_key: Any) -> bytes:
    protected = cbor_encode(protected_map)
    signature = private_key.sign(sig_structure(protected, payload))
    return cbor_encode(Tag(18, [protected, {}, payload, signature]))


class CoseRecord:
    def __init__(self, protected_bytes: bytes, protected: CMap, unprotected: CMap,
                 payload: bytes, signature: bytes):
        self.protected_bytes = protected_bytes
        self.protected = protected
        self.unprotected = unprotected
        self.payload = payload
        self.signature = signature


def parse_sign1(data: bytes) -> CoseRecord:
    outer = cbor_decode(data)
    if not isinstance(outer, Tag) or outer.number != 18:
        raise CBORError("not a tagged COSE_Sign1 (tag 18)")
    arr = outer.value
    if not isinstance(arr, list) or len(arr) != 4:
        raise CBORError("COSE_Sign1 is not a 4-element array")
    pb, unp, payload, sig = arr
    if not isinstance(pb, bytes) or not isinstance(unp, CMap) or not isinstance(sig, bytes):
        raise CBORError("COSE_Sign1 element types are wrong")
    if not isinstance(payload, bytes):
        raise CBORError("payload is detached or not a byte string")
    prot = cbor_decode(pb) if pb else CMap()
    if not isinstance(prot, CMap):
        raise CBORError("protected header is not a map")
    return CoseRecord(pb, prot, unp, payload, sig)


def check_signature(rec: CoseRecord, public_key: Any) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(rec.signature, sig_structure(rec.protected_bytes, rec.payload))
        return True
    except InvalidSignature:
        return False


def load_public_key(path: str) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    data = open(path, "rb").read()
    if b"BEGIN" in data:
        key = load_pem_public_key(data)
    else:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(data.decode().strip()))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def load_private_key(path: str) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(open(path, "rb").read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    return key


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
