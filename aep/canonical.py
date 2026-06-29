"""Canonical encoding + hashing.

Everything that gets signed or hash-chained is first reduced to a single deterministic
byte string: JSON with sorted keys, tight separators, UTF-8. This is the one place the
"exact bytes authorisation is bound to" is defined, so signatures are reproducible and a
verifier can recompute the same digest the signer did.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic canonical JSON encoding (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """sha256 over the canonical encoding of obj."""
    return sha256_hex(canonical_bytes(obj))
