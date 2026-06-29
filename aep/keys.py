"""Ed25519 key handling for the sandbox.

Trust anchors (issuer, principal, agent) hold *secret* private keys. An attacker who
clones this repo gets only the PUBLIC keys (keys/*.pub committed) and the public trust
store (keys/trusted_issuers.json). The private keys live under keys/private/ which is
git-ignored — that is the whole point: you are meant to break the scheme WITHOUT them.

`make keys` (scripts/init_keys.py) generates a fresh set locally if you want to mint your
own valid packages to attack.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes


def generate_private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def pub_hex(sk: Ed25519PrivateKey) -> str:
    return _pub_raw(sk).hex()


def _pub_raw(sk: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def priv_hex(sk: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.hex()


def load_private_hex(h: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(h.strip()))


def pub_from_hex(h: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(h.strip()))


def sign(sk: Ed25519PrivateKey, payload) -> str:
    """Sign the canonical encoding of `payload`, return hex signature."""
    return sk.sign(canonical_bytes(payload)).hex()


def verify(pub_h: str, payload, sig_hex: str) -> bool:
    """True iff `sig_hex` is a valid signature over canonical(payload) by pub_h."""
    try:
        pub_from_hex(pub_h).verify(bytes.fromhex(sig_hex), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()
