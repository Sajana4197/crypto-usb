"""HMAC-SHA256 generation and verification.

Used to protect data (such as encrypted metadata) against tampering
independently of any AEAD tag already provided by the encryption
layer — a distinct key and a distinct check, so compromising one does
not automatically defeat the other.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

HMAC_KEY_SIZE_BYTES = 32


def generate_hmac_key() -> bytes:
    """Generate a fresh, random 256-bit HMAC key."""
    return os.urandom(HMAC_KEY_SIZE_BYTES)


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute an HMAC-SHA256 tag over `data`."""
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time verification of an HMAC-SHA256 tag."""
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except InvalidSignature:
        return False
