"""SHA-256 integrity hashing for encrypted file containers."""

from __future__ import annotations

import hashlib


def compute_integrity_hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of `data`."""
    return hashlib.sha256(data).hexdigest()


def verify_integrity_hash(data: bytes, expected_hash: str) -> bool:
    """Check that `data` hashes to `expected_hash` (case-insensitive hex)."""
    return compute_integrity_hash(data) == expected_hash.lower()
