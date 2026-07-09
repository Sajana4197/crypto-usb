"""AES-256-GCM file/data encryption.

Each call operates on a full plaintext buffer via AES-GCM's
authenticated encryption, which both encrypts and integrity-protects
the data in one pass. A fresh random 96-bit nonce is generated on
every call to `encrypt` — nonces must never be reused with the same
key, so no nonce is ever accepted as a caller-supplied parameter.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.exceptions import DecryptionError, EncryptionError

AES_KEY_SIZE_BYTES = 32  # AES-256
NONCE_SIZE_BYTES = 12  # 96-bit nonce, recommended size for GCM


def generate_fek() -> bytes:
    """Generate a fresh, random 256-bit File Encryption Key."""
    return os.urandom(AES_KEY_SIZE_BYTES)


def encrypt(
    plaintext: bytes, key: bytes, associated_data: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encrypt `plaintext` with AES-256-GCM.

    Returns (nonce, ciphertext_with_tag). The GCM authentication tag is
    appended to the ciphertext by the underlying implementation.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise EncryptionError(f"AES-256 key must be {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_SIZE_BYTES)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    except Exception as exc:
        raise EncryptionError(f"AES-GCM encryption failed: {exc}") from exc
    return nonce, ciphertext


def decrypt(
    nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes | None = None
) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises DecryptionError on tampering or a wrong key."""
    if len(key) != AES_KEY_SIZE_BYTES:
        raise DecryptionError(f"AES-256 key must be {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE_BYTES:
        raise DecryptionError(f"Nonce must be {NONCE_SIZE_BYTES} bytes, got {len(nonce)}")

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError("Authentication failed: ciphertext or key is invalid/tampered") from exc
    except Exception as exc:
        raise DecryptionError(f"AES-GCM decryption failed: {exc}") from exc
