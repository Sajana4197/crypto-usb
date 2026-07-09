"""Exceptions raised by the crypto package."""

from __future__ import annotations


class CryptoError(Exception):
    """Base class for all cryptographic errors."""


class EncryptionError(CryptoError):
    """Raised when file/data encryption fails."""


class DecryptionError(CryptoError):
    """Raised when file/data decryption fails (e.g. tampered ciphertext, wrong key)."""


class KeyWrappingError(CryptoError):
    """Raised when wrapping (encrypting) a key fails."""


class KeyUnwrappingError(CryptoError):
    """Raised when unwrapping (decrypting) a key fails."""


class KeyDestroyedError(CryptoError):
    """Raised when an operation is attempted on key material that has already been destroyed."""
