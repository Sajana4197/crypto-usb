"""Secure password hashing.

Uses scrypt — a memory-hard KDF — rather than a fast general-purpose
hash, so brute-forcing a stolen password digest is expensive even with
GPU/ASIC hardware. Each password gets a fresh random salt, and
verification compares digests in constant time to avoid leaking match
information through timing.
"""

from __future__ import annotations

import hmac
import os
import secrets
import string

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from security.exceptions import WeakPasswordError
from security.models import PasswordCredential

# scrypt cost parameters: N (CPU/memory cost, must be a power of 2), r
# (block size), p (parallelism). These values follow the widely used
# "interactive login" recommendation (~roughly tens of milliseconds per
# hash on typical hardware) while remaining memory-hard.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN_BYTES = 32
SALT_LEN_BYTES = 16

MIN_PASSWORD_LENGTH = 8

RECOVERY_CODE_LENGTH = 24
_RECOVERY_CODE_ALPHABET = string.ascii_uppercase + string.digits


def validate_password_strength(password: str) -> None:
    """Raise `WeakPasswordError` if `password` fails the minimum policy."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")


def hash_password(password: str) -> PasswordCredential:
    """Hash `password` under a fresh random salt. Raises `WeakPasswordError` first."""
    validate_password_strength(password)
    salt = os.urandom(SALT_LEN_BYTES)
    digest = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN_BYTES)
    key_wrap_salt = os.urandom(SALT_LEN_BYTES)
    return PasswordCredential(
        salt=salt,
        digest=digest,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        key_len=KEY_LEN_BYTES,
        key_wrap_salt=key_wrap_salt,
    )


def verify_password(password: str, credential: PasswordCredential) -> bool:
    """Constant-time check that `password` matches `credential`."""
    candidate = _derive(password, credential.salt, credential.n, credential.r, credential.p, credential.key_len)
    return hmac.compare_digest(candidate, credential.digest)


def _derive(password: str, salt: bytes, n: int, r: int, p: int, key_len: int) -> bytes:
    kdf = Scrypt(salt=salt, length=key_len, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Derive the vault key that wraps the app's metadata/tracking
    protection keys, from `password` and its dedicated `key_wrap_salt` —
    same scrypt cost parameters as `hash_password`, but a separate salt so
    the vault key is cryptographically independent from the stored
    password-verification digest.
    """
    return _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN_BYTES)


def derive_vault_key_from_bytes(secret: bytes, salt: bytes) -> bytes:
    """Derive the vault key for private-key accounts, from `secret` (e.g.
    the private key PEM plus passphrase) and its dedicated `key_wrap_salt`.
    Same scrypt cost parameters as `derive_vault_key`, but takes bytes
    directly since private key material is not a UTF-8 string.
    """
    kdf = Scrypt(salt=salt, length=KEY_LEN_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(secret)


def derive_recovery_key(recovery_code: str, salt: bytes) -> bytes:
    """Derive the key that unlocks the Vault Master Key's recovery slot
    (see `app.protection_keys`) from a plaintext recovery code and its
    dedicated wrap salt (stored as `key_wrap_salt` on the recovery
    code's own `PasswordCredential`). Same scrypt cost parameters as
    `derive_vault_key`, but keyed off the recovery code instead of the
    password, so a recovery-code reset can unlock the same underlying
    protection keys a password-derived vault key would.
    """
    return _derive(recovery_code, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN_BYTES)


def generate_recovery_code() -> str:
    """A fresh random recovery code, e.g. for showing once at registration."""
    return "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(RECOVERY_CODE_LENGTH))


def hash_recovery_code(recovery_code: str) -> PasswordCredential:
    """Hash `recovery_code` under a fresh random salt, using the same scrypt
    scheme as `hash_password` — the plaintext is never stored. Also
    generates a `key_wrap_salt` (unused for verification, mirroring
    `hash_password`'s) for `derive_recovery_key` to use as the recovery
    slot's independent KDF salt.
    """
    salt = os.urandom(SALT_LEN_BYTES)
    digest = _derive(recovery_code, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN_BYTES)
    key_wrap_salt = os.urandom(SALT_LEN_BYTES)
    return PasswordCredential(
        salt=salt, digest=digest, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, key_len=KEY_LEN_BYTES,
        key_wrap_salt=key_wrap_salt,
    )


def verify_recovery_code(recovery_code: str, credential: PasswordCredential) -> bool:
    """Constant-time check that `recovery_code` matches `credential`."""
    candidate = _derive(recovery_code, credential.salt, credential.n, credential.r, credential.p, credential.key_len)
    return hmac.compare_digest(candidate, credential.digest)
