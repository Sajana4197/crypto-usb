"""RSA-4096 key pair generation, serialization, and loading.

Private keys are always serialized encrypted-at-rest — never in
plaintext — using the `cryptography` library's PBKDF-based
`BestAvailableEncryption`. Public keys are serialized as plaintext
PEM, which is expected: public keys are not secret.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto.exceptions import CryptoError

RSA_KEY_SIZE_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537


@dataclass
class RSAKeyPair:
    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    algorithm: str = "RSA-4096"


def generate_rsa_keypair() -> RSAKeyPair:
    """Generate a fresh RSA-4096 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE_BITS,
    )
    return RSAKeyPair(private_key=private_key, public_key=private_key.public_key())


def serialize_private_key(private_key: RSAPrivateKey, passphrase: bytes) -> bytes:
    """Serialize a private key to PEM, encrypted at rest with `passphrase`."""
    if not passphrase:
        raise CryptoError("A non-empty passphrase is required to serialize a private key")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to plaintext PEM (public keys are not secret)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes | bytearray, passphrase: bytes | bytearray) -> RSAPrivateKey:
    """Load a private key from encrypted PEM. Raises CryptoError on bad data/passphrase."""
    try:
        return serialization.load_pem_private_key(pem_data, password=passphrase)
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"Failed to load private key: {exc}") from exc


def load_public_key(pem_data: bytes) -> RSAPublicKey:
    """Load a public key from plaintext PEM."""
    try:
        return serialization.load_pem_public_key(pem_data)
    except ValueError as exc:
        raise CryptoError(f"Failed to load public key: {exc}") from exc
