"""Key-wrapping interface.

`KeyWrapper` is the extension point for wrapping (encrypting) and
unwrapping (decrypting) a File Encryption Key under an asymmetric key
pair. `RSAOAEPKeyWrapper` is the only implementation today; adding
ECC (e.g. an ECIES/ECDH-based wrapper) later means writing a new
class that implements this same interface — `KeyManager` and
`FileEncryptor` consume `KeyWrapper` generically and never need to
change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto.exceptions import KeyUnwrappingError, KeyWrappingError


class KeyWrapper(ABC):
    """Wraps and unwraps a symmetric key under an asymmetric key pair."""

    algorithm: str

    @abstractmethod
    def wrap(self, key_material: bytes) -> bytes:
        """Encrypt `key_material` (e.g. an AES FEK) under the public key."""

    @abstractmethod
    def unwrap(self, wrapped_key: bytes) -> bytes:
        """Decrypt a previously wrapped key. Requires the private key."""


class RSAOAEPKeyWrapper(KeyWrapper):
    """Wraps keys using RSA-OAEP with SHA-256 (MGF1)."""

    algorithm = "RSA-OAEP"

    def __init__(self, public_key: RSAPublicKey, private_key: RSAPrivateKey | None = None) -> None:
        self._public_key = public_key
        self._private_key = private_key

    @property
    def private_key(self) -> RSAPrivateKey | None:
        """The private key this wrapper unwraps with, if any — exposed so a
        caller that generated this wrapper's keypair (e.g.
        `ui.pages.device_page.DevicePage`) can later export it for the
        user to keep, without reaching into a private attribute."""
        return self._private_key

    @staticmethod
    def _oaep_padding() -> padding.OAEP:
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def wrap(self, key_material: bytes) -> bytes:
        try:
            return self._public_key.encrypt(key_material, self._oaep_padding())
        except Exception as exc:
            raise KeyWrappingError(f"RSA-OAEP key wrapping failed: {exc}") from exc

    def unwrap(self, wrapped_key: bytes) -> bytes:
        if self._private_key is None:
            raise KeyUnwrappingError("No private key available to unwrap with")
        try:
            return self._private_key.decrypt(wrapped_key, self._oaep_padding())
        except KeyUnwrappingError:
            raise
        except Exception as exc:
            raise KeyUnwrappingError(f"RSA-OAEP key unwrapping failed: {exc}") from exc
