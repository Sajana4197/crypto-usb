"""Key-wrapping interface.

`KeyWrapper` is the extension point for wrapping (encrypting) and
unwrapping (decrypting) a File Encryption Key under an asymmetric key
pair. `RSAOAEPKeyWrapper` is the only asymmetric implementation today;
adding ECC (e.g. an ECIES/ECDH-based wrapper) later means writing a new
class that implements this same interface — `KeyManager` and
`FileEncryptor` consume `KeyWrapper` generically and never need to
change.

`DeviceBoundKeyWrapper` is a second implementation, but a *decorator*
rather than a replacement: it wraps another `KeyWrapper` and adds an
outer AES-256-GCM layer keyed by a device-derived key (see
`crypto.key_manager.derive_device_binding_key`), used whenever a file is
bound to its USB device with no machine binding (`bind_device=True`,
`metadata.models.MachineBindingMode.NONE` — see
`usb.secure_storage_service`) so a wrong device doesn't just fail
`validation.device_binding_validator`'s policy check — it derives the
wrong key and unwrapping fails outright, the same way a wrong RSA
private key already does.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from crypto import aes_cipher
from crypto.exceptions import DecryptionError, EncryptionError, KeyUnwrappingError, KeyWrappingError


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
        `ui.pages.encryption_page.EncryptionPage`) can later export it for the
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


class DeviceBoundKeyWrapper(KeyWrapper):
    """Adds an outer AES-256-GCM wrap layer over another `KeyWrapper`,
    keyed by a device-derived key. `wrap` encrypts whatever `inner` just
    wrapped; `unwrap` must decrypt that outer layer with the *same*
    `device_key` before `inner` ever sees its own wrapped bytes again —
    a different `device_key` (i.e. a different device) fails the AES-GCM
    authentication tag outright, never reaching `inner.unwrap` at all.
    """

    def __init__(self, inner: KeyWrapper, device_key: bytes) -> None:
        self._inner = inner
        self._device_key = device_key
        self.algorithm = f"{inner.algorithm}+DEVICE-BOUND-AES-GCM"

    def wrap(self, key_material: bytes) -> bytes:
        inner_wrapped = self._inner.wrap(key_material)
        try:
            nonce, ciphertext = aes_cipher.encrypt(inner_wrapped, self._device_key)
        except EncryptionError as exc:
            raise KeyWrappingError(f"Device-bound key wrapping failed: {exc}") from exc
        return nonce + ciphertext

    def unwrap(self, wrapped_key: bytes) -> bytes:
        nonce = wrapped_key[: aes_cipher.NONCE_SIZE_BYTES]
        ciphertext = wrapped_key[aes_cipher.NONCE_SIZE_BYTES :]
        try:
            inner_wrapped = aes_cipher.decrypt(nonce, ciphertext, self._device_key)
        except DecryptionError as exc:
            raise KeyUnwrappingError(f"Device-bound key unwrapping failed: {exc}") from exc
        return self._inner.unwrap(inner_wrapped)
