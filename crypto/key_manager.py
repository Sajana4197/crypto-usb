"""Key Management Module.

Central authority for the cryptographic key lifecycle: generating File
Encryption Keys (FEKs) and RSA key pairs, wrapping/unwrapping FEKs
through a `KeyWrapper`, and securely destroying key material once it
is no longer needed. No key material is ever written to a log — only
algorithm names and object identifiers are logged.

`derive_device_binding_key` below derives a symmetric key from a
DEVICE_ONLY file's device fingerprint (`validation.usb_identifier`),
used by `crypto.key_wrapper.DeviceBoundKeyWrapper` to add an outer
device-bound wrap layer around the FEK for that binding mode. It
mirrors the labeled-HKDF pattern `metadata.protection`'s
`derive_protection_keys_from_key_material` already establishes (a
distinct `info` label per derived key, so different keys derived from
related input material stay cryptographically independent) — but uses
full HKDF (extract-then-expand), not `HKDFExpand` alone, since a device
fingerprint is raw identifying data, not already a uniform, high-entropy
secret the way that function's scrypt-stretched master secret is.
"""

from __future__ import annotations

from enum import Enum, auto

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.logger import get_logger
from crypto import aes_cipher, rsa_keypair
from crypto.exceptions import KeyDestroyedError
from crypto.key_wrapper import KeyWrapper
from crypto.rsa_keypair import RSAKeyPair
from crypto.secure_bytes import SecureBytes

logger = get_logger(__name__)

# Distinct HKDF info label, matching the convention `metadata.protection`
# uses for its own derived keys — keeps this derivation cryptographically
# independent of any other key ever expanded from related input material.
_HKDF_INFO_DEVICE_BINDING_KEY = b"crypto-usb:device-binding:wrap-key"

DEVICE_BINDING_KEY_SIZE_BYTES = aes_cipher.AES_KEY_SIZE_BYTES


def derive_device_binding_key(device_fingerprint: bytes) -> bytes:
    """Derive a device-bound AES-256 key from `device_fingerprint`
    (see `validation.usb_identifier.device_fingerprint_material`).

    Deterministic: the same fingerprint bytes always derive the same
    key, which is the entire point — encrypting on the enrolled device
    and later decrypting on the presented device must derive identical
    keys if and only if the two devices are, cryptographically, the
    same one.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=DEVICE_BINDING_KEY_SIZE_BYTES,
        salt=None,
        info=_HKDF_INFO_DEVICE_BINDING_KEY,
    ).derive(device_fingerprint)


class KeyState(Enum):
    ACTIVE = auto()
    DESTROYED = auto()


class ManagedKey:
    """A File Encryption Key tracked through its lifecycle: active -> destroyed."""

    def __init__(self, key_material: bytes) -> None:
        self._secure = SecureBytes(key_material)
        self._state = KeyState.ACTIVE

    @property
    def state(self) -> KeyState:
        return self._state

    def material(self) -> bytes:
        if self._state is KeyState.DESTROYED:
            raise KeyDestroyedError("Cannot access destroyed key material")
        return bytes(self._secure)

    def destroy(self) -> None:
        if self._state is KeyState.ACTIVE:
            self._secure.destroy()
            self._state = KeyState.DESTROYED
            logger.info("Key material destroyed (key=%s)", id(self))

    def __enter__(self) -> "ManagedKey":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()


class KeyManager:
    """Generates, wraps, unwraps, and destroys cryptographic keys."""

    def generate_fek(self) -> ManagedKey:
        """Generate a new AES-256 File Encryption Key."""
        key = ManagedKey(aes_cipher.generate_fek())
        logger.info("Generated new FEK (key=%s)", id(key))
        return key

    def generate_rsa_keypair(self) -> RSAKeyPair:
        """Generate a new RSA-4096 key pair for wrapping FEKs."""
        keypair = rsa_keypair.generate_rsa_keypair()
        logger.info("Generated new %s key pair", keypair.algorithm)
        return keypair

    def wrap_key(self, fek: ManagedKey, wrapper: KeyWrapper) -> bytes:
        """Wrap a FEK's material using the given `KeyWrapper`."""
        wrapped = wrapper.wrap(fek.material())
        logger.info("Wrapped FEK using %s (key=%s)", wrapper.algorithm, id(fek))
        return wrapped

    def unwrap_key(self, wrapped: bytes, wrapper: KeyWrapper) -> ManagedKey:
        """Unwrap a previously wrapped FEK, returning it as a managed key."""
        material = wrapper.unwrap(wrapped)
        key = ManagedKey(material)
        logger.info("Unwrapped FEK using %s (key=%s)", wrapper.algorithm, id(key))
        return key

    def destroy_key(self, key: ManagedKey) -> None:
        """Securely destroy a key's in-memory material."""
        key.destroy()
