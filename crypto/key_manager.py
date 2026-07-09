"""Key Management Module.

Central authority for the cryptographic key lifecycle: generating File
Encryption Keys (FEKs) and RSA key pairs, wrapping/unwrapping FEKs
through a `KeyWrapper`, and securely destroying key material once it
is no longer needed. No key material is ever written to a log — only
algorithm names and object identifiers are logged.
"""

from __future__ import annotations

from enum import Enum, auto

from core.logger import get_logger
from crypto import aes_cipher, rsa_keypair
from crypto.exceptions import KeyDestroyedError
from crypto.key_wrapper import KeyWrapper
from crypto.rsa_keypair import RSAKeyPair
from crypto.secure_bytes import SecureBytes

logger = get_logger(__name__)


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
