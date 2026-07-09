"""Hybrid file encryption: AES-256-GCM for file content, with the FEK
wrapped by a `KeyWrapper` (RSA-OAEP today; an ECC-based wrapper can be
added later without changing this class — see `crypto.key_wrapper`).

The on-disk container produced here holds only ciphertext and the
wrapped key, never a plaintext key. It carries no metadata beyond what
AES-GCM itself needs to decrypt (nonce, wrap-algorithm tag). Metadata-
driven access control and USB packaging are implemented in a later
phase; `encrypt_bytes`/`decrypt_bytes` give that future phase a
disk-free interface to build on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.logger import get_logger
from crypto import aes_cipher
from crypto.exceptions import DecryptionError, EncryptionError
from crypto.key_manager import KeyManager
from crypto.key_wrapper import KeyWrapper

logger = get_logger(__name__)

_MAGIC = b"CUSB"
_FORMAT_VERSION = 1


@dataclass
class EncryptedContainer:
    """Serializable envelope: wrapped FEK + AES-GCM nonce + ciphertext."""

    wrap_algorithm: str
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes

    def serialize(self) -> bytes:
        algo_bytes = self.wrap_algorithm.encode("ascii")
        if len(algo_bytes) > 255:
            raise EncryptionError("wrap_algorithm name too long to serialize")
        if len(self.wrapped_key) > 65535:
            raise EncryptionError("wrapped_key too large to serialize")

        return b"".join(
            [
                _MAGIC,
                bytes([_FORMAT_VERSION]),
                bytes([len(algo_bytes)]),
                algo_bytes,
                len(self.wrapped_key).to_bytes(2, "big"),
                self.wrapped_key,
                self.nonce,
                self.ciphertext,
            ]
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedContainer":
        if data[:4] != _MAGIC:
            raise DecryptionError("Not a valid CUSB encrypted container (bad magic bytes)")
        version = data[4]
        if version != _FORMAT_VERSION:
            raise DecryptionError(f"Unsupported container version: {version}")

        offset = 5
        algo_len = data[offset]
        offset += 1
        wrap_algorithm = data[offset : offset + algo_len].decode("ascii")
        offset += algo_len

        wrapped_key_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        wrapped_key = data[offset : offset + wrapped_key_len]
        offset += wrapped_key_len

        nonce = data[offset : offset + aes_cipher.NONCE_SIZE_BYTES]
        offset += aes_cipher.NONCE_SIZE_BYTES

        ciphertext = data[offset:]

        return cls(
            wrap_algorithm=wrap_algorithm,
            wrapped_key=wrapped_key,
            nonce=nonce,
            ciphertext=ciphertext,
        )


class FileEncryptor:
    """Encrypts and decrypts files using hybrid AES-256-GCM + key-wrap encryption."""

    def __init__(self, key_manager: KeyManager | None = None) -> None:
        self._key_manager = key_manager or KeyManager()

    def encrypt_bytes(self, plaintext: bytes, wrapper: KeyWrapper) -> EncryptedContainer:
        fek = self._key_manager.generate_fek()
        try:
            nonce, ciphertext = aes_cipher.encrypt(plaintext, fek.material())
            wrapped_key = self._key_manager.wrap_key(fek, wrapper)
        finally:
            fek.destroy()

        return EncryptedContainer(
            wrap_algorithm=wrapper.algorithm,
            wrapped_key=wrapped_key,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decrypt_bytes(self, container: EncryptedContainer, wrapper: KeyWrapper) -> bytes:
        fek = self._key_manager.unwrap_key(container.wrapped_key, wrapper)
        try:
            return aes_cipher.decrypt(container.nonce, container.ciphertext, fek.material())
        finally:
            fek.destroy()

    def encrypt_file(self, input_path: Path, output_path: Path, wrapper: KeyWrapper) -> EncryptedContainer:
        input_path, output_path = Path(input_path), Path(output_path)
        container = self.encrypt_bytes(input_path.read_bytes(), wrapper)
        output_path.write_bytes(container.serialize())
        logger.info("Encrypted %s -> %s", input_path.name, output_path.name)
        return container

    def decrypt_file(self, input_path: Path, output_path: Path, wrapper: KeyWrapper) -> None:
        input_path, output_path = Path(input_path), Path(output_path)
        container = EncryptedContainer.deserialize(input_path.read_bytes())
        plaintext = self.decrypt_bytes(container, wrapper)
        output_path.write_bytes(plaintext)
        logger.info("Decrypted %s -> %s", input_path.name, output_path.name)
