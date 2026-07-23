"""Secure container format for USB storage.

Bundles everything the Secure Storage Layer must persist for a
protected file — the AES-256-GCM encrypted file and its wrapped FEK
(`crypto.file_encryptor.EncryptedContainer`), its local encrypted+HMAC
metadata record (`metadata.protection.ProtectedMetadata`), and
optionally a portable metadata envelope
(`metadata.portable_envelope.PortableMetadataEnvelope`, protected
under keys derived from the file-wrapping private key + a passphrase
rather than any local secret — see that module) — into one
self-contained binary envelope (`.cusc`), plus an outer SHA-256 hash
covering the whole payload so tampering, truncation, or a corrupted
write can be detected without needing any key material at all.
Nothing in this module ever holds or serializes plaintext.

The portable section is what previously shipped as a separate
`.cumeta` sibling file next to the `.cusc` container; embedding it
here means one file on the USB device fully represents one protected
file, with nothing else needed to locate or keep track of. A version-1
container (written before this section existed) has no portable
section at all and still deserializes fine, with `portable_metadata`
coming back `None` — old `.cusc` files already on a device keep working
unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from core.logger import get_logger
from crypto import aes_cipher
from crypto.exceptions import DecryptionError, KeyUnwrappingError
from crypto.file_encryptor import EncryptedContainer
from crypto.key_manager import KeyManager
from crypto.key_wrapper import KeyWrapper
from metadata.exceptions import MetadataTamperError, MetadataValidationError
from metadata.portable_envelope import PortableMetadataEnvelope
from metadata.protection import MetadataProtector, ProtectedMetadata
from usb.exceptions import ContainerVerificationError

logger = get_logger(__name__)

MAGIC = b"CUSC"  # CryptoUSB Secure Container
FORMAT_VERSION = 2
_MIN_FORMAT_VERSION_WITH_PORTABLE_SECTION = 2
CONTAINER_EXTENSION = ".cusc"
_OUTER_HASH_SIZE_BYTES = 32


@dataclass
class SecureContainer:
    """The full on-USB payload for one protected file: never plaintext."""

    file_id: str
    file_container: EncryptedContainer
    protected_metadata: ProtectedMetadata
    portable_metadata: Optional[PortableMetadataEnvelope] = None

    def serialize(self) -> bytes:
        """Serialize to the `.cusc` binary format, header through outer hash."""
        file_id_bytes = self.file_id.encode("utf-8")
        if len(file_id_bytes) > 255:
            raise ContainerVerificationError("file_id too long to serialize")

        file_blob = self.file_container.serialize()
        meta_blob = _serialize_protected_metadata(self.protected_metadata)
        portable_blob = self.portable_metadata.serialize() if self.portable_metadata is not None else b""

        body = b"".join(
            [
                MAGIC,
                bytes([FORMAT_VERSION]),
                bytes([len(file_id_bytes)]),
                file_id_bytes,
                len(file_blob).to_bytes(8, "big"),
                file_blob,
                len(meta_blob).to_bytes(8, "big"),
                meta_blob,
                len(portable_blob).to_bytes(8, "big"),
                portable_blob,
            ]
        )
        checksum = hashlib.sha256(body).digest()
        return body + checksum

    @classmethod
    def deserialize(cls, data: bytes) -> "SecureContainer":
        """Parse a `.cusc` payload, verifying the outer SHA-256 hash first."""
        min_len = len(MAGIC) + 1 + 1 + _OUTER_HASH_SIZE_BYTES
        if len(data) < min_len:
            raise ContainerVerificationError("Container data is too short to be valid")

        body, checksum = data[:-_OUTER_HASH_SIZE_BYTES], data[-_OUTER_HASH_SIZE_BYTES:]
        if hashlib.sha256(body).digest() != checksum:
            raise ContainerVerificationError(
                "Container integrity check failed: outer SHA-256 hash mismatch "
                "(the file is corrupt, truncated, or has been tampered with)"
            )

        if body[:4] != MAGIC:
            raise ContainerVerificationError("Not a valid CUSC secure container (bad magic bytes)")
        version = body[4]
        if version < 1 or version > FORMAT_VERSION:
            raise ContainerVerificationError(f"Unsupported container version: {version}")

        offset = 5
        file_id_len = body[offset]
        offset += 1
        file_id = body[offset : offset + file_id_len].decode("utf-8")
        offset += file_id_len

        file_blob_len = int.from_bytes(body[offset : offset + 8], "big")
        offset += 8
        file_blob = body[offset : offset + file_blob_len]
        offset += file_blob_len

        meta_blob_len = int.from_bytes(body[offset : offset + 8], "big")
        offset += 8
        meta_blob = body[offset : offset + meta_blob_len]
        offset += meta_blob_len

        portable_metadata = None
        if version >= _MIN_FORMAT_VERSION_WITH_PORTABLE_SECTION:
            portable_blob_len = int.from_bytes(body[offset : offset + 8], "big")
            offset += 8
            portable_blob = body[offset : offset + portable_blob_len]
            if portable_blob:
                try:
                    portable_metadata = PortableMetadataEnvelope.deserialize(portable_blob)
                except MetadataValidationError as exc:
                    raise ContainerVerificationError(f"Embedded portable metadata is invalid: {exc}") from exc

        try:
            file_container = EncryptedContainer.deserialize(file_blob)
        except DecryptionError as exc:
            raise ContainerVerificationError(f"Embedded file container is invalid: {exc}") from exc

        protected_metadata = _deserialize_protected_metadata(meta_blob, file_id)

        return cls(
            file_id=file_id,
            file_container=file_container,
            protected_metadata=protected_metadata,
            portable_metadata=portable_metadata,
        )


def _serialize_protected_metadata(protected: ProtectedMetadata) -> bytes:
    return b"".join(
        [
            protected.metadata_version.to_bytes(4, "big"),
            len(protected.nonce).to_bytes(2, "big"),
            protected.nonce,
            len(protected.hmac_tag).to_bytes(2, "big"),
            protected.hmac_tag,
            len(protected.ciphertext).to_bytes(8, "big"),
            protected.ciphertext,
        ]
    )


def _deserialize_protected_metadata(blob: bytes, file_id: str) -> ProtectedMetadata:
    offset = 0
    metadata_version = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    nonce_len = int.from_bytes(blob[offset : offset + 2], "big")
    offset += 2
    nonce = blob[offset : offset + nonce_len]
    offset += nonce_len
    hmac_len = int.from_bytes(blob[offset : offset + 2], "big")
    offset += 2
    hmac_tag = blob[offset : offset + hmac_len]
    offset += hmac_len
    ciphertext_len = int.from_bytes(blob[offset : offset + 8], "big")
    offset += 8
    ciphertext = blob[offset : offset + ciphertext_len]

    return ProtectedMetadata(
        file_id=file_id,
        metadata_version=metadata_version,
        nonce=nonce,
        ciphertext=ciphertext,
        hmac_tag=hmac_tag,
    )


def verify_container_deep(
    container: SecureContainer,
    key_manager: KeyManager,
    key_wrapper: KeyWrapper,
    metadata_protector: MetadataProtector,
) -> bool:
    """Fully verify a container by unwrapping its FEK, decrypting the file
    ciphertext, and unprotecting its metadata — entirely in memory.

    Plaintext is never returned, logged, or written anywhere: it exists
    only long enough for the AES-GCM authentication tag to be checked,
    then it is immediately overwritten with zeros. Raises
    `ContainerVerificationError` if any step fails.
    """
    try:
        fek = key_manager.unwrap_key(container.file_container.wrapped_key, key_wrapper)
    except KeyUnwrappingError as exc:
        raise ContainerVerificationError(f"Deep verification failed: could not unwrap key: {exc}") from exc

    try:
        with fek:
            plaintext = bytearray(
                aes_cipher.decrypt(
                    container.file_container.nonce,
                    container.file_container.ciphertext,
                    fek.material(),
                )
            )
    except DecryptionError as exc:
        raise ContainerVerificationError(
            f"Deep verification failed: file ciphertext did not decrypt/authenticate: {exc}"
        ) from exc

    for i in range(len(plaintext)):
        plaintext[i] = 0

    try:
        metadata_protector.unprotect(container.protected_metadata)
    except MetadataTamperError as exc:
        raise ContainerVerificationError(f"Deep verification failed: metadata tamper check failed: {exc}") from exc

    logger.info("Deep-verified secure container file_id=%s", container.file_id)
    return True
