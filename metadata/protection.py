"""Encrypted, HMAC-protected storage envelope for `FileMetadata` records.

Metadata is encrypted with AES-256-GCM (confidentiality plus its own
built-in authentication) and additionally protected by an independent
HMAC-SHA256 computed with a separate key (encrypt-then-MAC). The HMAC
is checked first, before any decryption is attempted, so tampering is
caught immediately and an attacker who compromises one key does not
automatically defeat the other check.

Persisting or deriving the encryption/HMAC keys from a user credential
is the responsibility of the future authentication module — callers
here must supply or generate keys explicitly.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from core.logger import get_logger
from crypto import aes_cipher
from crypto.exceptions import DecryptionError
from crypto.hmac_util import HMAC_KEY_SIZE_BYTES, compute_hmac, verify_hmac
from metadata.exceptions import MetadataTamperError
from metadata.models import FileMetadata

logger = get_logger(__name__)


@dataclass
class MetadataProtectionKeys:
    encryption_key: bytes
    hmac_key: bytes


def generate_protection_keys() -> MetadataProtectionKeys:
    """Generate a fresh metadata encryption key and HMAC key."""
    return MetadataProtectionKeys(
        encryption_key=aes_cipher.generate_fek(),
        hmac_key=os.urandom(HMAC_KEY_SIZE_BYTES),
    )


@dataclass
class ProtectedMetadata:
    """The on-disk envelope: everything except file_id/version is opaque."""

    file_id: str
    metadata_version: int
    nonce: bytes
    ciphertext: bytes
    hmac_tag: bytes


class MetadataProtector:
    """Encrypts/decrypts `FileMetadata` records and guards them with an HMAC."""

    def __init__(self, keys: MetadataProtectionKeys) -> None:
        self._keys = keys

    @staticmethod
    def _mac_input(file_id: str, metadata_version: int, nonce: bytes, ciphertext: bytes) -> bytes:
        return b"|".join(
            [
                file_id.encode("utf-8"),
                str(metadata_version).encode("ascii"),
                nonce,
                ciphertext,
            ]
        )

    def protect(self, metadata: FileMetadata) -> ProtectedMetadata:
        payload = json.dumps(metadata.to_dict()).encode("utf-8")
        nonce, ciphertext = aes_cipher.encrypt(payload, self._keys.encryption_key)
        mac_input = self._mac_input(metadata.file_id, metadata.metadata_version, nonce, ciphertext)
        hmac_tag = compute_hmac(self._keys.hmac_key, mac_input)

        logger.info("Protected metadata for file_id=%s", metadata.file_id)
        return ProtectedMetadata(
            file_id=metadata.file_id,
            metadata_version=metadata.metadata_version,
            nonce=nonce,
            ciphertext=ciphertext,
            hmac_tag=hmac_tag,
        )

    def unprotect(self, protected: ProtectedMetadata) -> FileMetadata:
        mac_input = self._mac_input(
            protected.file_id, protected.metadata_version, protected.nonce, protected.ciphertext
        )
        if not verify_hmac(self._keys.hmac_key, mac_input, protected.hmac_tag):
            logger.warning("Metadata HMAC verification failed for file_id=%s", protected.file_id)
            raise MetadataTamperError(f"Metadata integrity check failed for file_id={protected.file_id}")

        try:
            payload = aes_cipher.decrypt(protected.nonce, protected.ciphertext, self._keys.encryption_key)
        except DecryptionError as exc:
            raise MetadataTamperError(
                f"Metadata decryption failed for file_id={protected.file_id}: {exc}"
            ) from exc

        return FileMetadata.from_dict(json.loads(payload.decode("utf-8")))
