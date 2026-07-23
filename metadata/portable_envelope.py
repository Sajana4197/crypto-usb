"""The portable metadata envelope.

Embedded as its own section directly inside each `.cusc` container
(`usb.secure_container.SecureContainer.portable_metadata`) so a file's
metadata can be recovered on *any* machine that has the file-wrapping
RSA private key and its passphrase — independent of this machine's
local SQLite `metadata.repository.MetadataRepository`. It is protected
with keys from `metadata.protection.derive_protection_keys_from_key_material`
rather than the (typically random) `MetadataProtectionKeys` embedded
in the container's own local metadata section, so the `salt` carried
in this envelope — plus the private key and passphrase the user
already exports and carries — is everything needed to re-derive the
same protection keys elsewhere and decrypt it. `salt` is not secret.

Binary format mirrors `crypto.file_encryptor.EncryptedContainer`'s
versioned envelope style: magic bytes, a version byte, then
length-prefixed fields — file_id and salt sized like
`usb.secure_container.SecureContainer`'s own fields, nonce/hmac_tag/
ciphertext sized exactly like its embedded `ProtectedMetadata` blob.
"""

from __future__ import annotations

from dataclasses import dataclass

from metadata.exceptions import MetadataValidationError
from metadata.protection import ProtectedMetadata

MAGIC = b"CUPM"  # CryptoUSB Portable Metadata
FORMAT_VERSION = 1


@dataclass
class PortableMetadataEnvelope:
    """The on-USB sibling-file payload: a non-secret KDF `salt` plus the
    metadata record it protects, protected under keys derived from that
    salt (see the module docstring)."""

    salt: bytes
    protected: ProtectedMetadata

    def serialize(self) -> bytes:
        file_id_bytes = self.protected.file_id.encode("utf-8")
        if len(file_id_bytes) > 255:
            raise MetadataValidationError("file_id too long to serialize into a portable metadata envelope")
        if len(self.salt) > 255:
            raise MetadataValidationError("salt too long to serialize into a portable metadata envelope")

        return b"".join(
            [
                MAGIC,
                bytes([FORMAT_VERSION]),
                bytes([len(file_id_bytes)]),
                file_id_bytes,
                bytes([len(self.salt)]),
                self.salt,
                self.protected.metadata_version.to_bytes(4, "big"),
                len(self.protected.nonce).to_bytes(2, "big"),
                self.protected.nonce,
                len(self.protected.hmac_tag).to_bytes(2, "big"),
                self.protected.hmac_tag,
                len(self.protected.ciphertext).to_bytes(8, "big"),
                self.protected.ciphertext,
            ]
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "PortableMetadataEnvelope":
        if data[:4] != MAGIC:
            raise MetadataValidationError("Not a valid CUPM portable metadata envelope (bad magic bytes)")
        version = data[4]
        if version != FORMAT_VERSION:
            raise MetadataValidationError(f"Unsupported portable metadata envelope version: {version}")

        offset = 5
        file_id_len = data[offset]
        offset += 1
        file_id = data[offset : offset + file_id_len].decode("utf-8")
        offset += file_id_len

        salt_len = data[offset]
        offset += 1
        salt = data[offset : offset + salt_len]
        offset += salt_len

        metadata_version = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4

        nonce_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        nonce = data[offset : offset + nonce_len]
        offset += nonce_len

        hmac_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        hmac_tag = data[offset : offset + hmac_len]
        offset += hmac_len

        ciphertext_len = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
        ciphertext = data[offset : offset + ciphertext_len]

        return cls(
            salt=salt,
            protected=ProtectedMetadata(
                file_id=file_id,
                metadata_version=metadata_version,
                nonce=nonce,
                ciphertext=ciphertext,
                hmac_tag=hmac_tag,
            ),
        )
