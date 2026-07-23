"""Secure Storage Layer orchestration.

Ties together file encryption (`crypto`), metadata protection
(`metadata`), and device I/O (`usb.storage_writer`) into the single
operation the Secure Storage Layer exists to perform: take a plaintext
file and a validated USB device, and end up with one `.cusc` container
on the device holding the encrypted file, its wrapped key, and its
encrypted metadata — and nothing in plaintext, ever touching the disk.

Metadata is always embedded in the `.cusc` container itself (so the
container is self-contained and independently deep-verifiable — see
`verify_stored_file`), and, when a `metadata_repository` is supplied,
also saved there under the same `file_id`. That second copy is what
`validation.validation_engine`/`usb.secure_access_service` consult for
every access-time check (device binding, expiry, one-time access) —
those checks need a local, queryable record independent of whatever
`.cusc` file happens to be presented, which is exactly what
`metadata_repository` provides. Both copies are protected with the
same `protection_keys` and built from the same `FileMetadata`, so they
never disagree.

When `portable_metadata_keys`/`portable_metadata_salt` are also
supplied (typically derived by the caller from the file-wrapping
private key + a passphrase via
`metadata.protection.derive_protection_keys_from_key_material` — see
`ui.pages.encryption_page.EncryptionPage`), a *third* copy of the same
`FileMetadata` is protected under those keys and embedded directly in
the `.cusc` container as its portable-metadata section
(`metadata.portable_envelope.PortableMetadataEnvelope`, part of
`usb.secure_container.SecureContainer` — see that module). Unlike the
local SQLite copy, this one travels with the device and can be
re-derived and decrypted on any machine that has the private key and
passphrase, with no local database, and no second file, required. It
is additive: omitting these two parameters writes exactly as before,
with no portable section.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from crypto.file_encryptor import FileEncryptor
from crypto.key_manager import KeyManager
from crypto.key_wrapper import KeyWrapper
from metadata.hashing import compute_integrity_hash
from metadata.models import CURRENT_METADATA_VERSION, DeviceBinding, ExpiryRules, FileMetadata, UsagePolicy
from metadata.portable_envelope import PortableMetadataEnvelope
from metadata.protection import MetadataProtectionKeys, MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from usb.device_detector import USBDevice
from usb.secure_container import SecureContainer, verify_container_deep
from usb.storage_writer import SecureStorageWriter
from validation.machine_fingerprint import compute_machine_fingerprint
from validation.usb_identifier import compute_usb_identifier

logger = get_logger(__name__)


@dataclass
class SecureWriteResult:
    """What the caller needs to locate, and later verify, a stored file."""

    file_id: str
    destination: Path
    container_size_bytes: int
    protection_keys: MetadataProtectionKeys
    portable_metadata_embedded: bool = False


class SecureStorageService:
    """High-level entry point: encrypt a file and write it to a USB device as a secure container."""

    def __init__(
        self,
        file_encryptor: Optional[FileEncryptor] = None,
        storage_writer: Optional[SecureStorageWriter] = None,
        key_manager: Optional[KeyManager] = None,
    ) -> None:
        self._file_encryptor = file_encryptor or FileEncryptor()
        self._storage_writer = storage_writer or SecureStorageWriter()
        self._key_manager = key_manager or KeyManager()

    def store_file(
        self,
        source_path: Path,
        device: USBDevice,
        key_wrapper: KeyWrapper,
        owner_id: str,
        overwrite: bool = False,
        protection_keys: Optional[MetadataProtectionKeys] = None,
        metadata_repository: Optional[MetadataRepository] = None,
        expiry_rules: Optional[ExpiryRules] = None,
        usage_policy: Optional[UsagePolicy] = None,
        bind_to_device: bool = False,
        portable_metadata_keys: Optional[MetadataProtectionKeys] = None,
        portable_metadata_salt: Optional[bytes] = None,
    ) -> SecureWriteResult:
        """Encrypt `source_path` and write it to `device` as a secure container.

        Never writes plaintext anywhere. Raises `usb.exceptions.DeviceValidationError`,
        `ContainerOverwriteError`, `ContainerWriteError`, or `ContainerVerificationError`
        on failure (see `SecureStorageWriter.write_container`).

        When `metadata_repository` is given, the same protected metadata
        record embedded in the `.cusc` container is also saved there —
        see the module docstring for why both copies exist. `expiry_rules`
        / `usage_policy` (e.g. one-time access) are enforced later by
        `validation.validation_engine`, which only ever consults the
        repository copy. When `bind_to_device` is True, this file can
        only ever be validated again from this same physical USB device
        and host machine (`validation.device_binding_validator`).

        When `portable_metadata_keys` and `portable_metadata_salt` are
        both given, a third protected copy of the same metadata is
        embedded in the container's own portable-metadata section — see
        the module docstring. Both must be supplied together; either one
        alone is a caller error.
        """
        if (portable_metadata_keys is None) != (portable_metadata_salt is None):
            raise ValueError("portable_metadata_keys and portable_metadata_salt must be supplied together")
        source_path = Path(source_path)
        file_container = self._file_encryptor.encrypt_bytes(source_path.read_bytes(), key_wrapper)

        integrity_hash = compute_integrity_hash(file_container.serialize())
        file_id = str(uuid.uuid4())

        device_binding = (
            DeviceBinding(
                device_id=device.device_id,
                label=device.label,
                bound=True,
                usb_serial=compute_usb_identifier(device),
                machine_fingerprint=compute_machine_fingerprint(),
            )
            if bind_to_device
            else DeviceBinding()
        )

        metadata = FileMetadata(
            file_id=file_id,
            owner_id=owner_id,
            wrapped_key=file_container.wrapped_key,
            wrap_algorithm=file_container.wrap_algorithm,
            integrity_hash=integrity_hash,
            created_at=datetime.now(timezone.utc),
            expiry_rules=expiry_rules or ExpiryRules(),
            device_binding=device_binding,
            usage_policy=usage_policy or UsagePolicy(),
            metadata_version=CURRENT_METADATA_VERSION,
        )

        keys = protection_keys or generate_protection_keys()
        protected_metadata = MetadataProtector(keys).protect(metadata)

        if metadata_repository is not None:
            metadata_repository.save(protected_metadata)

        portable_metadata = None
        if portable_metadata_keys is not None and portable_metadata_salt is not None:
            portable_protected = MetadataProtector(portable_metadata_keys).protect(metadata)
            portable_metadata = PortableMetadataEnvelope(salt=portable_metadata_salt, protected=portable_protected)

        container = SecureContainer(
            file_id=file_id,
            file_container=file_container,
            protected_metadata=protected_metadata,
            portable_metadata=portable_metadata,
        )

        destination = self._storage_writer.write_container(
            container, device, filename=f"{file_id}.cusc", overwrite=overwrite
        )

        logger.info(
            "Stored file %s as secure container %s on device %s",
            source_path.name,
            destination,
            device.device_id,
        )

        return SecureWriteResult(
            file_id=file_id,
            destination=destination,
            container_size_bytes=destination.stat().st_size,
            protection_keys=keys,
            portable_metadata_embedded=portable_metadata is not None,
        )

    def read_encrypted_file_bytes(self, container_path: Path) -> tuple[str, bytes]:
        """Read a `.cusc` container and return `(file_id, encrypted_file_bytes)`
        in exactly the form `usb.secure_access_service.SecureAccessService.attempt_access`
        expects — the embedded `crypto.file_encryptor.EncryptedContainer` bytes,
        not the outer `.cusc` envelope (whose own integrity is checked
        separately, structurally, by `SecureContainer.deserialize` itself).
        """
        container = self._storage_writer.read_container(Path(container_path))
        return container.file_id, container.file_container.serialize()

    def verify_stored_file(
        self,
        container_path: Path,
        key_wrapper: KeyWrapper,
        protection_keys: MetadataProtectionKeys,
    ) -> bool:
        """Deep-verify a previously stored container: unwrap, decrypt, and check
        metadata integrity entirely in memory. Never exposes plaintext.
        """
        container = self._storage_writer.read_container(Path(container_path))
        protector = MetadataProtector(protection_keys)
        return verify_container_deep(container, self._key_manager, key_wrapper, protector)
