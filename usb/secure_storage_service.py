"""Secure Storage Layer orchestration.

Ties together file encryption (`crypto`), metadata protection
(`metadata`), and device I/O (`usb.storage_writer`) into the single
operation the Secure Storage Layer exists to perform: take a plaintext
file and a validated USB device, and end up with one `.cusc` container
on the device holding the encrypted file, its wrapped key, and its
encrypted metadata — and nothing in plaintext, ever touching the disk.
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
from metadata.models import CURRENT_METADATA_VERSION, FileMetadata
from metadata.protection import MetadataProtectionKeys, MetadataProtector, generate_protection_keys
from usb.device_detector import USBDevice
from usb.secure_container import SecureContainer, verify_container_deep
from usb.storage_writer import SecureStorageWriter

logger = get_logger(__name__)


@dataclass
class SecureWriteResult:
    """What the caller needs to locate, and later verify, a stored file."""

    file_id: str
    destination: Path
    container_size_bytes: int
    protection_keys: MetadataProtectionKeys


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
    ) -> SecureWriteResult:
        """Encrypt `source_path` and write it to `device` as a secure container.

        Never writes plaintext anywhere. Raises `usb.exceptions.DeviceValidationError`,
        `ContainerOverwriteError`, `ContainerWriteError`, or `ContainerVerificationError`
        on failure (see `SecureStorageWriter.write_container`).
        """
        source_path = Path(source_path)
        file_container = self._file_encryptor.encrypt_bytes(source_path.read_bytes(), key_wrapper)

        integrity_hash = compute_integrity_hash(file_container.serialize())
        file_id = str(uuid.uuid4())

        metadata = FileMetadata(
            file_id=file_id,
            owner_id=owner_id,
            wrapped_key=file_container.wrapped_key,
            wrap_algorithm=file_container.wrap_algorithm,
            integrity_hash=integrity_hash,
            created_at=datetime.now(timezone.utc),
            metadata_version=CURRENT_METADATA_VERSION,
        )

        keys = protection_keys or generate_protection_keys()
        protected_metadata = MetadataProtector(keys).protect(metadata)

        container = SecureContainer(
            file_id=file_id, file_container=file_container, protected_metadata=protected_metadata
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
        )

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
