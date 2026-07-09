"""Secure writing of `SecureContainer` payloads to a validated USB device.

Writes are atomic (temp file + `os.replace`) so a crash or an unplugged
drive mid-write never leaves a half-written, corrupt container in place
of a good one. An existing container at the destination is never
overwritten unless the caller explicitly opts in, and every write is
immediately read back and verified before being reported as successful.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from usb.device_detector import USBDevice
from usb.device_validator import USBDeviceValidator
from usb.exceptions import (
    ContainerOverwriteError,
    ContainerVerificationError,
    ContainerWriteError,
    DeviceValidationError,
)
from usb.secure_container import CONTAINER_EXTENSION, SecureContainer

logger = get_logger(__name__)


class SecureStorageWriter:
    """Writes, verifies, and reads `SecureContainer` payloads on removable devices."""

    def __init__(self, validator: Optional[USBDeviceValidator] = None) -> None:
        self._validator = validator or USBDeviceValidator()

    def write_container(
        self,
        container: SecureContainer,
        device: USBDevice,
        filename: Optional[str] = None,
        overwrite: bool = False,
    ) -> Path:
        """Validate the device, write `container` atomically, then verify it.

        Raises `DeviceValidationError` if the device isn't safe to write to,
        `ContainerOverwriteError` if the destination exists and `overwrite`
        is False, `ContainerWriteError` on an I/O failure, or
        `ContainerVerificationError` if the post-write verification fails.
        """
        payload = container.serialize()

        validation = self._validator.validate(device, required_bytes=len(payload))
        if not validation.ok:
            raise DeviceValidationError(
                f"Device {device.device_id} failed validation: {'; '.join(validation.reasons)}"
            )

        name = filename or f"{container.file_id}{CONTAINER_EXTENSION}"
        destination = Path(device.mount_point) / name

        if destination.exists() and not overwrite:
            raise ContainerOverwriteError(
                f"Refusing to overwrite existing container at {destination}. "
                "Pass overwrite=True to replace it explicitly."
            )

        temp_path = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            with open(temp_path, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, destination)
        except OSError as exc:
            self._cleanup(temp_path)
            logger.error("Failed to write secure container to %s: %s", destination, exc)
            raise ContainerWriteError(f"Failed to write container to {destination}: {exc}") from exc

        logger.info(
            "Wrote secure container file_id=%s -> %s (%d bytes)",
            container.file_id,
            destination,
            len(payload),
        )

        try:
            self.verify_container(destination, expected_payload=payload)
        except ContainerVerificationError:
            logger.error("Post-write verification failed for %s", destination)
            raise

        return destination

    def read_container(self, path: Path) -> SecureContainer:
        """Load and structurally verify a container from disk."""
        data = Path(path).read_bytes()
        return SecureContainer.deserialize(data)

    def verify_container(self, path: Path, expected_payload: Optional[bytes] = None) -> bool:
        """Verify a container on disk: structural validity, outer hash, and
        (if `expected_payload` is given) a byte-for-byte match against what
        was just written. Raises `ContainerVerificationError` on any failure.
        """
        path = Path(path)
        if not path.exists():
            raise ContainerVerificationError(f"No container found at {path}")

        data = path.read_bytes()

        if expected_payload is not None and data != expected_payload:
            raise ContainerVerificationError(
                f"On-disk container at {path} does not match the data that was written"
            )

        SecureContainer.deserialize(data)

        logger.info("Verified secure container at %s (%d bytes)", path, len(data))
        return True

    @staticmethod
    def _cleanup(temp_path: Path) -> None:
        try:
            if temp_path.exists():
                os.remove(temp_path)
        except OSError:
            pass
