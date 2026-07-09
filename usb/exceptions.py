"""Exceptions raised by the USB secure storage layer."""

from __future__ import annotations


class USBError(Exception):
    """Base class for all USB storage layer errors."""


class DeviceNotFoundError(USBError):
    """Raised when a referenced device is no longer attached or mounted."""


class DeviceValidationError(USBError):
    """Raised when a device fails validation (not removable, not writable, insufficient space)."""


class ContainerOverwriteError(USBError):
    """Raised when writing would silently overwrite an existing container without explicit consent."""


class ContainerWriteError(USBError):
    """Raised when writing a secure container to the destination fails."""


class ContainerVerificationError(USBError):
    """Raised when a written or loaded container fails structural or integrity verification."""
