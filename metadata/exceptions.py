"""Exceptions raised by the metadata package."""

from __future__ import annotations


class MetadataError(Exception):
    """Base class for all metadata errors."""


class MetadataTamperError(MetadataError):
    """Raised when a stored metadata record fails its HMAC or decryption integrity check."""


class MetadataNotFoundError(MetadataError):
    """Raised when no metadata record exists for a given file_id."""


class MetadataValidationError(MetadataError):
    """Raised when a metadata record fails structural or business-rule validation."""


class PolicyViolationError(MetadataError):
    """Raised when accessing a file would violate its expiry or usage policy."""
