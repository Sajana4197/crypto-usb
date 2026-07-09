"""Metadata Controller: the single entry point for reading, updating,
validating, and policy-enforcing a file's encrypted metadata record.

Composes `MetadataProtector` (encryption + HMAC) with
`MetadataRepository` (SQLite persistence) so callers never touch
either directly.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.logger import get_logger
from metadata.exceptions import (
    MetadataNotFoundError,
    MetadataValidationError,
    PolicyViolationError,
)
from metadata.hashing import verify_integrity_hash
from metadata.models import (
    CURRENT_METADATA_VERSION,
    DeviceBinding,
    ExpiryRules,
    FileMetadata,
    UsagePolicy,
)
from metadata.protection import MetadataProtector
from metadata.repository import MetadataRepository

logger = get_logger(__name__)


class MetadataController:
    """Reads, updates, validates, and enforces policy on file metadata."""

    def __init__(self, repository: MetadataRepository, protector: MetadataProtector) -> None:
        self._repository = repository
        self._protector = protector

    def create(
        self,
        file_id: str,
        owner_id: str,
        wrapped_key: bytes,
        wrap_algorithm: str,
        integrity_hash: str,
        expiry_rules: ExpiryRules | None = None,
        device_binding: DeviceBinding | None = None,
        usage_policy: UsagePolicy | None = None,
    ) -> FileMetadata:
        metadata = FileMetadata(
            file_id=file_id,
            owner_id=owner_id,
            wrapped_key=wrapped_key,
            wrap_algorithm=wrap_algorithm,
            integrity_hash=integrity_hash,
            created_at=datetime.now(timezone.utc),
            last_accessed_at=None,
            access_count=0,
            expiry_rules=expiry_rules or ExpiryRules(),
            device_binding=device_binding or DeviceBinding(),
            usage_policy=usage_policy or UsagePolicy(),
            metadata_version=CURRENT_METADATA_VERSION,
        )
        self.validate(metadata)
        self._repository.save(self._protector.protect(metadata))
        logger.info("Created metadata record for file_id=%s", file_id)
        return metadata

    def read(self, file_id: str) -> FileMetadata:
        protected = self._repository.load(file_id)
        if protected is None:
            raise MetadataNotFoundError(f"No metadata found for file_id={file_id}")
        metadata = self._protector.unprotect(protected)
        self.validate(metadata)
        return metadata

    def update(self, file_id: str, **changes) -> FileMetadata:
        metadata = self.read(file_id)
        for key, value in changes.items():
            if not hasattr(metadata, key):
                raise MetadataValidationError(f"Unknown metadata field: {key}")
            setattr(metadata, key, value)
        self.validate(metadata)
        self._repository.save(self._protector.protect(metadata))
        logger.info("Updated metadata record for file_id=%s", file_id)
        return metadata

    def record_access(self, file_id: str) -> FileMetadata:
        """Enforce policy, then record a new access (count + timestamp)."""
        metadata = self.read(file_id)
        self.enforce_policy(metadata)
        metadata.access_count += 1
        metadata.last_accessed_at = datetime.now(timezone.utc)
        self.validate(metadata)
        self._repository.save(self._protector.protect(metadata))
        logger.info("Recorded access for file_id=%s (count=%d)", file_id, metadata.access_count)
        return metadata

    def enforce_policy(self, metadata: FileMetadata) -> None:
        """Raise PolicyViolationError if accessing this file now would violate policy."""
        now = datetime.now(timezone.utc)

        if metadata.expiry_rules.expires_at is not None and now > metadata.expiry_rules.expires_at:
            raise PolicyViolationError(
                f"File {metadata.file_id} expired at {metadata.expiry_rules.expires_at}"
            )

        if (
            metadata.expiry_rules.max_access_count is not None
            and metadata.access_count >= metadata.expiry_rules.max_access_count
        ):
            raise PolicyViolationError(
                f"File {metadata.file_id} reached its maximum access count "
                f"({metadata.expiry_rules.max_access_count})"
            )

        if metadata.usage_policy.one_time_access and metadata.access_count >= 1:
            raise PolicyViolationError(
                f"File {metadata.file_id} allows only one-time access and has already been accessed"
            )

    def validate(self, metadata: FileMetadata) -> None:
        """Structural/business-rule validation, independent of tamper detection."""
        if not metadata.file_id:
            raise MetadataValidationError("file_id must not be empty")
        if not metadata.owner_id:
            raise MetadataValidationError("owner_id must not be empty")
        if not metadata.wrapped_key:
            raise MetadataValidationError("wrapped_key must not be empty")
        if not metadata.wrap_algorithm:
            raise MetadataValidationError("wrap_algorithm must not be empty")
        if len(metadata.integrity_hash) != 64 or not _is_hex(metadata.integrity_hash):
            raise MetadataValidationError("integrity_hash must be a 64-character SHA-256 hex digest")
        if metadata.access_count < 0:
            raise MetadataValidationError("access_count must not be negative")
        if metadata.metadata_version != CURRENT_METADATA_VERSION:
            raise MetadataValidationError(
                f"Unsupported metadata_version: {metadata.metadata_version} "
                f"(expected {CURRENT_METADATA_VERSION})"
            )
        if metadata.last_accessed_at is not None and metadata.last_accessed_at < metadata.created_at:
            raise MetadataValidationError("last_accessed_at cannot be before created_at")

    def delete(self, file_id: str) -> bool:
        return self._repository.delete(file_id)

    def verify_file_integrity(self, file_id: str, encrypted_file_bytes: bytes) -> bool:
        """Check that `encrypted_file_bytes` matches this file's stored SHA-256 hash."""
        metadata = self.read(file_id)
        return verify_integrity_hash(encrypted_file_bytes, metadata.integrity_hash)


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False
