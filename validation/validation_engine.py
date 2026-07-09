"""The Validation Engine: the single place every access-time check runs
before a caller may proceed with decrypting or otherwise using a
protected file.

Composes, without duplicating:

- `metadata.protection.MetadataProtector` for the encrypt-then-MAC
  integrity check ("HMAC" — checked first, before any decryption is
  attempted, exactly as `MetadataProtector.unprotect` already does).
- `metadata.controller.MetadataController.validate` for structural
  metadata validity ("Metadata Integrity").
- `metadata.hashing` for the encrypted file's SHA-256 integrity check
  ("File Integrity").
- `validation.device_binding_validator.DeviceBindingValidator` for
  device/machine binding ("Device Binding", "Machine Fingerprint",
  "USB Identifier"; and the "Cloned USB" / "Unauthorized devices"
  rejection reasons).
- Expiry / access-count / one-time-access checks that mirror
  `MetadataController.enforce_policy`, but read-only — this engine
  never mutates `access_count` or `last_accessed_at`. Once access is
  actually granted, the caller is still expected to call
  `MetadataController.record_access` separately.

Nothing here decrypts a file or grants access by itself — it only
produces a `ValidationReport` the caller must check before proceeding.
What happens on a rejected access (deception-module behavior) is a
later phase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.logger import get_logger
from metadata.controller import MetadataController
from metadata.exceptions import MetadataTamperError, MetadataValidationError
from metadata.hashing import verify_integrity_hash
from metadata.models import FileMetadata
from metadata.protection import MetadataProtector
from metadata.repository import MetadataRepository
from usb.device_detector import USBDevice
from validation.device_binding_validator import DeviceBindingValidator
from validation.exceptions import ValidationFailedError

logger = get_logger(__name__)


@dataclass
class ValidationReport:
    """The outcome of validating one file, with a named boolean per check."""

    file_id: str
    ok: bool = True
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    metadata: Optional[FileMetadata] = None

    def add(self, name: str, passed: bool, reason: Optional[str] = None) -> None:
        self.checks[name] = passed
        if not passed:
            self.ok = False
            if reason:
                self.reasons.append(reason)


class ValidationEngine:
    """Runs every access-time validation check and returns one report."""

    def __init__(
        self,
        repository: MetadataRepository,
        protector: MetadataProtector,
        device_binding_validator: Optional[DeviceBindingValidator] = None,
    ) -> None:
        self._repository = repository
        self._protector = protector
        self._controller = MetadataController(repository, protector)
        self._device_binding_validator = device_binding_validator or DeviceBindingValidator()

    def validate(
        self,
        file_id: str,
        encrypted_file_bytes: bytes,
        current_device: Optional[USBDevice] = None,
        current_usb_identifier: Optional[str] = None,
        current_machine_fingerprint: Optional[str] = None,
    ) -> ValidationReport:
        """Run every check for `file_id` and return a `ValidationReport`.

        Never raises for an expected validation failure (bad HMAC, expired
        access, wrong device, ...) — check `report.ok` / `report.checks` /
        `report.reasons`. Use `validate_or_raise` if a single exception is
        more convenient at the call site.
        """
        logger.info("Validating file_id=%s", file_id)
        report = ValidationReport(file_id=file_id)

        protected = self._repository.load(file_id)
        if protected is None:
            report.add("metadata_present", False, f"No metadata found for file_id={file_id}")
            logger.warning("Validation failed for file_id=%s: metadata not found", file_id)
            return report
        report.add("metadata_present", True)

        try:
            metadata = self._protector.unprotect(protected)
        except MetadataTamperError as exc:
            report.add("hmac", False, f"Metadata failed HMAC/integrity check: {exc}")
            logger.warning("Validation failed for file_id=%s: HMAC/tamper check failed", file_id)
            return report
        report.add("hmac", True)
        report.metadata = metadata

        try:
            self._controller.validate(metadata)
            report.add("metadata_integrity", True)
        except MetadataValidationError as exc:
            report.add("metadata_integrity", False, f"Metadata failed structural validation: {exc}")

        file_integrity_ok = verify_integrity_hash(encrypted_file_bytes, metadata.integrity_hash)
        report.add(
            "file_integrity",
            file_integrity_ok,
            None if file_integrity_ok else "Encrypted file content does not match its stored integrity hash",
        )

        self._validate_policy(report, metadata)

        binding_result = self._device_binding_validator.validate(
            metadata.device_binding, current_device, current_usb_identifier, current_machine_fingerprint
        )
        for name, passed in binding_result.checks.items():
            report.add(name, passed)
        for reason in binding_result.reasons:
            if reason not in report.reasons:
                report.reasons.append(reason)

        if report.ok:
            logger.info("Validation passed for file_id=%s", file_id)
        else:
            logger.warning("Validation failed for file_id=%s: %s", file_id, "; ".join(report.reasons))

        return report

    def validate_or_raise(
        self,
        file_id: str,
        encrypted_file_bytes: bytes,
        current_device: Optional[USBDevice] = None,
        current_usb_identifier: Optional[str] = None,
        current_machine_fingerprint: Optional[str] = None,
    ) -> ValidationReport:
        """Like `validate`, but raises `ValidationFailedError` if any check failed."""
        report = self.validate(
            file_id, encrypted_file_bytes, current_device, current_usb_identifier, current_machine_fingerprint
        )
        if not report.ok:
            raise ValidationFailedError(report)
        return report

    @staticmethod
    def _validate_policy(report: ValidationReport, metadata: FileMetadata) -> None:
        now = datetime.now(timezone.utc)

        if metadata.expiry_rules.expires_at is not None:
            expired = now > metadata.expiry_rules.expires_at
            report.add("expiry", not expired, None if not expired else f"Access expired at {metadata.expiry_rules.expires_at}")
        else:
            report.add("expiry", True)

        if metadata.expiry_rules.max_access_count is not None:
            within_limit = metadata.access_count < metadata.expiry_rules.max_access_count
            report.add(
                "access_count",
                within_limit,
                None if within_limit else f"Maximum access count ({metadata.expiry_rules.max_access_count}) reached",
            )
        else:
            report.add("access_count", True)

        if metadata.usage_policy.one_time_access:
            not_reused = metadata.access_count < 1
            report.add("reused_access", not_reused, None if not_reused else "One-time access has already been used")
        else:
            report.add("reused_access", True)
