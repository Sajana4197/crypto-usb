"""Secure Access Service: the single place a caller attempts to view a
protected file.

Mirrors `usb.secure_storage_service.SecureStorageService` on the read
side: runs every access-time check (`validation.validation_engine`),
decrypts strictly in RAM (`crypto.secure_decryptor`), and — for a
one-time-access file — burns it immediately after a successful view
(`metadata.one_time_access.OneTimeAccessEnforcer`) so it can never be
legitimately opened again.

Every failure, at any stage, is handed to `deception.DeceptionEngine`
instead of being reported to the caller as an error:
- A failed validation check (tampered metadata, expired access, an
  unauthorized/cloned device, a reused one-time access still caught by
  the `access_count` counter) maps to the matching `DeceptionTrigger`.
- A decrypt that fails *despite validation passing* — which, for a
  one-time-access file, is the only place a repeat attempt is ever
  visible, since a burned file's metadata is deliberately
  indistinguishable from an unused one (see `metadata.one_time_access`)
  — is treated as `DeceptionTrigger.ACCESS_ALREADY_USED`.

The caller never learns *why* access was refused, and neither does
whoever is attempting it.

Metadata's `wrapped_key` — not the `wrapped_key` embedded in the
container bytes handed to `attempt_access` — is treated as the
authoritative key-wrapping state for every decrypt attempt. Burning a
one-time-access file only ever updates the metadata record, never the
stored container; treating metadata as authoritative here is what
makes that sufficient to permanently invalidate the file without
rewriting or deleting anything on the USB device.

When a `usage_tracker` is supplied, every attempt — granted or denied
— is recorded as one `tracking.tracking_service.UsageTracker` session:
login identity, whether validation passed, when the file was actually
opened (granted attempts only), and when the session closed. This is
the integration point `tracking.tracking_service`'s own docstring
anticipates ("not yet wired into ... validation.validation_engine ...
— a later integration phase"); it is wired here, at the same
composition root that already runs validation, rather than inside
`ValidationEngine` itself, since only this class has one attempt's
full lifecycle in view from start to finish.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import Callable, Optional

from core.logger import get_logger
from crypto.exceptions import DecryptionError, KeyUnwrappingError
from crypto.file_encryptor import EncryptedContainer
from crypto.key_wrapper import KeyWrapper
from crypto.secure_bytes import SecureBytes
from crypto.secure_cleanup import CleanupReason, cleanup
from crypto.secure_decryptor import SecureDecryptor
from deception.deception_engine import DeceptionEngine, DeceptionResponse
from deception.triggers import DeceptionTrigger
from metadata.models import FileMetadata
from metadata.one_time_access import OneTimeAccessEnforcer
from metadata.protection import MetadataProtectionKeys, MetadataProtector
from metadata.repository import MetadataRepository
from tracking.tracking_service import UsageTracker
from usb.device_detector import USBDevice
from validation.validation_engine import ValidationEngine, ValidationReport

logger = get_logger(__name__)

# Priority order matters: a record can fail more than one check at once
# (e.g. a tampered record is often also "expired" by coincidence of
# default values) — the most specific, most informative-for-logging
# trigger should win. None of this ordering is ever visible to whoever
# triggered the deception; it only shapes what gets logged internally.
_DEVICE_CHECK_NAMES = (
    "device_binding",
    "unauthorized_device",
    "cloned_usb",
    "usb_identifier",
    "machine_fingerprint",
)


def _map_validation_failure_to_trigger(report: ValidationReport) -> DeceptionTrigger:
    checks = report.checks
    if (
        checks.get("metadata_present") is False
        or checks.get("hmac") is False
        or checks.get("metadata_integrity") is False
    ):
        return DeceptionTrigger.METADATA_TAMPERING
    if checks.get("file_integrity") is False:
        return DeceptionTrigger.INTEGRITY_FAILURE
    if (
        checks.get("expiry") is False
        or checks.get("access_count") is False
        or checks.get("reused_access") is False
    ):
        return DeceptionTrigger.ACCESS_ALREADY_USED
    if any(checks.get(name) is False for name in _DEVICE_CHECK_NAMES):
        return DeceptionTrigger.DEVICE_MISMATCH
    return DeceptionTrigger.INTEGRITY_FAILURE


@dataclass
class AccessOutcome:
    """The result of one `SecureAccessService.attempt_access` call.

    `deception` is set when `granted` is False — the caller should show
    (or, for a file, hand back) its `content`, never anything indicating
    the real reason access was refused. `protection_keys` is set when
    `granted` is True and reflects whatever the caller must use for any
    future read of this file's metadata: unchanged for a reusable file,
    freshly rotated for a one-time-access file that was just burned.

    `on_view_closed` and `on_screen_capture_detected` are set whenever a
    usage-tracking session was started for this attempt (i.e. a
    `usage_tracker` was configured and this wasn't a `force_deception`
    short-circuit) — closing over the session's `UsageRecord` so the
    caller can seal it (`on_view_closed`) at the moment the user
    actually finishes viewing, and record a capture attempt
    (`on_screen_capture_detected`) at the moment one is detected,
    instead of this service guessing when either happens. Both are
    `None` when no usage tracker is configured.
    """

    granted: bool
    file_id: str
    deception: Optional[DeceptionResponse] = None
    protection_keys: Optional[MetadataProtectionKeys] = None
    on_view_closed: Optional[Callable[[], None]] = None
    on_screen_capture_detected: Optional[Callable[[], None]] = None


class SecureAccessService:
    """Validates, decrypts, and (for one-time-access files) burns a
    protected file in a single, deception-guarded operation."""

    def __init__(
        self,
        repository: MetadataRepository,
        decryptor: Optional[SecureDecryptor] = None,
        deception_engine: Optional[DeceptionEngine] = None,
        enforcer: Optional[OneTimeAccessEnforcer] = None,
        usage_tracker: Optional[UsageTracker] = None,
    ) -> None:
        self._repository = repository
        self._decryptor = decryptor or SecureDecryptor()
        self._deception_engine = deception_engine or DeceptionEngine()
        self._enforcer = enforcer or OneTimeAccessEnforcer(repository)
        self._usage_tracker = usage_tracker

    def attempt_access(
        self,
        file_id: str,
        encrypted_file_bytes: bytes,
        key_wrapper: KeyWrapper,
        protection_keys: MetadataProtectionKeys,
        on_granted: Callable[[SecureBytes, FileMetadata], None],
        current_device: Optional[USBDevice] = None,
        current_usb_identifier: Optional[str] = None,
        current_machine_fingerprint: Optional[str] = None,
        user: Optional[str] = None,
        force_deception: bool = False,
    ) -> AccessOutcome:
        """Validate and, if granted, decrypt `encrypted_file_bytes` for
        `file_id`, calling `on_granted(buffer, metadata)` with the
        decrypted content while it is still alive. The buffer is
        destroyed the instant `on_granted` returns (or raises) — see
        `crypto.secure_decryptor.SecureDecryptor.open_decrypted`.

        If `on_granted` returns normally and the file is marked for
        one-time access, it is burned immediately afterward: this was
        the only legitimate opportunity to view it.

        Never raises for an expected access failure — every such case
        instead activates the Deception Engine and is reported back
        through `AccessOutcome.deception`.

        `user` identifies the already-authenticated caller for the
        usage-tracking record (see the module docstring); callers reach
        this method only after `security.auth_controller` has already
        authenticated them, so the recorded `authentication_result` is
        always True — a failed authentication never gets this far.

        `force_deception=True` is how a decoy `AuthSession`
        (`security.auth_controller` returns one instead of raising on
        wrong credentials) reaches this service: it short-circuits before
        any usage-tracker session starts and before `ValidationEngine` or
        real key material is touched, so a decoy caller never gets near
        real metadata, real keys, or real decrypted content.
        """
        if force_deception:
            deception = self._deception_engine.activate(DeceptionTrigger.WRONG_CREDENTIALS, file_id=file_id)
            logger.warning(
                "Access attempt for file_id=%s forced into deception (decoy session); deception activated",
                file_id,
            )
            return AccessOutcome(granted=False, file_id=file_id, deception=deception)

        record = None
        if self._usage_tracker is not None:
            record = self._usage_tracker.start_session(
                user=user or "unknown",
                machine_id=current_machine_fingerprint or "unknown",
                file_id=file_id,
                usb_id=current_usb_identifier,
            )
            self._usage_tracker.record_authentication_result(record, True)

        engine = ValidationEngine(self._repository, MetadataProtector(protection_keys))
        report = engine.validate(
            file_id, encrypted_file_bytes, current_device, current_usb_identifier, current_machine_fingerprint
        )

        if not report.ok:
            trigger = _map_validation_failure_to_trigger(report)
            deception = self._deception_engine.activate(trigger, file_id=file_id)
            logger.warning(
                "Access denied for file_id=%s (trigger=%s); deception activated", file_id, trigger.value
            )
            on_view_closed = None
            on_screen_capture_detected = None
            if record is not None:
                self._usage_tracker.record_validation_result(record, False)
                on_view_closed = partial(self._usage_tracker.record_close, record)
                on_screen_capture_detected = partial(self._usage_tracker.record_screen_capture_attempt, record)
            cleanup(CleanupReason.VALIDATION_FAILURE)
            return AccessOutcome(
                granted=False,
                file_id=file_id,
                deception=deception,
                on_view_closed=on_view_closed,
                on_screen_capture_detected=on_screen_capture_detected,
            )

        if record is not None:
            self._usage_tracker.record_validation_result(record, True)

        metadata = report.metadata
        assert metadata is not None
        container = EncryptedContainer.deserialize(encrypted_file_bytes)
        # Metadata is the authoritative source for how this file's FEK is
        # wrapped — not whatever value happens to be embedded in the
        # container bytes read back from the device. This is what makes
        # burning (metadata.one_time_access.OneTimeAccessEnforcer.burn)
        # actually take effect without ever touching the stored container:
        # burning only replaces metadata.wrapped_key, so every future
        # decrypt attempt through this service uses the decoy key, no
        # matter how many byte-identical copies of the original container
        # exist on disk.
        container.wrapped_key = metadata.wrapped_key

        try:
            if record is not None:
                self._usage_tracker.record_open(record)
            with self._decryptor.open_decrypted(container, key_wrapper) as buffer:
                on_granted(buffer, metadata)
        except (KeyUnwrappingError, DecryptionError):
            deception = self._deception_engine.activate(DeceptionTrigger.ACCESS_ALREADY_USED, file_id=file_id)
            logger.warning(
                "Decryption failed for file_id=%s despite passing validation "
                "(one-time access already consumed, or invalid key material); deception activated",
                file_id,
            )
            on_view_closed = None
            on_screen_capture_detected = None
            if record is not None:
                on_view_closed = partial(self._usage_tracker.record_close, record)
                on_screen_capture_detected = partial(self._usage_tracker.record_screen_capture_attempt, record)
            cleanup(CleanupReason.VALIDATION_FAILURE)
            return AccessOutcome(
                granted=False,
                file_id=file_id,
                deception=deception,
                on_view_closed=on_view_closed,
                on_screen_capture_detected=on_screen_capture_detected,
            )

        new_keys = protection_keys
        if metadata.usage_policy.one_time_access:
            new_keys = self._enforcer.burn(metadata, key_wrapper, protection_keys)

        on_view_closed = None
        on_screen_capture_detected = None
        if record is not None:
            on_view_closed = partial(self._usage_tracker.record_close, record)
            on_screen_capture_detected = partial(self._usage_tracker.record_screen_capture_attempt, record)

        logger.info("Access granted and viewing completed for file_id=%s", file_id)
        cleanup(CleanupReason.SUCCESSFUL_VIEW)
        return AccessOutcome(
            granted=True,
            file_id=file_id,
            protection_keys=new_keys,
            on_view_closed=on_view_closed,
            on_screen_capture_detected=on_screen_capture_detected,
        )
