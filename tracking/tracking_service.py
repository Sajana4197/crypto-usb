"""Usage Tracking: the single place a file-access session's lifecycle is
recorded, from login through open/close, and persisted to the
tamper-evident log.

`UsageTracker` builds one in-memory `UsageRecord` per session (login ->
authentication/validation results -> open -> screen-capture/tampering
events accumulated while open -> close), then seals and appends it to
the log exactly once, at `record_close` — the log is append-only, so a
session's record is only ever written in its final, complete form
rather than mutated in place after being persisted.

Not yet wired into `security.auth_controller`, `validation.validation_engine`,
or `viewer.secure_viewer_widget` — those call sites are a later
integration phase, matching how earlier phases (validation, deception,
the viewer) each landed as a standalone, tested module first.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from core.logger import get_logger
from tracking.models import UsageRecord
from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import ChainVerificationResult, TamperEvidentLog, TrackingProtectionKeys

logger = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UsageTracker:
    """Builds and persists `UsageRecord`s across a session's lifecycle."""

    def __init__(
        self,
        keys: TrackingProtectionKeys,
        repository: Optional[TrackingRepository] = None,
    ) -> None:
        self._log = TamperEvidentLog(keys)
        self._repository = repository

    def start_session(self, user: str, machine_id: str, file_id: str, usb_id: Optional[str] = None) -> UsageRecord:
        """Begin tracking a session: records the login time and identity fields."""
        record = UsageRecord(
            session_id=str(uuid.uuid4()),
            user=user,
            machine_id=machine_id,
            file_id=file_id,
            usb_id=usb_id,
            login_time=_now(),
        )
        logger.info(
            "Usage session started: session_id=%s user=%s file_id=%s", record.session_id, user, file_id
        )
        return record

    def record_authentication_result(self, record: UsageRecord, success: bool) -> None:
        record.authentication_result = success

    def record_validation_result(self, record: UsageRecord, success: bool) -> None:
        record.validation_result = success

    def record_open(self, record: UsageRecord) -> None:
        record.open_time = _now()

    def record_screen_capture_attempt(self, record: UsageRecord) -> None:
        record.screen_capture_attempts += 1
        logger.warning(
            "Screen capture attempt recorded for session_id=%s (total=%d)",
            record.session_id,
            record.screen_capture_attempts,
        )

    def record_tampering_event(self, record: UsageRecord) -> None:
        record.tampering_events += 1
        logger.warning(
            "Tampering event recorded for session_id=%s (total=%d)",
            record.session_id,
            record.tampering_events,
        )

    def record_close(self, record: UsageRecord) -> UsageRecord:
        """Finalize `record`: sets close time and duration, then seals and
        appends it to the tamper-evident log (if a repository was given)."""
        record.close_time = _now()
        if record.open_time is not None:
            record.duration_seconds = (record.close_time - record.open_time).total_seconds()

        if self._repository is not None:
            prev_hmac = self._repository.last_entry_hmac()
            entry = self._log.seal(record, prev_hmac)
            self._repository.append(record.session_id, entry)

        logger.info(
            "Usage session closed: session_id=%s duration_seconds=%s",
            record.session_id,
            record.duration_seconds,
        )
        return record

    def read_all_records(self) -> list[UsageRecord]:
        """Decrypt and return every stored record, in original append order."""
        if self._repository is None:
            return []
        return [self._log.open(entry) for entry in self._repository.list_entries()]

    def verify_log_integrity(self) -> ChainVerificationResult:
        """Verify every stored entry's HMAC and the chain linking them."""
        if self._repository is None:
            return ChainVerificationResult(ok=True, verified_count=0, reason=None)
        return self._log.verify_chain(self._repository.list_entries())
