"""Rate-limiting for repeated device-mismatch attempts against a file.

Mirrors `security.lockout_policy.LockoutPolicy`'s escalating-lockout
shape — same thresholds, same doubling backoff formula, same reset-on-
success semantics — so brute-force protection behaves consistently
app-wide, whether the thing being probed is an account's password or a
file's device binding. `usb.secure_access_service.SecureAccessService`
previously let an unlimited number of different USB devices be tried
against the same protected file, each one independently triggering
`deception.triggers.DeceptionTrigger.DEVICE_MISMATCH` with no
escalation; this closes that gap.

Keyed by `file_id` rather than `owner_id` — a `UserAccount`'s lockout
state lives on the account because credential brute-forcing targets an
account, but device-mismatch probing targets a specific protected
file, independent of who's attempting it or which account they're
signed into. State lives in memory only, for the lifetime of one
`DeviceMismatchThrottle` instance — callers that need it to persist
across multiple access attempts (i.e. every real caller) must construct
one instance and reuse it, exactly as `ui.pages.decryption_page.DecryptionPage`
does with its own `DeceptionEngine` instance, rather than one per attempt.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from security.lockout_policy import BASE_LOCKOUT_SECONDS, MAX_FAILED_ATTEMPTS, MAX_LOCKOUT_SECONDS


@dataclass
class _DeviceMismatchState:
    """Per-`file_id` attempt state — the file-scoped analogue of
    `security.models.UserAccount`'s `failed_attempts`/`locked_until`."""

    failed_attempts: int = 0
    locked_until: Optional[datetime] = None


class DeviceMismatchThrottle:
    """Tracks and enforces escalating lockout for repeated device-mismatch
    attempts against the same `file_id`.

    Uses the exact same `MAX_FAILED_ATTEMPTS`/`BASE_LOCKOUT_SECONDS`/
    `MAX_LOCKOUT_SECONDS` constants as `security.lockout_policy.LockoutPolicy`
    (imported, not redefined) so a future change to those thresholds
    automatically stays consistent between both mechanisms.
    """

    def __init__(self) -> None:
        self._state: dict[str, _DeviceMismatchState] = {}

    def is_locked(self, file_id: str) -> bool:
        state = self._state.get(file_id)
        if state is None or state.locked_until is None:
            return False
        return datetime.now(timezone.utc) < state.locked_until

    def seconds_remaining(self, file_id: str) -> int:
        state = self._state.get(file_id)
        if state is None or state.locked_until is None:
            return 0
        remaining = (state.locked_until - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))

    def register_mismatch(self, file_id: str) -> None:
        state = self._state.setdefault(file_id, _DeviceMismatchState())
        state.failed_attempts += 1
        if state.failed_attempts >= MAX_FAILED_ATTEMPTS:
            overflow = state.failed_attempts - MAX_FAILED_ATTEMPTS
            lockout_seconds = min(BASE_LOCKOUT_SECONDS * (2**overflow), MAX_LOCKOUT_SECONDS)
            state.locked_until = datetime.now(timezone.utc) + timedelta(seconds=lockout_seconds)

    def register_success(self, file_id: str) -> None:
        state = self._state.get(file_id)
        if state is not None:
            state.failed_attempts = 0
            state.locked_until = None
