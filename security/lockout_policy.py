"""Brute-force protection via escalating account lockout.

After `MAX_FAILED_ATTEMPTS` consecutive failures, the account is locked
for a duration that doubles with each additional failure beyond the
threshold (capped at `MAX_LOCKOUT_SECONDS`). A locked account is
rejected before any credential comparison happens at all, so repeated
guesses cannot be used to probe the password/key even indirectly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from security.models import UserAccount

MAX_FAILED_ATTEMPTS = 5
BASE_LOCKOUT_SECONDS = 30
MAX_LOCKOUT_SECONDS = 60 * 60  # 1 hour


class LockoutPolicy:
    """Tracks and enforces failed-attempt lockout state on a `UserAccount`."""

    def is_locked(self, account: UserAccount) -> bool:
        return account.locked_until is not None and datetime.now(timezone.utc) < account.locked_until

    def seconds_remaining(self, account: UserAccount) -> int:
        if account.locked_until is None:
            return 0
        remaining = (account.locked_until - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))

    def register_failure(self, account: UserAccount) -> None:
        account.failed_attempts += 1
        if account.failed_attempts >= MAX_FAILED_ATTEMPTS:
            overflow = account.failed_attempts - MAX_FAILED_ATTEMPTS
            lockout_seconds = min(BASE_LOCKOUT_SECONDS * (2**overflow), MAX_LOCKOUT_SECONDS)
            account.locked_until = datetime.now(timezone.utc) + timedelta(seconds=lockout_seconds)

    def register_success(self, account: UserAccount) -> None:
        account.failed_attempts = 0
        account.locked_until = None
        account.last_login_at = datetime.now(timezone.utc)
