"""Tests for brute-force lockout protection."""

from datetime import datetime, timedelta, timezone

from security.lockout_policy import MAX_FAILED_ATTEMPTS, LockoutPolicy
from security.models import AuthMethod, PasswordCredential, UserAccount


def _account():
    return UserAccount(
        owner_id="owner-1",
        auth_method=AuthMethod.PASSWORD,
        credential=PasswordCredential(salt=b"s", digest=b"d", n=1, r=1, p=1, key_len=1),
        created_at=datetime.now(timezone.utc),
    )


def test_not_locked_initially():
    policy = LockoutPolicy()
    account = _account()
    assert policy.is_locked(account) is False


def test_locks_after_max_failed_attempts():
    policy = LockoutPolicy()
    account = _account()
    for _ in range(MAX_FAILED_ATTEMPTS):
        policy.register_failure(account)

    assert policy.is_locked(account) is True
    assert policy.seconds_remaining(account) > 0


def test_below_threshold_not_locked():
    policy = LockoutPolicy()
    account = _account()
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        policy.register_failure(account)

    assert policy.is_locked(account) is False


def test_success_resets_lockout_state():
    policy = LockoutPolicy()
    account = _account()
    for _ in range(MAX_FAILED_ATTEMPTS):
        policy.register_failure(account)

    policy.register_success(account)

    assert account.failed_attempts == 0
    assert account.locked_until is None
    assert policy.is_locked(account) is False


def test_lockout_duration_escalates_with_repeated_failures():
    policy = LockoutPolicy()
    account = _account()
    for _ in range(MAX_FAILED_ATTEMPTS):
        policy.register_failure(account)
    first_remaining = (account.locked_until - datetime.now(timezone.utc)).total_seconds()

    account.locked_until = None  # simulate the first lockout having expired
    policy.register_failure(account)
    second_remaining = (account.locked_until - datetime.now(timezone.utc)).total_seconds()

    assert second_remaining > first_remaining


def test_expired_lockout_is_not_locked():
    policy = LockoutPolicy()
    account = _account()
    account.failed_attempts = MAX_FAILED_ATTEMPTS
    account.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)

    assert policy.is_locked(account) is False
