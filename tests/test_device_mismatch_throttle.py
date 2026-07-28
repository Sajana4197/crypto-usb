"""Tests for device-mismatch rate-limiting (Phase 4)."""

from datetime import datetime, timedelta, timezone

from security.device_mismatch_throttle import DeviceMismatchThrottle
from security.lockout_policy import MAX_FAILED_ATTEMPTS


def test_not_locked_initially():
    throttle = DeviceMismatchThrottle()
    assert throttle.is_locked("file-1") is False


def test_locks_after_max_mismatches():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS):
        throttle.register_mismatch("file-1")

    assert throttle.is_locked("file-1") is True
    assert throttle.seconds_remaining("file-1") > 0


def test_below_threshold_not_locked():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        throttle.register_mismatch("file-1")

    assert throttle.is_locked("file-1") is False


def test_success_resets_lockout_state():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS):
        throttle.register_mismatch("file-1")

    throttle.register_success("file-1")

    assert throttle.is_locked("file-1") is False
    assert throttle.seconds_remaining("file-1") == 0


def test_success_on_never_seen_file_is_a_no_op():
    """A file that was never registered as mismatched has nothing to
    reset -- this must not raise or fabricate state."""
    throttle = DeviceMismatchThrottle()
    throttle.register_success("never-seen-file")
    assert throttle.is_locked("never-seen-file") is False


def test_lockout_duration_escalates_with_repeated_mismatches():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS):
        throttle.register_mismatch("file-1")
    first_remaining = throttle.seconds_remaining("file-1")

    throttle._state["file-1"].locked_until = None  # simulate the first lockout having expired
    throttle.register_mismatch("file-1")
    second_remaining = throttle.seconds_remaining("file-1")

    assert second_remaining > first_remaining


def test_expired_lockout_is_not_locked():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS):
        throttle.register_mismatch("file-1")
    throttle._state["file-1"].locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)

    assert throttle.is_locked("file-1") is False


# -- Per-file_id isolation ----------------------------------------------------


def test_lockout_never_affects_a_different_file_id():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS):
        throttle.register_mismatch("file-locked")

    assert throttle.is_locked("file-locked") is True
    assert throttle.is_locked("file-unrelated") is False
    assert throttle.seconds_remaining("file-unrelated") == 0


def test_mismatches_on_different_files_do_not_accumulate_together():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        throttle.register_mismatch("file-a")
        throttle.register_mismatch("file-b")

    # Neither file individually reached the threshold.
    assert throttle.is_locked("file-a") is False
    assert throttle.is_locked("file-b") is False


def test_success_on_one_file_does_not_reset_another_files_lockout():
    throttle = DeviceMismatchThrottle()
    for _ in range(MAX_FAILED_ATTEMPTS):
        throttle.register_mismatch("file-a")

    throttle.register_success("file-b")

    assert throttle.is_locked("file-a") is True
