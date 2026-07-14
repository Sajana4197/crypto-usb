"""Tests for `crypto.secure_cleanup`: the centralized secure-erasure
utility and its four guaranteed cleanup moments."""

import pytest

from crypto.key_manager import KeyManager
from crypto.secure_bytes import SecureBytes
from crypto.secure_cleanup import CleanupReason, cleanup, wipe, wipe_bytearray


# -- wipe_bytearray -----------------------------------------------------


def test_wipe_bytearray_zeroes_every_byte():
    buffer = bytearray(b"top-secret-key-material")
    wipe_bytearray(buffer)
    assert all(byte == 0 for byte in buffer)


def test_wipe_bytearray_preserves_length():
    buffer = bytearray(b"12345678")
    wipe_bytearray(buffer)
    assert len(buffer) == 8


def test_wipe_bytearray_handles_empty_buffer():
    buffer = bytearray(b"")
    wipe_bytearray(buffer)  # must not raise
    assert buffer == bytearray()


# -- wipe: duck-typed dispatch -------------------------------------------


def test_wipe_zeroes_a_bytearray_and_reports_true():
    buffer = bytearray(b"a-temporary-passphrase")
    assert wipe(buffer) is True
    assert all(byte == 0 for byte in buffer)


def test_wipe_destroys_a_secure_bytes_object():
    sb = SecureBytes(b"secret-key-material")
    assert wipe(sb) is True
    assert sb.is_destroyed is True


def test_wipe_destroys_a_managed_key():
    key = KeyManager().generate_fek()
    assert wipe(key) is True
    from crypto.key_manager import KeyState

    assert key.state is KeyState.DESTROYED


def test_wipe_is_safe_on_an_already_destroyed_object():
    sb = SecureBytes(b"secret-key-material")
    sb.destroy()
    assert wipe(sb) is True  # idempotent destroy(), must not raise


def test_wipe_returns_false_for_none():
    assert wipe(None) is False


def test_wipe_returns_false_for_immutable_bytes():
    # Python cannot zero an immutable `bytes` object in place.
    assert wipe(b"cannot-be-wiped") is False


def test_wipe_returns_false_for_a_plain_object_without_destroy():
    assert wipe(object()) is False


# -- cleanup: the guaranteed, logged cleanup pass -------------------------


def test_cleanup_wipes_every_sensitive_object_and_returns_count():
    buffer_a = bytearray(b"buffer-a")
    buffer_b = bytearray(b"buffer-b")
    sb = SecureBytes(b"secret")

    wiped = cleanup(CleanupReason.SUCCESSFUL_VIEW, buffer_a, buffer_b, sb)

    assert wiped == 3
    assert all(byte == 0 for byte in buffer_a)
    assert all(byte == 0 for byte in buffer_b)
    assert sb.is_destroyed is True


def test_cleanup_with_nothing_sensitive_still_runs_and_returns_zero():
    assert cleanup(CleanupReason.VALIDATION_FAILURE) == 0


def test_cleanup_skips_unwipeable_objects_but_still_wipes_the_rest():
    buffer = bytearray(b"wipeable")
    wiped = cleanup(CleanupReason.FAILED_AUTHENTICATION, None, b"immutable", buffer)

    assert wiped == 1
    assert all(byte == 0 for byte in buffer)


@pytest.mark.parametrize(
    "reason",
    [
        CleanupReason.SUCCESSFUL_VIEW,
        CleanupReason.FAILED_AUTHENTICATION,
        CleanupReason.VALIDATION_FAILURE,
        CleanupReason.APPLICATION_EXIT,
    ],
)
def test_cleanup_accepts_every_defined_reason(reason):
    assert cleanup(reason) == 0


def test_cleanup_logs_the_reason_name(caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="crypto.secure_cleanup"):
        cleanup(CleanupReason.APPLICATION_EXIT)

    assert "APPLICATION_EXIT" in caplog.text
