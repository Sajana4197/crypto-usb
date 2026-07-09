"""Tests for SecureBytes in-memory key zeroing."""

import pytest

from crypto.exceptions import KeyDestroyedError
from crypto.secure_bytes import SecureBytes


def test_bytes_returns_original_data():
    sb = SecureBytes(b"secret-key-material")
    assert bytes(sb) == b"secret-key-material"


def test_len_matches_data():
    sb = SecureBytes(b"12345678")
    assert len(sb) == 8


def test_destroy_zeroes_buffer_and_marks_destroyed():
    sb = SecureBytes(b"secret-key-material")
    sb.destroy()
    assert sb.is_destroyed is True
    assert all(b == 0 for b in sb._buffer)


def test_access_after_destroy_raises():
    sb = SecureBytes(b"secret-key-material")
    sb.destroy()
    with pytest.raises(KeyDestroyedError):
        bytes(sb)


def test_destroy_is_idempotent():
    sb = SecureBytes(b"secret-key-material")
    sb.destroy()
    sb.destroy()  # must not raise
    assert sb.is_destroyed is True


def test_repr_never_reveals_data():
    sb = SecureBytes(b"super-secret")
    assert "super-secret" not in repr(sb)
    assert "super-secret" not in str(sb)


def test_context_manager_destroys_on_exit():
    with SecureBytes(b"secret-key-material") as sb:
        assert sb.is_destroyed is False
    assert sb.is_destroyed is True
