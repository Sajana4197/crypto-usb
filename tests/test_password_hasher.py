"""Tests for scrypt-based password hashing."""

import pytest

from security.exceptions import WeakPasswordError
from security.password_hasher import MIN_PASSWORD_LENGTH, hash_password, verify_password


def test_hash_password_round_trip():
    credential = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", credential) is True


def test_wrong_password_fails_verification():
    credential = hash_password("correct horse battery staple")
    assert verify_password("wrong password", credential) is False


def test_hash_password_rejects_short_password():
    with pytest.raises(WeakPasswordError):
        hash_password("short")


def test_hash_password_uses_random_salt():
    a = hash_password("same password value")
    b = hash_password("same password value")
    assert a.salt != b.salt
    assert a.digest != b.digest


def test_credential_never_holds_plaintext_password():
    password = "UNMISTAKABLE_PLAINTEXT_MARKER_998877"
    credential = hash_password(password)
    assert password.encode("utf-8") not in credential.digest
    assert password.encode("utf-8") not in credential.salt


def test_minimum_length_boundary():
    hash_password("a" * MIN_PASSWORD_LENGTH)  # must not raise
    with pytest.raises(WeakPasswordError):
        hash_password("a" * (MIN_PASSWORD_LENGTH - 1))


def test_credential_to_dict_from_dict_round_trip():
    credential = hash_password("round trip password")
    restored = type(credential).from_dict(credential.to_dict())
    assert restored == credential
