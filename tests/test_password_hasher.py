"""Tests for scrypt-based password hashing."""

import pytest

from security.exceptions import WeakPasswordError
from security.password_hasher import (
    MIN_PASSWORD_LENGTH,
    RECOVERY_CODE_LENGTH,
    generate_recovery_code,
    hash_password,
    hash_recovery_code,
    verify_password,
    verify_recovery_code,
)


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


# -- Recovery codes -----------------------------------------------------


def test_generate_recovery_code_has_expected_length():
    code = generate_recovery_code()
    assert len(code) == RECOVERY_CODE_LENGTH == 24


def test_generate_recovery_code_is_random():
    assert generate_recovery_code() != generate_recovery_code()


def test_hash_recovery_code_round_trip():
    code = generate_recovery_code()
    credential = hash_recovery_code(code)
    assert verify_recovery_code(code, credential) is True


def test_wrong_recovery_code_fails_verification():
    credential = hash_recovery_code(generate_recovery_code())
    assert verify_recovery_code("not-the-right-code", credential) is False


def test_recovery_code_credential_never_holds_plaintext():
    code = generate_recovery_code()
    credential = hash_recovery_code(code)
    assert code.encode("utf-8") not in credential.digest
    assert code.encode("utf-8") not in credential.salt


def test_hash_recovery_code_uses_random_salt():
    code = generate_recovery_code()
    a = hash_recovery_code(code)
    b = hash_recovery_code(code)
    assert a.salt != b.salt
    assert a.digest != b.digest
