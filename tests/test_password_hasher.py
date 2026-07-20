"""Tests for scrypt-based password hashing."""

import pytest

from security.exceptions import WeakPasswordError
from security.password_hasher import (
    KEY_LEN_BYTES,
    MIN_PASSWORD_LENGTH,
    RECOVERY_CODE_LENGTH,
    SALT_LEN_BYTES,
    derive_recovery_key,
    derive_vault_key,
    derive_vault_key_from_bytes,
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


def test_hash_password_generates_key_wrap_salt():
    credential = hash_password("correct horse battery staple")
    assert credential.key_wrap_salt is not None
    assert len(credential.key_wrap_salt) == SALT_LEN_BYTES


def test_hash_password_key_wrap_salt_is_random():
    a = hash_password("same password value")
    b = hash_password("same password value")
    assert a.key_wrap_salt != b.key_wrap_salt


def test_credential_from_dict_without_key_wrap_salt_defaults_to_none():
    credential = hash_password("round trip password")
    data = credential.to_dict()
    del data["key_wrap_salt"]
    restored = type(credential).from_dict(data)
    assert restored.key_wrap_salt is None


# -- Vault key derivation -------------------------------------------------


def test_derive_vault_key_round_trip():
    salt = hash_password("some password").key_wrap_salt
    a = derive_vault_key("some password", salt)
    b = derive_vault_key("some password", salt)
    assert a == b
    assert len(a) == KEY_LEN_BYTES


def test_derive_vault_key_differs_by_salt():
    a = derive_vault_key("some password", b"\x01" * SALT_LEN_BYTES)
    b = derive_vault_key("some password", b"\x02" * SALT_LEN_BYTES)
    assert a != b


def test_derive_vault_key_differs_from_password_digest():
    credential = hash_password("shared-secret-password")
    vault_key = derive_vault_key("shared-secret-password", credential.key_wrap_salt)
    assert vault_key != credential.digest


def test_derive_vault_key_from_bytes_round_trip():
    salt = b"\x03" * SALT_LEN_BYTES
    secret = b"private-key-pem-bytes|passphrase-bytes"
    a = derive_vault_key_from_bytes(secret, salt)
    b = derive_vault_key_from_bytes(secret, salt)
    assert a == b
    assert len(a) == KEY_LEN_BYTES


def test_derive_vault_key_from_bytes_differs_by_secret():
    salt = b"\x04" * SALT_LEN_BYTES
    a = derive_vault_key_from_bytes(b"secret-one", salt)
    b = derive_vault_key_from_bytes(b"secret-two", salt)
    assert a != b


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


def test_hash_recovery_code_generates_key_wrap_salt():
    credential = hash_recovery_code(generate_recovery_code())
    assert credential.key_wrap_salt is not None
    assert len(credential.key_wrap_salt) == SALT_LEN_BYTES


def test_hash_recovery_code_key_wrap_salt_is_random():
    code = generate_recovery_code()
    a = hash_recovery_code(code)
    b = hash_recovery_code(code)
    assert a.key_wrap_salt != b.key_wrap_salt


# -- Recovery key derivation ---------------------------------------------


def test_derive_recovery_key_round_trip():
    code = generate_recovery_code()
    salt = hash_recovery_code(code).key_wrap_salt
    a = derive_recovery_key(code, salt)
    b = derive_recovery_key(code, salt)
    assert a == b
    assert len(a) == KEY_LEN_BYTES


def test_derive_recovery_key_differs_by_salt():
    code = generate_recovery_code()
    a = derive_recovery_key(code, b"\x01" * SALT_LEN_BYTES)
    b = derive_recovery_key(code, b"\x02" * SALT_LEN_BYTES)
    assert a != b


def test_derive_recovery_key_differs_by_code():
    salt = b"\x05" * SALT_LEN_BYTES
    a = derive_recovery_key("FIRST-RECOVERY-CODE-VALUE", salt)
    b = derive_recovery_key("SECOND-RECOVERY-CODE-VALUE", salt)
    assert a != b


def test_derive_recovery_key_differs_from_recovery_code_digest():
    code = generate_recovery_code()
    credential = hash_recovery_code(code)
    recovery_key = derive_recovery_key(code, credential.key_wrap_salt)
    assert recovery_key != credential.digest
