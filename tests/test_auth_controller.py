"""Tests for the Authentication Controller orchestration."""

import sqlite3
from unittest.mock import patch

import pytest

from crypto import rsa_keypair
from crypto.secure_cleanup import CleanupReason
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.exceptions import (
    AccountAlreadyExistsError,
    AccountLockedError,
    AccountNotFoundError,
    InvalidCredentialsError,
    WeakPasswordError,
)
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from security.models import AuthMethod

PASSPHRASE = b"strong-passphrase-1"


@pytest.fixture
def controller():
    conn = sqlite3.connect(":memory:")
    return AuthController(AccountRepository(conn))


def test_register_and_authenticate_password(controller):
    controller.register_password_account("owner-1", "correct-password")
    session = controller.authenticate_password("owner-1", "correct-password")

    assert session.owner_id == "owner-1"
    assert session.method == AuthMethod.PASSWORD


def test_authenticate_password_wrong_password_raises(controller):
    controller.register_password_account("owner-1", "correct-password")
    with pytest.raises(InvalidCredentialsError):
        controller.authenticate_password("owner-1", "wrong-password")


def test_register_password_twice_raises(controller):
    controller.register_password_account("owner-1", "correct-password")
    with pytest.raises(AccountAlreadyExistsError):
        controller.register_password_account("owner-1", "another-password")


def test_register_weak_password_raises(controller):
    with pytest.raises(WeakPasswordError):
        controller.register_password_account("owner-1", "weak")


def test_authenticate_missing_account_raises(controller):
    with pytest.raises(AccountNotFoundError):
        controller.authenticate_password("nobody", "whatever-password")


def test_register_and_authenticate_private_key(controller, rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    private_pem = rsa_keypair.serialize_private_key(rsa_keypair_fixture.private_key, PASSPHRASE)

    controller.register_private_key_account("owner-1", public_pem)
    session = controller.authenticate_private_key("owner-1", private_pem, PASSPHRASE)

    assert session.owner_id == "owner-1"
    assert session.method == AuthMethod.PRIVATE_KEY


def test_authenticate_private_key_wrong_key_raises(controller, rsa_keypair_fixture, other_rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)

    controller.register_private_key_account("owner-1", public_pem)
    with pytest.raises(InvalidCredentialsError):
        controller.authenticate_private_key("owner-1", wrong_private_pem, PASSPHRASE)


def test_account_locks_after_max_failed_attempts(controller):
    controller.register_password_account("owner-1", "correct-password")

    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(InvalidCredentialsError):
            controller.authenticate_password("owner-1", "wrong-password")

    with pytest.raises(AccountLockedError):
        controller.authenticate_password("owner-1", "correct-password")


def test_locked_account_rejects_even_correct_password(controller):
    controller.register_password_account("owner-1", "correct-password")
    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(InvalidCredentialsError):
            controller.authenticate_password("owner-1", "wrong-password")

    with pytest.raises(AccountLockedError) as exc_info:
        controller.authenticate_password("owner-1", "correct-password")
    assert exc_info.value.seconds_remaining > 0


def test_successful_login_resets_failed_attempts(controller):
    controller.register_password_account("owner-1", "correct-password")
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(InvalidCredentialsError):
            controller.authenticate_password("owner-1", "wrong-password")

    controller.authenticate_password("owner-1", "correct-password")

    account = controller.get_account("owner-1")
    assert account.failed_attempts == 0
    assert account.locked_until is None


def test_wrong_method_counts_as_failed_attempt(controller, rsa_keypair_fixture):
    controller.register_password_account("owner-1", "correct-password")
    private_pem = rsa_keypair.serialize_private_key(rsa_keypair_fixture.private_key, PASSPHRASE)

    with pytest.raises(InvalidCredentialsError):
        controller.authenticate_private_key("owner-1", private_pem, PASSPHRASE)

    account = controller.get_account("owner-1")
    assert account.failed_attempts == 1


# -- Secure cleanup runs after every failed authentication -----------------


def test_failed_password_authentication_runs_secure_cleanup(controller):
    controller.register_password_account("owner-1", "correct-password")

    with patch("security.auth_controller.cleanup") as mock_cleanup:
        with pytest.raises(InvalidCredentialsError):
            controller.authenticate_password("owner-1", "wrong-password")

    mock_cleanup.assert_called_once_with(CleanupReason.FAILED_AUTHENTICATION)


def test_failed_private_key_authentication_runs_secure_cleanup(controller, rsa_keypair_fixture, other_rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)
    controller.register_private_key_account("owner-1", public_pem)

    with patch("security.auth_controller.cleanup") as mock_cleanup:
        with pytest.raises(InvalidCredentialsError):
            controller.authenticate_private_key("owner-1", wrong_private_pem, PASSPHRASE)

    mock_cleanup.assert_called_once_with(CleanupReason.FAILED_AUTHENTICATION)


def test_successful_authentication_does_not_run_failure_cleanup(controller):
    controller.register_password_account("owner-1", "correct-password")

    with patch("security.auth_controller.cleanup") as mock_cleanup:
        controller.authenticate_password("owner-1", "correct-password")

    mock_cleanup.assert_not_called()
