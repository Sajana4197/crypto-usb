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


# -- Recovery code issuance at registration ---------------------------------


def test_registration_returns_recovery_code(controller):
    account, recovery_code = controller.register_password_account("owner-1", "correct-password")

    assert account.owner_id == "owner-1"
    assert len(recovery_code) == 24
    assert account.recovery_code_hash is not None
    assert account.recovery_code_hash.digest != recovery_code.encode("utf-8")


def test_private_key_account_has_no_recovery_code_hash(controller, rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    account = controller.register_private_key_account("owner-1", public_pem)

    assert account.recovery_code_hash is None


# -- Change password ---------------------------------------------------------


def test_change_password_success(controller):
    controller.register_password_account("owner-1", "correct-password")

    controller.change_password("owner-1", "correct-password", "new-correct-password")

    with pytest.raises(InvalidCredentialsError):
        controller.authenticate_password("owner-1", "correct-password")
    session = controller.authenticate_password("owner-1", "new-correct-password")
    assert session.owner_id == "owner-1"


def test_change_password_rotates_recovery_code(controller):
    _account, old_recovery_code = controller.register_password_account("owner-1", "correct-password")

    _account, new_recovery_code = controller.change_password(
        "owner-1", "correct-password", "new-correct-password"
    )

    assert new_recovery_code != old_recovery_code
    assert len(new_recovery_code) == 24

    # The old code no longer works...
    with pytest.raises(InvalidCredentialsError):
        controller.reset_password_with_recovery_code("owner-1", old_recovery_code, "another-password")

    # ...but the new one does.
    controller.reset_password_with_recovery_code("owner-1", new_recovery_code, "another-password")
    controller.authenticate_password("owner-1", "another-password")


def test_change_password_wrong_current_password_raises(controller):
    controller.register_password_account("owner-1", "correct-password")

    with pytest.raises(InvalidCredentialsError):
        controller.change_password("owner-1", "wrong-password", "new-correct-password")


def test_change_password_weak_new_password_raises(controller):
    controller.register_password_account("owner-1", "correct-password")

    with pytest.raises(WeakPasswordError):
        controller.change_password("owner-1", "correct-password", "weak")

    # Old password still works: the weak new password was never applied.
    controller.authenticate_password("owner-1", "correct-password")


def test_change_password_locks_after_repeated_wrong_current_password(controller):
    controller.register_password_account("owner-1", "correct-password")

    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(InvalidCredentialsError):
            controller.change_password("owner-1", "wrong-password", "new-correct-password")

    with pytest.raises(AccountLockedError):
        controller.change_password("owner-1", "correct-password", "new-correct-password")


# -- Reset password with recovery code ---------------------------------------


def test_reset_password_with_recovery_code_success(controller):
    _account, recovery_code = controller.register_password_account("owner-1", "correct-password")

    controller.reset_password_with_recovery_code("owner-1", recovery_code, "new-correct-password")

    with pytest.raises(InvalidCredentialsError):
        controller.authenticate_password("owner-1", "correct-password")
    session = controller.authenticate_password("owner-1", "new-correct-password")
    assert session.owner_id == "owner-1"


def test_reset_password_with_recovery_code_wrong_code_raises(controller):
    controller.register_password_account("owner-1", "correct-password")

    with pytest.raises(InvalidCredentialsError):
        controller.reset_password_with_recovery_code("owner-1", "not-the-real-code", "new-correct-password")


def test_reset_password_with_recovery_code_locks_after_repeated_bad_codes(controller):
    controller.register_password_account("owner-1", "correct-password")

    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(InvalidCredentialsError):
            controller.reset_password_with_recovery_code("owner-1", "bad-code", "new-correct-password")

    with pytest.raises(AccountLockedError):
        controller.reset_password_with_recovery_code("owner-1", "bad-code", "new-correct-password")


def test_reset_password_with_recovery_code_weak_new_password_raises(controller):
    _account, recovery_code = controller.register_password_account("owner-1", "correct-password")

    with pytest.raises(WeakPasswordError):
        controller.reset_password_with_recovery_code("owner-1", recovery_code, "weak")


def test_reset_password_against_private_key_account_raises(controller, rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    controller.register_private_key_account("owner-1", public_pem)

    with pytest.raises(InvalidCredentialsError):
        controller.reset_password_with_recovery_code("owner-1", "any-code", "new-correct-password")


def test_reset_password_with_recovery_code_is_single_use(controller):
    _account, old_recovery_code = controller.register_password_account("owner-1", "correct-password")

    _account, new_recovery_code = controller.reset_password_with_recovery_code(
        "owner-1", old_recovery_code, "new-correct-password"
    )

    assert new_recovery_code != old_recovery_code
    assert len(new_recovery_code) == 24

    # The just-used code no longer works...
    with pytest.raises(InvalidCredentialsError):
        controller.reset_password_with_recovery_code("owner-1", old_recovery_code, "another-password")

    # ...but the newly issued one does.
    controller.reset_password_with_recovery_code("owner-1", new_recovery_code, "another-password")
    controller.authenticate_password("owner-1", "another-password")
