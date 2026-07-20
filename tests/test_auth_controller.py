"""Tests for the Authentication Controller orchestration."""

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from app.protection_keys import (
    load_or_create_metadata_protection_keys,
    load_or_create_tracking_protection_keys,
    unwrap_vault_master_key_via_password,
    unwrap_vault_master_key_via_recovery,
)
from crypto import rsa_keypair
from crypto.secure_cleanup import CleanupReason
from database.db_manager import DatabaseManager
from deception.deception_engine import DeceptionEngine
from deception.triggers import DeceptionTrigger
from security import password_hasher
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


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")
    manager = DatabaseManager()
    manager.initialize()
    yield manager
    manager.close()


@pytest.fixture
def controller_with_db(db_manager):
    return AuthController(AccountRepository(db_manager.connect()), db_manager=db_manager)


@pytest.fixture
def deception_engine():
    return MagicMock(spec=DeceptionEngine)


@pytest.fixture
def controller_with_engine(deception_engine):
    conn = sqlite3.connect(":memory:")
    return AuthController(AccountRepository(conn), deception_engine=deception_engine)


def test_register_and_authenticate_password(controller):
    controller.register_password_account("owner-1", "correct-password")
    session = controller.authenticate_password("owner-1", "correct-password")

    assert session.owner_id == "owner-1"
    assert session.method == AuthMethod.PASSWORD


def test_authenticate_password_wrong_password_returns_decoy_session(controller):
    controller.register_password_account("owner-1", "correct-password")

    session = controller.authenticate_password("owner-1", "wrong-password")

    assert session.is_decoy is True
    assert session.owner_id == "owner-1"
    assert session.method == AuthMethod.PASSWORD


def test_authenticate_password_wrong_password_still_counts_as_failed_attempt(controller):
    controller.register_password_account("owner-1", "correct-password")

    controller.authenticate_password("owner-1", "wrong-password")

    account = controller.get_account("owner-1")
    assert account.failed_attempts == 1


def test_authenticate_password_correct_password_is_not_a_decoy(controller):
    controller.register_password_account("owner-1", "correct-password")

    session = controller.authenticate_password("owner-1", "correct-password")

    assert session.is_decoy is False


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


def test_authenticate_private_key_wrong_key_returns_decoy_session(
    controller, rsa_keypair_fixture, other_rsa_keypair_fixture
):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)

    controller.register_private_key_account("owner-1", public_pem)
    session = controller.authenticate_private_key("owner-1", wrong_private_pem, PASSPHRASE)

    assert session.is_decoy is True
    assert session.owner_id == "owner-1"
    assert session.method == AuthMethod.PRIVATE_KEY


# -- Deception Engine activation on wrong credentials -----------------------


def test_wrong_password_activates_deception_engine(controller_with_engine, deception_engine):
    controller_with_engine.register_password_account("owner-1", "correct-password")

    controller_with_engine.authenticate_password("owner-1", "wrong-password")

    deception_engine.activate.assert_called_once_with(DeceptionTrigger.WRONG_CREDENTIALS)


def test_wrong_private_key_activates_deception_engine(
    controller_with_engine, deception_engine, rsa_keypair_fixture, other_rsa_keypair_fixture
):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)
    controller_with_engine.register_private_key_account("owner-1", public_pem)

    controller_with_engine.authenticate_private_key("owner-1", wrong_private_pem, PASSPHRASE)

    deception_engine.activate.assert_called_once_with(DeceptionTrigger.WRONG_CREDENTIALS)


def test_correct_password_does_not_activate_deception_engine(controller_with_engine, deception_engine):
    controller_with_engine.register_password_account("owner-1", "correct-password")

    controller_with_engine.authenticate_password("owner-1", "correct-password")

    deception_engine.activate.assert_not_called()


def test_account_locks_after_max_failed_attempts(controller):
    controller.register_password_account("owner-1", "correct-password")

    for _ in range(MAX_FAILED_ATTEMPTS):
        session = controller.authenticate_password("owner-1", "wrong-password")
        assert session.is_decoy is True

    with pytest.raises(AccountLockedError):
        controller.authenticate_password("owner-1", "correct-password")


def test_locked_account_rejects_even_correct_password(controller):
    controller.register_password_account("owner-1", "correct-password")
    for _ in range(MAX_FAILED_ATTEMPTS):
        session = controller.authenticate_password("owner-1", "wrong-password")
        assert session.is_decoy is True

    with pytest.raises(AccountLockedError) as exc_info:
        controller.authenticate_password("owner-1", "correct-password")
    assert exc_info.value.seconds_remaining > 0


def test_successful_login_resets_failed_attempts(controller):
    controller.register_password_account("owner-1", "correct-password")
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        session = controller.authenticate_password("owner-1", "wrong-password")
        assert session.is_decoy is True

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
        session = controller.authenticate_password("owner-1", "wrong-password")

    assert session.is_decoy is True
    mock_cleanup.assert_called_once_with(CleanupReason.FAILED_AUTHENTICATION)


def test_failed_private_key_authentication_runs_secure_cleanup(controller, rsa_keypair_fixture, other_rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)
    controller.register_private_key_account("owner-1", public_pem)

    with patch("security.auth_controller.cleanup") as mock_cleanup:
        session = controller.authenticate_private_key("owner-1", wrong_private_pem, PASSPHRASE)

    assert session.is_decoy is True
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


# -- Vault key derivation on authentication ----------------------------------


def test_authenticate_password_success_populates_vault_key(controller):
    controller.register_password_account("owner-1", "correct-password")

    session = controller.authenticate_password("owner-1", "correct-password")

    assert session.vault_key is not None
    assert len(session.vault_key) == 32


def test_authenticate_password_wrong_password_decoy_has_no_vault_key(controller):
    controller.register_password_account("owner-1", "correct-password")

    session = controller.authenticate_password("owner-1", "wrong-password")

    assert session.is_decoy is True
    assert session.vault_key is None


def test_authenticate_password_vault_key_is_deterministic_per_credential(controller):
    controller.register_password_account("owner-1", "correct-password")

    first = controller.authenticate_password("owner-1", "correct-password")
    second = controller.authenticate_password("owner-1", "correct-password")

    assert first.vault_key == second.vault_key


def test_authenticate_password_self_heals_missing_key_wrap_salt(controller):
    controller.register_password_account("owner-1", "correct-password")
    account = controller.get_account("owner-1")
    account.credential.key_wrap_salt = None
    controller._repository.save(account)

    session = controller.authenticate_password("owner-1", "correct-password")

    assert session.vault_key is not None
    healed_account = controller.get_account("owner-1")
    assert healed_account.credential.key_wrap_salt is not None


def test_authenticate_private_key_success_populates_vault_key(controller, rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    private_pem = rsa_keypair.serialize_private_key(rsa_keypair_fixture.private_key, PASSPHRASE)
    controller.register_private_key_account("owner-1", public_pem)

    session = controller.authenticate_private_key("owner-1", private_pem, PASSPHRASE)

    assert session.vault_key is not None
    assert len(session.vault_key) == 32


def test_authenticate_private_key_wrong_key_decoy_has_no_vault_key(
    controller, rsa_keypair_fixture, other_rsa_keypair_fixture
):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)
    controller.register_private_key_account("owner-1", public_pem)

    session = controller.authenticate_private_key("owner-1", wrong_private_pem, PASSPHRASE)

    assert session.is_decoy is True
    assert session.vault_key is None


def test_authenticate_private_key_self_heals_missing_key_wrap_salt(controller, rsa_keypair_fixture):
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    private_pem = rsa_keypair.serialize_private_key(rsa_keypair_fixture.private_key, PASSPHRASE)
    controller.register_private_key_account("owner-1", public_pem)
    account = controller.get_account("owner-1")
    account.credential.key_wrap_salt = None
    controller._repository.save(account)

    session = controller.authenticate_private_key("owner-1", private_pem, PASSPHRASE)

    assert session.vault_key is not None
    healed_account = controller.get_account("owner-1")
    assert healed_account.credential.key_wrap_salt is not None


# -- Change password ---------------------------------------------------------


def test_change_password_success(controller):
    controller.register_password_account("owner-1", "correct-password")

    controller.change_password("owner-1", "correct-password", "new-correct-password")

    old_password_session = controller.authenticate_password("owner-1", "correct-password")
    assert old_password_session.is_decoy is True
    session = controller.authenticate_password("owner-1", "new-correct-password")
    assert session.owner_id == "owner-1"
    assert session.is_decoy is False


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

    old_password_session = controller.authenticate_password("owner-1", "correct-password")
    assert old_password_session.is_decoy is True
    session = controller.authenticate_password("owner-1", "new-correct-password")
    assert session.owner_id == "owner-1"
    assert session.is_decoy is False


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


# -- Vault Master Key establishment (Phase 2) -----------------------------


def test_register_password_account_without_db_manager_does_not_raise(controller):
    # `controller` has no `db_manager`; registration must still work exactly
    # as before, just without establishing a Vault Master Key.
    controller.register_password_account("owner-1", "correct-password")


def test_register_password_account_establishes_vault_master_key(controller_with_db, db_manager):
    account, recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")

    assert account.credential.key_wrap_salt is not None
    assert account.recovery_code_hash.key_wrap_salt is not None

    vault_key = password_hasher.derive_vault_key("correct-password", account.credential.key_wrap_salt)
    recovery_key = password_hasher.derive_recovery_key(
        recovery_code, account.recovery_code_hash.key_wrap_salt
    )

    vmk_via_password = unwrap_vault_master_key_via_password(db_manager, vault_key)
    vmk_via_recovery = unwrap_vault_master_key_via_recovery(db_manager, recovery_key)

    assert vmk_via_password is not None
    assert vmk_via_password == vmk_via_recovery


# -- Vault Master Key rewrap on password change (Phase 3) -----------------


def _vault_key_for(account, password):
    return password_hasher.derive_vault_key(password, account.credential.key_wrap_salt)


def test_change_password_preserves_metadata_and_tracking_protection_keys(controller_with_db, db_manager):
    """Regression test for the reported bug: after a password change, the
    tamper-evident usage log must still verify against the same HMAC key
    -- changing the password must not silently mint new protection keys
    and orphan everything already encrypted/HMAC'd under the old ones."""
    account, _recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")
    old_vault_key = _vault_key_for(account, "correct-password")
    original_metadata = load_or_create_metadata_protection_keys(db_manager, old_vault_key)
    original_tracking = load_or_create_tracking_protection_keys(db_manager, old_vault_key)

    account, _new_recovery_code = controller_with_db.change_password(
        "owner-1", "correct-password", "new-correct-password"
    )
    new_vault_key = _vault_key_for(account, "new-correct-password")

    rotated_metadata = load_or_create_metadata_protection_keys(db_manager, new_vault_key)
    rotated_tracking = load_or_create_tracking_protection_keys(db_manager, new_vault_key)

    assert rotated_metadata.encryption_key == original_metadata.encryption_key
    assert rotated_metadata.hmac_key == original_metadata.hmac_key
    assert rotated_tracking.encryption_key == original_tracking.encryption_key
    assert rotated_tracking.hmac_key == original_tracking.hmac_key


def test_change_password_updates_recovery_slot_to_new_code(controller_with_db, db_manager):
    account, _recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")

    account, new_recovery_code = controller_with_db.change_password(
        "owner-1", "correct-password", "new-correct-password"
    )

    new_vault_key = _vault_key_for(account, "new-correct-password")
    new_recovery_key = password_hasher.derive_recovery_key(
        new_recovery_code, account.recovery_code_hash.key_wrap_salt
    )

    vmk_via_password = unwrap_vault_master_key_via_password(db_manager, new_vault_key)
    vmk_via_recovery = unwrap_vault_master_key_via_recovery(db_manager, new_recovery_key)

    assert vmk_via_password is not None
    assert vmk_via_password == vmk_via_recovery


def test_change_password_without_db_manager_does_not_raise(controller):
    controller.register_password_account("owner-1", "correct-password")

    # `controller` has no `db_manager`; must behave exactly as before.
    controller.change_password("owner-1", "correct-password", "new-correct-password")


# -- Vault Master Key rewrap on recovery-code reset (Phase 4) -------------


def test_reset_password_with_recovery_code_preserves_metadata_and_tracking_protection_keys(
    controller_with_db, db_manager
):
    """This is the exact scenario originally reported: resetting the
    password via the forgotten-password/recovery-code flow (no old
    password known) must still leave the tamper-evident usage log
    verifiable afterwards, not show a false "HMAC mismatch" because a
    fresh, unrelated tracking key got minted on next login."""
    account, recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")
    old_vault_key = _vault_key_for(account, "correct-password")
    original_metadata = load_or_create_metadata_protection_keys(db_manager, old_vault_key)
    original_tracking = load_or_create_tracking_protection_keys(db_manager, old_vault_key)

    account, _new_recovery_code = controller_with_db.reset_password_with_recovery_code(
        "owner-1", recovery_code, "new-correct-password"
    )
    new_vault_key = _vault_key_for(account, "new-correct-password")

    rotated_metadata = load_or_create_metadata_protection_keys(db_manager, new_vault_key)
    rotated_tracking = load_or_create_tracking_protection_keys(db_manager, new_vault_key)

    assert rotated_metadata.encryption_key == original_metadata.encryption_key
    assert rotated_metadata.hmac_key == original_metadata.hmac_key
    assert rotated_tracking.encryption_key == original_tracking.encryption_key
    assert rotated_tracking.hmac_key == original_tracking.hmac_key


def test_reset_password_with_recovery_code_updates_recovery_slot_to_new_code(controller_with_db, db_manager):
    account, recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")

    account, new_recovery_code = controller_with_db.reset_password_with_recovery_code(
        "owner-1", recovery_code, "new-correct-password"
    )

    new_vault_key = _vault_key_for(account, "new-correct-password")
    new_recovery_key = password_hasher.derive_recovery_key(
        new_recovery_code, account.recovery_code_hash.key_wrap_salt
    )

    vmk_via_password = unwrap_vault_master_key_via_password(db_manager, new_vault_key)
    vmk_via_recovery = unwrap_vault_master_key_via_recovery(db_manager, new_recovery_key)

    assert vmk_via_password is not None
    assert vmk_via_password == vmk_via_recovery


def test_reset_password_with_recovery_code_old_recovery_key_no_longer_unlocks_vmk(controller_with_db, db_manager):
    """Confirms the recovery slot actually rotates -- the old, now-spent
    recovery code must not still be able to unlock the VMK afterwards."""
    account, recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")
    old_recovery_key = password_hasher.derive_recovery_key(recovery_code, account.recovery_code_hash.key_wrap_salt)

    controller_with_db.reset_password_with_recovery_code("owner-1", recovery_code, "new-correct-password")

    assert unwrap_vault_master_key_via_recovery(db_manager, old_recovery_key) is None


def test_reset_password_with_recovery_code_without_db_manager_does_not_raise(controller):
    _account, recovery_code = controller.register_password_account("owner-1", "correct-password")

    # `controller` has no `db_manager`; must behave exactly as before.
    controller.reset_password_with_recovery_code("owner-1", recovery_code, "new-correct-password")


# -- Legacy (pre-VMK) account self-heal ------------------------------------


def _make_legacy_account(controller_with_db):
    """Simulate an account created before Phase 1: no `key_wrap_salt` on
    either the credential or the recovery-code hash, and no VMK/slots
    ever established, matching what a pre-fix install's `app_meta` and
    `accounts` rows would actually look like."""
    account, recovery_code = controller_with_db.register_password_account("owner-1", "correct-password")
    account.credential.key_wrap_salt = None
    account.recovery_code_hash.key_wrap_salt = None
    controller_with_db._repository.save(account)
    return recovery_code


def test_change_password_on_legacy_account_does_not_raise_and_establishes_vmk(controller_with_db, db_manager):
    _recovery_code = _make_legacy_account(controller_with_db)

    account, new_recovery_code = controller_with_db.change_password(
        "owner-1", "correct-password", "new-correct-password"
    )

    new_vault_key = _vault_key_for(account, "new-correct-password")
    new_recovery_key = password_hasher.derive_recovery_key(
        new_recovery_code, account.recovery_code_hash.key_wrap_salt
    )
    assert unwrap_vault_master_key_via_password(db_manager, new_vault_key) is not None
    assert unwrap_vault_master_key_via_recovery(db_manager, new_recovery_key) is not None


def test_reset_password_with_recovery_code_on_legacy_account_does_not_raise_and_establishes_vmk(
    controller_with_db, db_manager
):
    recovery_code = _make_legacy_account(controller_with_db)

    account, new_recovery_code = controller_with_db.reset_password_with_recovery_code(
        "owner-1", recovery_code, "new-correct-password"
    )

    new_vault_key = _vault_key_for(account, "new-correct-password")
    new_recovery_key = password_hasher.derive_recovery_key(
        new_recovery_code, account.recovery_code_hash.key_wrap_salt
    )
    assert unwrap_vault_master_key_via_password(db_manager, new_vault_key) is not None
    assert unwrap_vault_master_key_via_recovery(db_manager, new_recovery_key) is not None
