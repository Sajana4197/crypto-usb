"""Tests for the Secure Authentication dialog."""

import sqlite3

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog

from crypto import rsa_keypair
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from ui.dialogs.auth_dialog import AuthDialog
from ui.dialogs.recovery_dialog import PasswordResetDialog


def _app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def controller():
    conn = sqlite3.connect(":memory:")
    return AuthController(AccountRepository(conn))


# -- Registration: password ---------------------------------------------


def test_registration_mode_shown_when_no_account(controller):
    _app()
    dialog = AuthDialog(controller, "owner-1")

    assert dialog.windowTitle() == "Create Account"
    assert dialog._password_radio.isChecked() is True


class _FakeRecoveryCodeDialog:
    """Stands in for `RecoveryCodeDialog` so registration/reset tests don't
    block on a real modal `.exec()` — captures the code it was shown for.
    """

    last_code = None

    def __init__(self, recovery_code, replaces_previous_code=False, parent=None):
        _FakeRecoveryCodeDialog.last_code = recovery_code

    def exec(self):
        return QDialog.DialogCode.Accepted


def test_password_registration_success(controller, monkeypatch):
    _app()
    monkeypatch.setattr("ui.dialogs.auth_dialog.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    dialog = AuthDialog(controller, "owner-1")
    dialog._new_password_edit.setText("correct-password")
    dialog._confirm_password_edit.setText("correct-password")

    dialog._on_register_clicked()

    assert dialog.session is not None
    assert dialog.session.owner_id == "owner-1"
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_password_registration_shows_recovery_code_once(controller, monkeypatch):
    _app()
    monkeypatch.setattr("ui.dialogs.auth_dialog.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    dialog = AuthDialog(controller, "owner-1")
    dialog._new_password_edit.setText("correct-password")
    dialog._confirm_password_edit.setText("correct-password")

    dialog._on_register_clicked()

    assert _FakeRecoveryCodeDialog.last_code is not None
    assert len(_FakeRecoveryCodeDialog.last_code) == 24
    account = controller.get_account("owner-1")
    from security.password_hasher import verify_recovery_code

    assert verify_recovery_code(_FakeRecoveryCodeDialog.last_code, account.recovery_code_hash) is True


def test_password_registration_mismatch_shows_error(controller):
    _app()
    dialog = AuthDialog(controller, "owner-1")
    dialog._new_password_edit.setText("correct-password")
    dialog._confirm_password_edit.setText("different-password")

    dialog._on_register_clicked()

    assert dialog.session is None
    assert "not match" in dialog._error_label.text().lower()


def test_password_registration_weak_password_shows_error(controller):
    _app()
    dialog = AuthDialog(controller, "owner-1")
    dialog._new_password_edit.setText("weak")
    dialog._confirm_password_edit.setText("weak")

    dialog._on_register_clicked()

    assert dialog.session is None
    assert dialog._error_label.text() != ""


# -- Registration: private key -------------------------------------------


def test_private_key_registration_success(controller, tmp_path, monkeypatch):
    _app()
    dialog = AuthDialog(controller, "owner-1")
    dialog._key_radio.setChecked(True)
    dialog._key_passphrase_edit.setText("key-passphrase-1")
    dialog._key_passphrase_confirm_edit.setText("key-passphrase-1")

    save_path = tmp_path / "private_key.pem"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **kw: (str(save_path), "")))

    dialog._on_generate_key_clicked()
    assert save_path.exists()

    dialog._on_register_clicked()

    assert dialog.session is not None
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_private_key_registration_rejects_short_passphrase(controller):
    _app()
    dialog = AuthDialog(controller, "owner-1")
    dialog._key_radio.setChecked(True)
    dialog._key_passphrase_edit.setText("short")
    dialog._key_passphrase_confirm_edit.setText("short")

    dialog._on_generate_key_clicked()

    assert dialog._pending_public_key_pem is None
    assert dialog._error_label.text() != ""


def test_private_key_registration_requires_generated_key_first(controller):
    _app()
    dialog = AuthDialog(controller, "owner-1")
    dialog._key_radio.setChecked(True)

    dialog._on_register_clicked()

    assert dialog.session is None
    assert dialog._error_label.text() != ""


# -- Login: password -------------------------------------------------


def test_login_mode_shown_when_account_exists(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    dialog = AuthDialog(controller, "owner-1")

    assert dialog.windowTitle() == "Sign In"


def test_login_success(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    dialog = AuthDialog(controller, "owner-1")
    dialog._login_password_edit.setText("correct-password")
    dialog._on_login_clicked()

    assert dialog.session is not None
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_login_wrong_password_returns_decoy_session_and_closes_dialog(controller):
    # Phase 20: a wrong password against an existing, unlocked account no
    # longer raises or shows an error — it activates the Deception Engine
    # and the dialog closes exactly as it would for a real success, so a
    # wrong-credentials attempt is indistinguishable from a genuine one.
    _app()
    controller.register_password_account("owner-1", "correct-password")

    dialog = AuthDialog(controller, "owner-1")
    dialog._login_password_edit.setText("wrong-password")
    dialog._on_login_clicked()

    assert dialog.session is not None
    assert dialog.session.is_decoy is True
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_login_locked_account_shows_lockout_message(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")
    for _ in range(MAX_FAILED_ATTEMPTS):
        dialog = AuthDialog(controller, "owner-1")
        dialog._login_password_edit.setText("wrong-password")
        dialog._on_login_clicked()

    dialog = AuthDialog(controller, "owner-1")
    dialog._login_password_edit.setText("correct-password")
    dialog._on_login_clicked()

    assert dialog.session is None
    assert "locked" in dialog._error_label.text().lower()


# -- Login: private key -------------------------------------------------


def test_private_key_login_success(controller, tmp_path):
    _app()
    keypair = rsa_keypair.generate_rsa_keypair()
    public_pem = rsa_keypair.serialize_public_key(keypair.public_key)
    private_pem = rsa_keypair.serialize_private_key(keypair.private_key, b"key-passphrase-1")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(private_pem)

    controller.register_private_key_account("owner-1", public_pem)

    dialog = AuthDialog(controller, "owner-1")
    dialog._private_key_file = key_path
    dialog._login_passphrase_edit.setText("key-passphrase-1")
    dialog._on_login_clicked()

    assert dialog.session is not None
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_private_key_login_without_file_shows_error(controller):
    _app()
    keypair = rsa_keypair.generate_rsa_keypair()
    public_pem = rsa_keypair.serialize_public_key(keypair.public_key)
    controller.register_private_key_account("owner-1", public_pem)

    dialog = AuthDialog(controller, "owner-1")
    dialog._login_passphrase_edit.setText("key-passphrase-1")
    dialog._on_login_clicked()

    assert dialog.session is None
    assert dialog._error_label.text() != ""


# -- Forgot password link -------------------------------------------------


class _FakePasswordResetDialog:
    """Stands in for `PasswordResetDialog` so link-wiring tests don't block
    on a real modal `.exec()`.
    """

    def __init__(self, outcome_accepted: bool, succeeded: bool):
        self._outcome_accepted = outcome_accepted
        self.succeeded = succeeded

    def __call__(self, controller, owner_id, parent=None):
        return self

    def exec(self):
        return QDialog.DialogCode.Accepted if self._outcome_accepted else QDialog.DialogCode.Rejected


def test_forgot_password_link_shown_for_password_accounts(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    dialog = AuthDialog(controller, "owner-1")

    assert dialog._forgot_password_button.text() == "Forgot password?"


def test_forgot_password_success_shows_info_message(controller, monkeypatch):
    _app()
    controller.register_password_account("owner-1", "correct-password")
    monkeypatch.setattr(
        "ui.dialogs.auth_dialog.PasswordResetDialog", _FakePasswordResetDialog(outcome_accepted=True, succeeded=True)
    )

    dialog = AuthDialog(controller, "owner-1")
    dialog._login_password_edit.setText("stale-text")
    dialog._on_forgot_password_clicked()

    assert dialog._login_password_edit.text() == ""
    assert "reset" in dialog._error_label.text().lower()


def test_forgot_password_cancelled_leaves_error_untouched(controller, monkeypatch):
    _app()
    controller.register_password_account("owner-1", "correct-password")
    monkeypatch.setattr(
        "ui.dialogs.auth_dialog.PasswordResetDialog",
        _FakePasswordResetDialog(outcome_accepted=False, succeeded=False),
    )

    dialog = AuthDialog(controller, "owner-1")
    dialog._on_forgot_password_clicked()

    assert dialog._error_label.text() == ""


# -- PasswordResetDialog itself --------------------------------------------


def test_password_reset_dialog_success(controller, monkeypatch):
    _app()
    monkeypatch.setattr("ui.dialogs.recovery_dialog.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    _account, recovery_code = controller.register_password_account("owner-1", "correct-password")

    dialog = PasswordResetDialog(controller, "owner-1")
    dialog._recovery_code_edit.setText(recovery_code)
    dialog._new_password_edit.setText("brand-new-password")
    dialog._confirm_password_edit.setText("brand-new-password")

    dialog._on_reset_clicked()

    assert dialog.succeeded is True
    assert dialog.result() == QDialog.DialogCode.Accepted
    controller.authenticate_password("owner-1", "brand-new-password")


def test_password_reset_dialog_shows_new_recovery_code(controller, monkeypatch):
    _app()
    monkeypatch.setattr("ui.dialogs.recovery_dialog.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    _account, old_recovery_code = controller.register_password_account("owner-1", "correct-password")

    dialog = PasswordResetDialog(controller, "owner-1")
    dialog._recovery_code_edit.setText(old_recovery_code)
    dialog._new_password_edit.setText("brand-new-password")
    dialog._confirm_password_edit.setText("brand-new-password")

    dialog._on_reset_clicked()

    assert dialog.new_recovery_code is not None
    assert dialog.new_recovery_code != old_recovery_code
    assert _FakeRecoveryCodeDialog.last_code == dialog.new_recovery_code

    # The old code is single-use: it no longer works for a second reset.
    dialog2 = PasswordResetDialog(controller, "owner-1")
    dialog2._recovery_code_edit.setText(old_recovery_code)
    dialog2._new_password_edit.setText("another-password")
    dialog2._confirm_password_edit.setText("another-password")
    dialog2._on_reset_clicked()
    assert dialog2.succeeded is False


def test_password_reset_dialog_wrong_code_shows_error(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    dialog = PasswordResetDialog(controller, "owner-1")
    dialog._recovery_code_edit.setText("not-the-real-code")
    dialog._new_password_edit.setText("brand-new-password")
    dialog._confirm_password_edit.setText("brand-new-password")

    dialog._on_reset_clicked()

    assert dialog.succeeded is False
    assert dialog._error_label.text() != ""


def test_password_reset_dialog_mismatched_confirmation_shows_error(controller):
    _app()
    _account, recovery_code = controller.register_password_account("owner-1", "correct-password")

    dialog = PasswordResetDialog(controller, "owner-1")
    dialog._recovery_code_edit.setText(recovery_code)
    dialog._new_password_edit.setText("brand-new-password")
    dialog._confirm_password_edit.setText("different-password")

    dialog._on_reset_clicked()

    assert dialog.succeeded is False
    assert "not match" in dialog._error_label.text().lower()


def test_password_reset_dialog_locks_after_repeated_bad_codes(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    for _ in range(MAX_FAILED_ATTEMPTS):
        dialog = PasswordResetDialog(controller, "owner-1")
        dialog._recovery_code_edit.setText("bad-code")
        dialog._new_password_edit.setText("brand-new-password")
        dialog._confirm_password_edit.setText("brand-new-password")
        dialog._on_reset_clicked()
        assert dialog.succeeded is False

    dialog = PasswordResetDialog(controller, "owner-1")
    dialog._recovery_code_edit.setText("bad-code")
    dialog._new_password_edit.setText("brand-new-password")
    dialog._confirm_password_edit.setText("brand-new-password")
    dialog._on_reset_clicked()

    assert dialog.succeeded is False
    assert "locked" in dialog._error_label.text().lower()
