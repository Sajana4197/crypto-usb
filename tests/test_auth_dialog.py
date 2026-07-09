"""Tests for the Secure Authentication dialog."""

import sqlite3

import pytest
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog

from crypto import rsa_keypair
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from ui.dialogs.auth_dialog import AuthDialog


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


def test_password_registration_success(controller):
    _app()
    dialog = AuthDialog(controller, "owner-1")
    dialog._new_password_edit.setText("correct-password")
    dialog._confirm_password_edit.setText("correct-password")

    dialog._on_register_clicked()

    assert dialog.session is not None
    assert dialog.session.owner_id == "owner-1"
    assert dialog.result() == QDialog.DialogCode.Accepted


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


def test_login_wrong_password_shows_attempts_remaining(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    dialog = AuthDialog(controller, "owner-1")
    dialog._login_password_edit.setText("wrong-password")
    dialog._on_login_clicked()

    assert dialog.session is None
    assert "remaining" in dialog._error_label.text().lower()


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
