"""Tests for the Settings page's Change Password section."""

import sqlite3
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QApplication, QDialog

from crypto import rsa_keypair
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from ui.pages.settings_page import SettingsPage


def _app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def mock_result_popup(monkeypatch):
    """`important=True` status calls now pop up a real, blocking
    `QMessageBox` -- autouse so every test in this file is safe by
    default; tests that specifically assert on popup behavior can still
    take this fixture as a parameter to inspect the same mock."""
    mock = MagicMock()
    monkeypatch.setattr("ui.pages.settings_page.show_result_popup", mock)
    return mock


@pytest.fixture
def controller():
    conn = sqlite3.connect(":memory:")
    return AuthController(AccountRepository(conn))


class _FakeRecoveryCodeDialog:
    """Stands in for `RecoveryCodeDialog` so change-password tests don't
    block on a real modal `.exec()` — captures the code it was shown for.
    """

    last_code = None
    last_replaces_previous_code = None

    def __init__(self, recovery_code, replaces_previous_code=False, parent=None):
        _FakeRecoveryCodeDialog.last_code = recovery_code
        _FakeRecoveryCodeDialog.last_replaces_previous_code = replaces_previous_code

    def exec(self):
        return QDialog.DialogCode.Accepted


def test_no_password_section_controls_when_signed_out():
    _app()
    page = SettingsPage()

    assert not hasattr(page, "change_password_button")


def test_password_section_hidden_for_private_key_account(controller, rsa_keypair_fixture):
    _app()
    public_pem = rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)
    controller.register_private_key_account("owner-1", public_pem)

    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    assert not hasattr(page, "change_password_button")


def test_password_section_shown_for_password_account(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    assert hasattr(page, "change_password_button")


def test_change_password_success(controller, monkeypatch):
    _app()
    monkeypatch.setattr("ui.pages.settings_page.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("correct-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("brand-new-password")
    page._on_change_password_clicked()

    assert "success" in page.password_status_label.text().lower()
    controller.authenticate_password("owner-1", "brand-new-password")
    assert page.current_password_edit.text() == ""


def test_change_password_shows_new_recovery_code(controller, monkeypatch):
    _app()
    monkeypatch.setattr("ui.pages.settings_page.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    _account, old_recovery_code = controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("correct-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("brand-new-password")
    page._on_change_password_clicked()

    assert _FakeRecoveryCodeDialog.last_code is not None
    assert _FakeRecoveryCodeDialog.last_code != old_recovery_code
    assert _FakeRecoveryCodeDialog.last_replaces_previous_code is True


def test_change_password_success_pops_up_result(controller, monkeypatch, mock_result_popup):
    monkeypatch.setattr("ui.pages.settings_page.RecoveryCodeDialog", _FakeRecoveryCodeDialog)
    controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("correct-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("brand-new-password")
    page._on_change_password_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs.get("ok", True) is True


def test_change_password_wrong_current_password_pops_up_result(controller, mock_result_popup):
    controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("wrong-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("brand-new-password")
    page._on_change_password_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs["ok"] is False


def test_change_password_wrong_current_password_shows_error(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("wrong-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("brand-new-password")
    page._on_change_password_clicked()

    assert "incorrect" in page.password_status_label.text().lower()


def test_change_password_mismatched_confirmation_shows_error(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("correct-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("different-password")
    page._on_change_password_clicked()

    assert "not match" in page.password_status_label.text().lower()


def test_change_password_weak_new_password_shows_error(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")
    page = SettingsPage(auth_controller=controller, owner_id="owner-1")

    page.current_password_edit.setText("correct-password")
    page.new_password_edit.setText("weak")
    page.confirm_password_edit.setText("weak")
    page._on_change_password_clicked()

    assert page.password_status_label.text() != ""
    controller.authenticate_password("owner-1", "correct-password")


def test_change_password_locks_after_repeated_wrong_current_password(controller):
    _app()
    controller.register_password_account("owner-1", "correct-password")

    for _ in range(MAX_FAILED_ATTEMPTS):
        page = SettingsPage(auth_controller=controller, owner_id="owner-1")
        page.current_password_edit.setText("wrong-password")
        page.new_password_edit.setText("brand-new-password")
        page.confirm_password_edit.setText("brand-new-password")
        page._on_change_password_clicked()

    page = SettingsPage(auth_controller=controller, owner_id="owner-1")
    page.current_password_edit.setText("correct-password")
    page.new_password_edit.setText("brand-new-password")
    page.confirm_password_edit.setText("brand-new-password")
    page._on_change_password_clicked()

    assert "locked" in page.password_status_label.text().lower()
