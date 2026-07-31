"""Settings page: theme toggle, application preferences, and (for
password accounts) a change-password form backed by the same
`security.auth_controller.AuthController` the sign-in dialog uses, so a
change here goes through the exact same lockout policy as a normal
sign-in attempt.

Also a "Danger Zone" section for permanently deleting the account,
re-confirming the current password first (`AuthController.delete_account`
— same honest, non-deceptive re-authentication as changing the
password, not the login-gate Deception Engine). Deletion is a full
local reset, not just the account row — see that method's docstring
for why. This page only calls it and emits `account_deleted` on
success; it never touches `ui.main_window.MainWindow` or
`ui.dialogs.auth_dialog.AuthDialog` directly — the caller wiring that
signal up is responsible for returning the user to account creation.
"""

from __future__ import annotations

import platform
from typing import Optional

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QFrame,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from security.auth_controller import AuthController
from security.exceptions import (
    AccountLockedError,
    AccountNotFoundError,
    InvalidCredentialsError,
    SecurityError,
    WeakPasswordError,
)
from security.models import AuthMethod, UserAccount
from security.password_hasher import MIN_PASSWORD_LENGTH
from ui.dialogs.recovery_dialog import RecoveryCodeDialog
from ui.pages.base_page import BasePage
from ui.widgets.busy import show_result_popup
from validation.machine_fingerprint import compute_machine_fingerprint

logger = get_logger(__name__)

# How long "Delete Account"'s confirmation Yes button stays disabled,
# counting down in its own label -- long enough that a reflexive
# double-click on the original button can't also dismiss the warning
# meant to make the user actually read it.
_DELETE_CONFIRM_SECONDS = 10

_DELETE_CONFIRM_ENABLED_STYLE = "background-color: #e5484d; color: white; font-weight: 600;"


def arm_countdown_button(button: QPushButton, timer: QTimer, seconds: int) -> None:
    """Disable `button`, label it with a live countdown from `seconds`,
    and re-enable it (styled red) once `timer` has ticked `seconds`
    times. `timer` is expected to already be parented/owned by whatever
    dialog `button` belongs to; this only configures its interval and
    connects its `timeout` -- starting it is the caller's job, done only
    after this setup so the button is already showing "seconds" and
    disabled the instant the dialog appears.

    A free function (not a method) so a test can drive it directly
    against a bare `QPushButton`/`QTimer` — firing `timer.timeout.emit()`
    to simulate ticks — without ever going through a real, blocking
    modal dialog.
    """
    remaining = {"value": seconds}
    button.setEnabled(False)
    button.setText(f"Yes ({seconds})")

    def _tick() -> None:
        remaining["value"] -= 1
        if remaining["value"] <= 0:
            timer.stop()
            button.setText("Yes")
            button.setEnabled(True)
            button.setStyleSheet(_DELETE_CONFIRM_ENABLED_STYLE)
        else:
            button.setText(f"Yes ({remaining['value']})")

    timer.setInterval(1000)
    timer.timeout.connect(_tick)
    timer.start()


class SettingsPage(BasePage):
    theme_changed = Signal(str)
    account_deleted = Signal()

    def __init__(
        self,
        current_theme: str = "dark",
        auth_controller: Optional[AuthController] = None,
        owner_id: Optional[str] = None,
        parent=None,
    ) -> None:
        super().__init__(
            "Settings",
            "Application preferences.",
            parent,
        )
        self._auth_controller = auth_controller
        self._owner_id = owner_id

        form_container = QWidget()
        form = QFormLayout(form_container)
        form.setContentsMargins(0, 0, 0, 0)

        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["dark", "light"])
        self.theme_selector.setMaximumWidth(260)
        self.theme_selector.setCurrentText(current_theme)
        self.theme_selector.currentTextChanged.connect(self.theme_changed.emit)
        form.addRow(QLabel("Theme:"), self.theme_selector)

        self.add_widget(form_container)
        self.add_widget(self._build_machine_identity_section())
        self.add_widget(self._build_password_section())
        self.add_widget(self._build_danger_zone_section())

    def set_theme(self, theme: str) -> None:
        self.theme_selector.blockSignals(True)
        self.theme_selector.setCurrentText(theme)
        self.theme_selector.blockSignals(False)

    # -- Machine identity (Phase 7: pre-enrollment for "bind to a specific
    # machine") ------------------------------------------------------------

    def _build_machine_identity_section(self) -> QWidget:
        """Displays this machine's fingerprint so it can be copied over to
        a *different* machine's Encrypt File page and pasted into "Bind to
        a specific machine" there — no live connection between the two
        machines is ever needed, since `compute_machine_fingerprint` is a
        pure local read (see that function's docstring) and this is just
        a short string the user carries across by any means (typed,
        copy-pasted via a file, even written down).
        """
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 18, 0, 0)

        heading = QLabel("Machine Identity")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt;")
        layout.addWidget(heading)

        note = QLabel(
            "To bind a file (encrypted on a different machine) to this one, copy "
            "this fingerprint and paste it into that machine's \"Bind to a "
            "specific machine\" field on the Encrypt File page."
        )
        note.setWordWrap(True)
        note.setObjectName("dropHint")
        layout.addWidget(note)

        form_container = QWidget()
        form = QFormLayout(form_container)
        form.setContentsMargins(0, 8, 0, 0)

        form.addRow(QLabel("This machine:"), QLabel(platform.node() or "unknown"))

        self.machine_fingerprint_edit = QLineEdit(compute_machine_fingerprint())
        self.machine_fingerprint_edit.setReadOnly(True)
        self.machine_fingerprint_edit.setMinimumWidth(360)
        form.addRow(QLabel("Fingerprint:"), self.machine_fingerprint_edit)

        layout.addWidget(form_container)

        self.copy_fingerprint_button = QPushButton("Copy Fingerprint")
        self.copy_fingerprint_button.setMaximumWidth(200)
        self.copy_fingerprint_button.clicked.connect(self._on_copy_fingerprint_clicked)
        layout.addWidget(self.copy_fingerprint_button)

        return section

    def _on_copy_fingerprint_clicked(self) -> None:
        QApplication.clipboard().setText(self.machine_fingerprint_edit.text())
        show_result_popup(self, "Machine fingerprint copied to clipboard.")

    # -- Change password ------------------------------------------------------

    def _build_password_section(self) -> QWidget:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 18, 0, 0)

        heading = QLabel("Change Password")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt;")
        layout.addWidget(heading)

        account = self._current_account()

        if account is None:
            note = QLabel("Sign in to manage password settings.")
            note.setObjectName("dropHint")
            layout.addWidget(note)
            return section

        if account.auth_method != AuthMethod.PASSWORD:
            note = QLabel(
                "This account uses private-key authentication. Your private "
                "key file is your recovery mechanism; there is no password to change."
            )
            note.setWordWrap(True)
            note.setObjectName("dropHint")
            layout.addWidget(note)
            return section

        form_container = QWidget()
        form = QFormLayout(form_container)
        form.setContentsMargins(0, 8, 0, 0)

        self.current_password_edit = QLineEdit()
        self.current_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.current_password_edit.setMaximumWidth(320)
        form.addRow(QLabel("Current password:"), self.current_password_edit)

        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_edit.setMaximumWidth(320)
        form.addRow(QLabel(f"New password (min {MIN_PASSWORD_LENGTH} characters):"), self.new_password_edit)

        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit.setMaximumWidth(320)
        form.addRow(QLabel("Confirm new password:"), self.confirm_password_edit)

        self.change_password_button = QPushButton("Change Password")
        self.change_password_button.clicked.connect(self._on_change_password_clicked)
        self.change_password_button.setMaximumWidth(200)
        form.addRow("", self.change_password_button)

        layout.addWidget(form_container)

        self.password_status_label = QLabel("")
        self.password_status_label.setWordWrap(True)
        layout.addWidget(self.password_status_label)

        return section

    def _current_account(self) -> Optional[UserAccount]:
        if self._auth_controller is None or self._owner_id is None:
            return None
        try:
            return self._auth_controller.get_account(self._owner_id)
        except AccountNotFoundError:
            return None

    def _on_change_password_clicked(self) -> None:
        self._set_password_status("", error=False)

        new_password = self.new_password_edit.text()
        if new_password != self.confirm_password_edit.text():
            self._set_password_status("New passwords do not match.", error=True, important=True)
            return

        try:
            _account, recovery_code = self._auth_controller.change_password(
                self._owner_id, self.current_password_edit.text(), new_password
            )
        except AccountLockedError as exc:
            self._set_password_status(
                f"Account locked: try again in {exc.seconds_remaining} second(s).", error=True, important=True
            )
            return
        except InvalidCredentialsError as exc:
            self._set_password_status(str(exc), error=True, important=True)
            return
        except WeakPasswordError as exc:
            self._set_password_status(str(exc), error=True, important=True)
            return
        except SecurityError as exc:
            self._set_password_status(str(exc), error=True, important=True)
            return

        self.current_password_edit.clear()
        self.new_password_edit.clear()
        self.confirm_password_edit.clear()
        self._set_password_status("Password changed successfully.", error=False, important=True)
        logger.info("Password changed via Settings page for owner_id=%s", self._owner_id)

        RecoveryCodeDialog(recovery_code, replaces_previous_code=True, parent=self).exec()

    def _set_password_status(self, message: str, error: bool, important: bool = False) -> None:
        self.password_status_label.setStyleSheet(f"color: {'#e5484d' if error else '#3ecf8e'};")
        self.password_status_label.setText(message)
        if important:
            show_result_popup(self, message, ok=not error)

    # -- Danger zone: delete account -------------------------------------------

    def _build_danger_zone_section(self) -> QWidget:
        section = QFrame()
        section.setObjectName("dangerZonePanel")
        layout = QVBoxLayout(section)
        layout.setContentsMargins(14, 12, 14, 12)

        heading = QLabel("Danger Zone")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt; color: #e5484d;")
        layout.addWidget(heading)

        account = self._current_account()

        if account is None:
            note = QLabel("Sign in to manage this account.")
            note.setObjectName("dropHint")
            layout.addWidget(note)
            return section

        if account.auth_method != AuthMethod.PASSWORD:
            note = QLabel(
                "This account uses private-key authentication. Account deletion from "
                "this page is only available for password accounts."
            )
            note.setWordWrap(True)
            note.setObjectName("dropHint")
            layout.addWidget(note)
            return section

        warning = QLabel(
            "Deleting your account is a full reset of this installation: your sign-in "
            "credential, every protected file's metadata, the usage tracking log, and "
            "the deception event history are all permanently removed. This cannot be "
            "undone, and you will be taken to account creation afterward."
        )
        warning.setWordWrap(True)
        warning.setObjectName("dropHint")
        layout.addWidget(warning)

        form_container = QWidget()
        form = QFormLayout(form_container)
        form.setContentsMargins(0, 8, 0, 0)

        self.delete_account_password_edit = QLineEdit()
        self.delete_account_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.delete_account_password_edit.setMaximumWidth(320)
        form.addRow(QLabel("Current password:"), self.delete_account_password_edit)

        self.delete_account_button = QPushButton("Delete Account")
        self.delete_account_button.setStyleSheet(
            "QPushButton { background-color: #e5484d; color: white; font-weight: 600; }"
            "QPushButton:hover { background-color: #c93c40; }"
        )
        self.delete_account_button.clicked.connect(self._on_delete_account_clicked)
        self.delete_account_button.setMaximumWidth(200)
        form.addRow("", self.delete_account_button)

        layout.addWidget(form_container)

        self.delete_account_status_label = QLabel("")
        self.delete_account_status_label.setWordWrap(True)
        layout.addWidget(self.delete_account_status_label)

        return section

    def _on_delete_account_clicked(self) -> None:
        self._set_delete_account_status("", error=False)

        password = self.delete_account_password_edit.text()
        if not password:
            self._set_delete_account_status("Enter your current password.", error=True)
            return

        # Verify the password *before* asking "are you sure?" -- a wrong
        # password should never reach a confirmation prompt for a
        # deletion it was never going to be allowed to perform.
        try:
            self._auth_controller.verify_password(self._owner_id, password)
        except AccountLockedError as exc:
            self._set_delete_account_status(
                f"Account locked: try again in {exc.seconds_remaining} second(s).", error=True, important=True
            )
            return
        except InvalidCredentialsError as exc:
            self._set_delete_account_status(str(exc), error=True, important=True)
            return
        except SecurityError as exc:
            self._set_delete_account_status(str(exc), error=True, important=True)
            return

        if not self._confirm_delete_account():
            return

        try:
            self._auth_controller.delete_account(self._owner_id, password)
        except AccountLockedError as exc:
            self._set_delete_account_status(
                f"Account locked: try again in {exc.seconds_remaining} second(s).", error=True, important=True
            )
            return
        except InvalidCredentialsError as exc:
            self._set_delete_account_status(str(exc), error=True, important=True)
            return
        except SecurityError as exc:
            self._set_delete_account_status(str(exc), error=True, important=True)
            return

        self.delete_account_password_edit.clear()
        logger.warning("Account deleted via Settings page for owner_id=%s", self._owner_id)
        self.account_deleted.emit()

    def _confirm_delete_account(self) -> bool:
        """Show the "are you sure?" prompt with its Yes button disabled
        for `_DELETE_CONFIRM_SECONDS` seconds (counting down in its own
        label, then turning red once enabled) — a reflexive click must
        not be able to confirm an irreversible action nobody has had
        time to actually read yet. `No` is never restricted.
        """
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle("Delete Account")
        dialog.setText(
            "This permanently deletes your account's sign-in credential, protected "
            "file metadata, usage tracking log, and deception event history. This "
            "cannot be undone, and you will be taken to account creation afterward.\n\n"
            "Continue?"
        )
        dialog.addButton(QMessageBox.StandardButton.No)
        yes_button = dialog.addButton(QMessageBox.StandardButton.Yes)
        dialog.setDefaultButton(QMessageBox.StandardButton.No)

        timer = QTimer(dialog)
        arm_countdown_button(yes_button, timer, _DELETE_CONFIRM_SECONDS)

        dialog.exec()
        timer.stop()
        return dialog.clickedButton() is yes_button

    def _set_delete_account_status(self, message: str, error: bool, important: bool = False) -> None:
        self.delete_account_status_label.setStyleSheet(f"color: {'#e5484d' if error else '#3ecf8e'};")
        self.delete_account_status_label.setText(message)
        if important:
            show_result_popup(self, message, ok=not error)
