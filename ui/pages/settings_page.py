"""Settings page: theme toggle, application preferences, and (for
password accounts) a change-password form backed by the same
`security.auth_controller.AuthController` the sign-in dialog uses, so a
change here goes through the exact same lockout policy as a normal
sign-in attempt.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
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

logger = get_logger(__name__)


class SettingsPage(BasePage):
    theme_changed = Signal(str)

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
        self.add_widget(self._build_password_section())

    def set_theme(self, theme: str) -> None:
        self.theme_selector.blockSignals(True)
        self.theme_selector.setCurrentText(theme)
        self.theme_selector.blockSignals(False)

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
