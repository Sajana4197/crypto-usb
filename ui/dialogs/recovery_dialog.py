"""Password recovery dialogs: showing a one-time recovery code at
registration, and using one later to reset a forgotten password.

Both are small modal dialogs used by `ui.dialogs.auth_dialog.AuthDialog`
and talk only to `security.auth_controller.AuthController` — the same
controller the main sign-in flow uses, so a recovery-code reset goes
through the exact same brute-force lockout policy as a normal sign-in.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from core.logger import get_logger
from security.auth_controller import AuthController
from security.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    SecurityError,
    WeakPasswordError,
)
from security.password_hasher import MIN_PASSWORD_LENGTH

logger = get_logger(__name__)


class RecoveryCodeDialog(QDialog):
    """Shown exactly once, right after password registration succeeds."""

    def __init__(self, recovery_code: str, replaces_previous_code: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle("Save Your Recovery Code")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        heading = QLabel("Save this recovery code somewhere safe.")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt;")
        layout.addWidget(heading)

        warning_text = (
            "It won't be shown again. If you forget your password, this is "
            "the only way to reset it without losing access to your account."
        )
        if replaces_previous_code:
            warning_text += " Your previous recovery code no longer works."
        warning = QLabel(warning_text)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        code_edit = QLineEdit(recovery_code)
        code_edit.setReadOnly(True)
        code_edit.setStyleSheet("font-family: monospace; font-size: 12pt;")
        layout.addWidget(code_edit)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        done_button = QPushButton("I've saved it")
        done_button.setObjectName("primaryButton")
        done_button.clicked.connect(self.accept)
        button_row.addWidget(done_button)
        layout.addLayout(button_row)


class PasswordResetDialog(QDialog):
    """"Forgot password?" flow: enter the recovery code and a new password."""

    def __init__(self, controller: AuthController, owner_id: str, parent=None) -> None:
        super().__init__(parent)
        self._controller = controller
        self._owner_id = owner_id
        self.succeeded = False
        self.new_recovery_code: Optional[str] = None

        self.setModal(True)
        self.setWindowTitle("Reset Password")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        heading = QLabel("Reset your password with your recovery code")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt;")
        layout.addWidget(heading)

        layout.addWidget(QLabel("Recovery code:"))
        self._recovery_code_edit = QLineEdit()
        layout.addWidget(self._recovery_code_edit)

        layout.addWidget(QLabel(f"New password (minimum {MIN_PASSWORD_LENGTH} characters):"))
        self._new_password_edit = QLineEdit()
        self._new_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._new_password_edit)

        layout.addWidget(QLabel("Confirm new password:"))
        self._confirm_password_edit = QLineEdit()
        self._confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._confirm_password_edit)

        self._error_label = QLabel("")
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet("color: #e5484d;")
        layout.addWidget(self._error_label)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)
        reset_button = QPushButton("Reset Password")
        reset_button.setObjectName("primaryButton")
        reset_button.clicked.connect(self._on_reset_clicked)
        button_row.addWidget(reset_button)
        layout.addLayout(button_row)

    def _on_reset_clicked(self) -> None:
        self._error_label.setText("")

        new_password = self._new_password_edit.text()
        confirm_password = self._confirm_password_edit.text()
        if new_password != confirm_password:
            self._error_label.setText("Passwords do not match.")
            return

        try:
            _account, new_recovery_code = self._controller.reset_password_with_recovery_code(
                self._owner_id, self._recovery_code_edit.text(), new_password
            )
        except AccountLockedError as exc:
            self._error_label.setText(f"Account locked: try again in {exc.seconds_remaining} second(s).")
            return
        except InvalidCredentialsError as exc:
            self._error_label.setText(str(exc))
            return
        except WeakPasswordError as exc:
            self._error_label.setText(str(exc))
            return
        except SecurityError as exc:
            self._error_label.setText(str(exc))
            return

        self.succeeded = True
        self.new_recovery_code = new_recovery_code
        logger.info("Password reset via recovery code succeeded for owner_id=%s", self._owner_id)

        RecoveryCodeDialog(new_recovery_code, replaces_previous_code=True, parent=self).exec()
        self.accept()
