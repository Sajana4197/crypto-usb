"""Secure Authentication dialog: account creation and sign-in.

Shows a "Create Account" flow (password or private key) when no local
account exists yet, or a "Sign In" flow matching the stored account's
method otherwise. Every credential field uses password echo mode, and
nothing sensitive — password, passphrase, or private key bytes — is
ever logged or held longer than the call that needs it. On success,
`self.session` is set to the validated `AuthSession` and the dialog is
accepted; the caller (see `app.main.bootstrap`) must not proceed until
that has happened.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from crypto import rsa_keypair
from security.auth_controller import AuthController
from security.auth_session import AuthSession
from security.exceptions import (
    AccountLockedError,
    AccountNotFoundError,
    InvalidCredentialsError,
    SecurityError,
    WeakPasswordError,
)
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from security.models import AuthMethod
from security.password_hasher import MIN_PASSWORD_LENGTH
from ui.dialogs.recovery_dialog import PasswordResetDialog, RecoveryCodeDialog

logger = get_logger(__name__)


class AuthDialog(QDialog):
    """Modal login/registration dialog. Sets `self.session` on success."""

    def __init__(self, controller: AuthController, owner_id: str, parent=None) -> None:
        super().__init__(parent)
        self._controller = controller
        self._owner_id = owner_id
        self.session: Optional[AuthSession] = None

        self._pending_public_key_pem: Optional[bytes] = None
        self._pending_private_key_pem: Optional[bytes] = None
        self._private_key_file: Optional[Path] = None

        self.setModal(True)
        self.setMinimumWidth(420)

        self._layout = QVBoxLayout(self)

        if controller.has_account(owner_id):
            self.setWindowTitle("Sign In")
            self._build_login_ui()
        else:
            self.setWindowTitle("Create Account")
            self._build_registration_ui()

    # -- Registration --------------------------------------------------------

    def _build_registration_ui(self) -> None:
        heading = QLabel("Create your local account")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt;")
        self._layout.addWidget(heading)

        method_row = QHBoxLayout()
        self._password_radio = QRadioButton("Password")
        self._key_radio = QRadioButton("Private Key")
        self._password_radio.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self._password_radio)
        group.addButton(self._key_radio)
        method_row.addWidget(self._password_radio)
        method_row.addWidget(self._key_radio)
        method_row.addStretch(1)
        self._layout.addLayout(method_row)

        self._register_stack = QStackedWidget()
        self._register_stack.addWidget(self._build_password_registration_page())
        self._register_stack.addWidget(self._build_key_registration_page())
        self._layout.addWidget(self._register_stack)

        self._password_radio.toggled.connect(
            lambda checked: checked and self._register_stack.setCurrentIndex(0)
        )
        self._key_radio.toggled.connect(
            lambda checked: checked and self._register_stack.setCurrentIndex(1)
        )

        self._error_label = QLabel("")
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet("color: #e5484d;")
        self._layout.addWidget(self._error_label)

        self._layout.addWidget(self._build_action_row("Create Account", self._on_register_clicked))

    def _build_password_registration_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)

        layout.addWidget(QLabel(f"Password (minimum {MIN_PASSWORD_LENGTH} characters):"))
        self._new_password_edit = QLineEdit()
        self._new_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._new_password_edit)

        layout.addWidget(QLabel("Confirm password:"))
        self._confirm_password_edit = QLineEdit()
        self._confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._confirm_password_edit)

        return page

    def _build_key_registration_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)

        intro_label = QLabel(
            "A new RSA-4096 key pair will be generated. The private key is "
            "encrypted with the passphrase below and saved to a file you "
            "choose — the application does not keep a copy of it."
        )
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        layout.addWidget(QLabel("Private key passphrase:"))
        self._key_passphrase_edit = QLineEdit()
        self._key_passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._key_passphrase_edit)

        layout.addWidget(QLabel("Confirm passphrase:"))
        self._key_passphrase_confirm_edit = QLineEdit()
        self._key_passphrase_confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._key_passphrase_confirm_edit)

        self._generate_key_button = QPushButton("Generate Key Pair && Choose Save Location...")
        self._generate_key_button.clicked.connect(self._on_generate_key_clicked)
        layout.addWidget(self._generate_key_button)

        self._key_status_label = QLabel("No key pair generated yet.")
        self._key_status_label.setWordWrap(True)
        layout.addWidget(self._key_status_label)

        return page

    def _on_generate_key_clicked(self) -> None:
        passphrase = self._key_passphrase_edit.text()
        confirm = self._key_passphrase_confirm_edit.text()

        if len(passphrase) < MIN_PASSWORD_LENGTH:
            self._show_error(f"Passphrase must be at least {MIN_PASSWORD_LENGTH} characters long.")
            return
        if passphrase != confirm:
            self._show_error("Passphrases do not match.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Private Key", "private_key.pem", "PEM Files (*.pem)")
        if not path:
            return

        keypair = rsa_keypair.generate_rsa_keypair()
        private_pem = rsa_keypair.serialize_private_key(keypair.private_key, passphrase.encode("utf-8"))
        public_pem = rsa_keypair.serialize_public_key(keypair.public_key)
        Path(path).write_bytes(private_pem)

        self._pending_private_key_pem = private_pem
        self._pending_public_key_pem = public_pem
        self._private_key_file = Path(path)
        self._key_status_label.setText(f"Key pair generated. Private key saved to:\n{path}")
        self._clear_error()
        logger.info("Generated new RSA key pair for registration; private key saved to %s", path)

    def _on_register_clicked(self) -> None:
        self._clear_error()
        try:
            if self._password_radio.isChecked():
                self._register_password()
            else:
                self._register_private_key()
        except SecurityError as exc:
            self._show_error(str(exc))

    def _register_password(self) -> None:
        password = self._new_password_edit.text()
        confirm = self._confirm_password_edit.text()

        if password != confirm:
            self._show_error("Passwords do not match.")
            return

        try:
            _account, recovery_code = self._controller.register_password_account(self._owner_id, password)
        except WeakPasswordError as exc:
            self._show_error(str(exc))
            return

        # Validate credentials before continuing, rather than assuming
        # registration implies a valid session.
        self.session = self._controller.authenticate_password(self._owner_id, password)

        RecoveryCodeDialog(recovery_code, parent=self).exec()
        self.accept()

    def _register_private_key(self) -> None:
        if self._pending_public_key_pem is None or self._pending_private_key_pem is None:
            self._show_error("Generate a key pair before creating the account.")
            return

        self._controller.register_private_key_account(self._owner_id, self._pending_public_key_pem)

        # Validate credentials before continuing: prove possession of the
        # just-generated private key via the same challenge/response path
        # a later sign-in would use.
        self.session = self._controller.authenticate_private_key(
            self._owner_id, self._pending_private_key_pem, self._key_passphrase_edit.text().encode("utf-8")
        )
        self.accept()

    # -- Login ---------------------------------------------------------------

    def _build_login_ui(self) -> None:
        heading = QLabel("Sign in")
        heading.setStyleSheet("font-weight: 600; font-size: 12pt;")
        self._layout.addWidget(heading)

        account = self._controller.get_account(self._owner_id)
        self._login_method = account.auth_method

        if self._login_method == AuthMethod.PASSWORD:
            self._layout.addWidget(self._build_password_login_page())
        else:
            self._layout.addWidget(self._build_key_login_page())

        self._error_label = QLabel("")
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet("color: #e5484d;")
        self._layout.addWidget(self._error_label)

        self._layout.addWidget(self._build_action_row("Sign In", self._on_login_clicked))

    def _build_password_login_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)

        layout.addWidget(QLabel("Password:"))
        self._login_password_edit = QLineEdit()
        self._login_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._login_password_edit.returnPressed.connect(self._on_login_clicked)
        layout.addWidget(self._login_password_edit)

        forgot_row = QHBoxLayout()
        forgot_row.addStretch(1)
        self._forgot_password_button = QPushButton("Forgot password?")
        self._forgot_password_button.setFlat(True)
        self._forgot_password_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._forgot_password_button.clicked.connect(self._on_forgot_password_clicked)
        forgot_row.addWidget(self._forgot_password_button)
        layout.addLayout(forgot_row)

        return page

    def _on_forgot_password_clicked(self) -> None:
        dialog = PasswordResetDialog(self._controller, self._owner_id, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.succeeded:
            self._login_password_edit.clear()
            self._show_info("Password reset. Sign in with your new password.")

    def _build_key_login_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)

        row = QHBoxLayout()
        self._choose_key_button = QPushButton("Browse Private Key File...")
        self._choose_key_button.clicked.connect(self._on_choose_login_key_clicked)
        row.addWidget(self._choose_key_button)
        layout.addLayout(row)

        self._login_key_path_label = QLabel("No file selected.")
        self._login_key_path_label.setWordWrap(True)
        layout.addWidget(self._login_key_path_label)

        layout.addWidget(QLabel("Passphrase:"))
        self._login_passphrase_edit = QLineEdit()
        self._login_passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._login_passphrase_edit.returnPressed.connect(self._on_login_clicked)
        layout.addWidget(self._login_passphrase_edit)

        return page

    def _on_choose_login_key_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Private Key File", "", "PEM Files (*.pem)")
        if path:
            self._private_key_file = Path(path)
            self._login_key_path_label.setText(path)

    def _on_login_clicked(self) -> None:
        self._clear_error()
        try:
            if self._login_method == AuthMethod.PASSWORD:
                self.session = self._controller.authenticate_password(
                    self._owner_id, self._login_password_edit.text()
                )
            else:
                if self._private_key_file is None:
                    self._show_error("Select your private key file first.")
                    return
                self.session = self._controller.authenticate_private_key(
                    self._owner_id,
                    self._private_key_file.read_bytes(),
                    self._login_passphrase_edit.text().encode("utf-8"),
                )
        except AccountLockedError as exc:
            self._show_error(f"Account locked: try again in {exc.seconds_remaining} second(s).")
            return
        except InvalidCredentialsError as exc:
            attempts_left = self._attempts_remaining()
            suffix = f" ({attempts_left} attempt(s) remaining before lockout)" if attempts_left is not None else ""
            self._show_error(f"{exc}{suffix}")
            return
        except AccountNotFoundError as exc:
            self._show_error(str(exc))
            return

        self.accept()

    def _attempts_remaining(self) -> Optional[int]:
        try:
            account = self._controller.get_account(self._owner_id)
        except AccountNotFoundError:
            return None
        return max(0, MAX_FAILED_ATTEMPTS - account.failed_attempts)

    # -- Shared ----------------------------------------------------------

    def _build_action_row(self, accept_label: str, on_accept) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addStretch(1)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

        accept_button = QPushButton(accept_label)
        accept_button.setObjectName("primaryButton")
        accept_button.clicked.connect(on_accept)
        layout.addWidget(accept_button)

        return row

    def _show_error(self, message: str) -> None:
        self._error_label.setStyleSheet("color: #e5484d;")
        self._error_label.setText(message)
        logger.warning("Auth dialog error for owner_id=%s: %s", self._owner_id, message)

    def _show_info(self, message: str) -> None:
        self._error_label.setStyleSheet("color: #3ecf8e;")
        self._error_label.setText(message)

    def _clear_error(self) -> None:
        self._error_label.setStyleSheet("color: #e5484d;")
        self._error_label.setText("")
