"""Application bootstrap: config, logging, database, theme, and the main window."""

from __future__ import annotations

import sys
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QDialog

from app.config import ConfigManager
from app.error_handling import install_excepthook
from core.constants import APP_NAME, APP_ORGANIZATION, APP_VERSION, LOCAL_OWNER_ID
from core.logger import get_logger, setup_logging
from crypto.secure_cleanup import CleanupReason, cleanup
from database.db_manager import DatabaseManager
from deception.deception_engine import DeceptionEngine
from deception.event_repository import DeceptionEventRepository
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.auth_session import SessionManager
from ui.dialogs.auth_dialog import AuthDialog
from ui.main_window import MainWindow
from ui.theme.theme_manager import ThemeManager
from utils.paths import get_icons_dir


def create_application() -> QApplication:
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_ORGANIZATION)
    # App-wide default icon (taskbar, the auth dialog, every window that
    # doesn't set its own) before any window is shown — `MainWindow` also
    # sets it explicitly for correct taskbar grouping on Windows.
    app.setWindowIcon(QIcon(str(get_icons_dir() / "app_icon.ico")))
    return app


def bootstrap() -> tuple[QApplication, Optional[MainWindow]]:
    """Wire together config, logging, database, authentication, theme, and
    the main window. `window` is None if the user cancels authentication —
    callers must not show or use it in that case.
    """
    config_manager = ConfigManager()

    setup_logging(config_manager.config.log_level)
    logger = get_logger(__name__)
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)
    install_excepthook()

    db_manager = DatabaseManager()
    db_manager.initialize()

    app = create_application()

    deception_event_repository = DeceptionEventRepository(db_manager.connect())
    deception_engine = DeceptionEngine(event_repository=deception_event_repository)

    account_repository = AccountRepository(db_manager.connect())
    auth_controller = AuthController(account_repository, deception_engine=deception_engine, db_manager=db_manager)
    session_manager = SessionManager()

    auth_dialog = AuthDialog(auth_controller, owner_id=LOCAL_OWNER_ID)
    if auth_dialog.exec() != QDialog.DialogCode.Accepted or auth_dialog.session is None:
        logger.info("Authentication was not completed; exiting")
        db_manager.close()
        cleanup(CleanupReason.APPLICATION_EXIT)
        return app, None
    session_manager.set(auth_dialog.session)
    logger.info("Authenticated owner_id=%s via %s", auth_dialog.session.owner_id, auth_dialog.session.method.value)

    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    window = MainWindow(config_manager, theme_manager, db_manager=db_manager, session_manager=session_manager)

    return app, window


def run() -> int:
    app, window = bootstrap()
    if window is None:
        return 0
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run())
