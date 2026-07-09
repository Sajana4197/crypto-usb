"""Application bootstrap: config, logging, database, theme, and the main window."""

from __future__ import annotations

import sys
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog

from app.config import ConfigManager
from core.constants import APP_NAME, APP_ORGANIZATION, APP_VERSION, LOCAL_OWNER_ID
from core.logger import get_logger, setup_logging
from database.db_manager import DatabaseManager
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.auth_session import SessionManager
from ui.dialogs.auth_dialog import AuthDialog
from ui.main_window import MainWindow
from ui.theme.theme_manager import ThemeManager


def create_application() -> QApplication:
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_ORGANIZATION)
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

    db_manager = DatabaseManager()
    db_manager.initialize()

    app = create_application()

    account_repository = AccountRepository(db_manager.connect())
    auth_controller = AuthController(account_repository)
    session_manager = SessionManager()

    auth_dialog = AuthDialog(auth_controller, owner_id=LOCAL_OWNER_ID)
    if auth_dialog.exec() != QDialog.DialogCode.Accepted or auth_dialog.session is None:
        logger.info("Authentication was not completed; exiting")
        db_manager.close()
        return app, None
    session_manager.set(auth_dialog.session)
    logger.info("Authenticated owner_id=%s via %s", auth_dialog.session.owner_id, auth_dialog.session.method.value)

    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    window = MainWindow(config_manager, theme_manager)
    window.db_manager = db_manager  # kept alive with the window for later phases
    window.session_manager = session_manager  # for later access-control/validation phases

    return app, window


def run() -> int:
    app, window = bootstrap()
    if window is None:
        return 0
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run())
