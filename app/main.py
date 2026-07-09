"""Application bootstrap: config, logging, database, theme, and the main window."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.config import ConfigManager
from core.constants import APP_NAME, APP_ORGANIZATION, APP_VERSION
from core.logger import get_logger, setup_logging
from database.db_manager import DatabaseManager
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


def bootstrap() -> tuple[QApplication, MainWindow]:
    """Wire together config, logging, database, theme and the main window."""
    config_manager = ConfigManager()

    setup_logging(config_manager.config.log_level)
    logger = get_logger(__name__)
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)

    db_manager = DatabaseManager()
    db_manager.initialize()

    app = create_application()

    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    window = MainWindow(config_manager, theme_manager)
    window.db_manager = db_manager  # kept alive with the window for later phases

    return app, window


def run() -> int:
    app, window = bootstrap()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run())
