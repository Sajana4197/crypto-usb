"""Smoke test: the application must construct and launch without error."""

from PySide6.QtWidgets import QApplication

from app.config import ConfigManager
from database.db_manager import DatabaseManager
from ui.main_window import MainWindow
from ui.navigation.navigation_panel import DEFAULT_NAV_ITEMS
from ui.theme.theme_manager import ThemeManager


def _build_window(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.get_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")

    app = QApplication.instance() or QApplication([])

    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    db_manager.initialize()

    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    window = MainWindow(config_manager, theme_manager)
    return app, window, db_manager


def test_main_window_constructs_and_shows(tmp_path, monkeypatch):
    app, window, db_manager = _build_window(tmp_path, monkeypatch)
    try:
        window.show()
        app.processEvents()
        assert window.isVisible()
        assert "Cryptographic Security Layer for USB Storage" in window.windowTitle()
    finally:
        window.close()
        db_manager.close()


def test_all_pages_are_reachable(tmp_path, monkeypatch):
    app, window, db_manager = _build_window(tmp_path, monkeypatch)
    try:
        for item in DEFAULT_NAV_ITEMS:
            window._navigate_to(item.page_id)
            app.processEvents()
            assert window.stack.currentWidget() is window._pages[item.page_id]
    finally:
        window.close()
        db_manager.close()


def test_theme_toggle_updates_stylesheet(tmp_path, monkeypatch):
    app, window, db_manager = _build_window(tmp_path, monkeypatch)
    try:
        starting_theme = window._theme_manager.current_theme
        window._toggle_theme()
        assert window._theme_manager.current_theme != starting_theme
        assert app.styleSheet() != ""
    finally:
        window.close()
        db_manager.close()
