"""Smoke test: the application must construct and launch without error."""

from datetime import datetime, timezone

from PySide6.QtWidgets import QApplication

from app.config import ConfigManager
from database.db_manager import DatabaseManager
from security.auth_session import AuthSession, SessionManager
from security.models import AuthMethod
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


def test_startup_always_opens_dashboard_even_with_a_different_persisted_last_page(tmp_path, monkeypatch):
    """Every login must land on the Dashboard, regardless of which page
    was open when the app was last closed — `config.last_page` is still
    persisted on navigation, but must not be consulted for the startup
    page."""
    monkeypatch.setattr("app.config.get_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")

    app = QApplication.instance() or QApplication([])

    config_manager = ConfigManager()
    config_manager.update(last_page="settings")

    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    window = MainWindow(config_manager, theme_manager)
    try:
        assert window.stack.currentWidget() is window._pages["dashboard"]
    finally:
        window.close()


def test_build_shared_services_all_none_without_session_manager(tmp_path, monkeypatch):
    app, window, db_manager = _build_window(tmp_path, monkeypatch)
    try:
        assert window.session_manager is None
        services = window._build_shared_services()
        assert services == (None, None, None, None, None)
    finally:
        window.close()
        db_manager.close()


def test_build_shared_services_all_none_for_decoy_session(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.get_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")

    app = QApplication.instance() or QApplication([])
    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    db_manager.initialize()
    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    session_manager = SessionManager()
    session_manager.set(
        AuthSession(
            owner_id="owner-1",
            method=AuthMethod.PASSWORD,
            authenticated_at=datetime.now(timezone.utc),
            is_decoy=True,
        )
    )

    window = MainWindow(config_manager, theme_manager, db_manager=db_manager, session_manager=session_manager)
    try:
        assert session_manager.current.vault_key is None
        services = window._build_shared_services()
        assert services == (None, None, None, None, None)
    finally:
        window.close()
        db_manager.close()


def test_build_shared_services_populated_with_real_vault_key(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.get_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")

    app = QApplication.instance() or QApplication([])
    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    db_manager.initialize()
    theme_manager = ThemeManager(app, theme=config_manager.config.theme)
    theme_manager.apply()

    session_manager = SessionManager()
    session_manager.set(
        AuthSession(
            owner_id="owner-1",
            method=AuthMethod.PASSWORD,
            authenticated_at=datetime.now(timezone.utc),
            vault_key=b"\x11" * 32,
        )
    )

    window = MainWindow(config_manager, theme_manager, db_manager=db_manager, session_manager=session_manager)
    try:
        services = window._build_shared_services()
        assert all(service is not None for service in services)
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
