"""Tests for the configuration system."""

from app.config import AppConfig, ConfigManager


def test_app_config_defaults():
    config = AppConfig()
    assert config.theme == "dark"
    assert config.window_width == 1200
    assert config.window_height == 760


def test_config_manager_creates_file_when_missing(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    monkeypatch.setattr("app.config.get_config_path", lambda: config_path)

    manager = ConfigManager()
    assert manager.config == AppConfig()
    assert not config_path.exists()  # not written until save()/update()

    manager.update(theme="light")
    assert config_path.exists()
    assert manager.config.theme == "light"


def test_config_manager_round_trip(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    monkeypatch.setattr("app.config.get_config_path", lambda: config_path)

    manager = ConfigManager()
    manager.update(theme="light", last_page="settings")

    reloaded = ConfigManager()
    assert reloaded.config.theme == "light"
    assert reloaded.config.last_page == "settings"


def test_config_manager_ignores_unknown_and_corrupt_data(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text("not valid json", encoding="utf-8")
    monkeypatch.setattr("app.config.get_config_path", lambda: config_path)

    manager = ConfigManager()
    assert manager.config == AppConfig()
