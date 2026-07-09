"""Tests that app.main.bootstrap() gates the main window behind authentication."""

from datetime import datetime, timezone

from PySide6.QtWidgets import QDialog

import app.main as main_module
from security.auth_session import AuthSession
from security.models import AuthMethod


def _patch_paths(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.get_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")


def test_bootstrap_returns_no_window_when_auth_cancelled(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(main_module.AuthDialog, "exec", lambda self: QDialog.DialogCode.Rejected)

    app, window = main_module.bootstrap()

    assert window is None


def test_bootstrap_returns_window_when_auth_succeeds(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)

    fake_session = AuthSession(
        owner_id="local-user", method=AuthMethod.PASSWORD, authenticated_at=datetime.now(timezone.utc)
    )

    def _fake_exec(self):
        self.session = fake_session
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(main_module.AuthDialog, "exec", _fake_exec)

    app, window = main_module.bootstrap()

    try:
        assert window is not None
        assert window.session_manager.current is fake_session
        assert window.session_manager.is_authenticated is True
    finally:
        if window is not None:
            window.close()
            window.db_manager.close()
