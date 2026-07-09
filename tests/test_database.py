"""Tests for SQLite database initialization."""

from core.constants import SCHEMA_VERSION
from database.db_manager import DatabaseManager


def test_initialize_creates_database_file(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    manager = DatabaseManager()
    manager.initialize()

    assert db_path.exists()
    manager.close()


def test_initialize_sets_schema_version(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    manager = DatabaseManager()
    manager.initialize()

    assert manager.get_schema_version() == SCHEMA_VERSION
    manager.close()


def test_initialize_is_idempotent(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    manager = DatabaseManager()
    manager.initialize()
    manager.initialize()  # must not raise or duplicate rows

    with manager.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM app_meta WHERE key = 'schema_version'")
        assert cur.fetchone()["n"] == 1
    manager.close()
