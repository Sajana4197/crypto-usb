"""Tests for SQLite database initialization."""

import os

import pytest

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


# -- SQLCipher-backed encryption at rest (Phase 23) --------------------------


def test_database_file_is_not_plain_sqlite(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    manager = DatabaseManager()
    manager.initialize()
    manager.close()

    header = db_path.read_bytes()[:16]
    assert not header.startswith(b"SQLite format 3")


def test_reopening_the_same_database_reuses_the_persisted_key(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    first = DatabaseManager()
    first.initialize()
    first.close()

    second = DatabaseManager()
    second.initialize()  # must not raise: the same key file unlocks the same file

    assert second.get_schema_version() == SCHEMA_VERSION
    second.close()


def test_wrong_key_file_raises_a_clear_runtime_error(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    manager = DatabaseManager()
    manager.initialize()
    manager.close()

    # Corrupt the persisted key file so it no longer matches the one the
    # database was actually encrypted under.
    from database.file_key import get_vault_key_path

    get_vault_key_path().write_bytes(os.urandom(32))

    with pytest.raises(RuntimeError, match="Failed to unlock the encrypted database"):
        DatabaseManager().connect()


def test_missing_key_file_after_initialization_raises_a_clear_runtime_error(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    manager = DatabaseManager()
    manager.initialize()
    manager.close()

    from database.file_key import get_vault_key_path

    get_vault_key_path().unlink()

    with pytest.raises(RuntimeError, match="Failed to unlock the encrypted database"):
        DatabaseManager().connect()
