"""Tests for SQLite-backed metadata storage."""

import sqlite3

import pytest

from database.db_manager import DatabaseManager
from metadata.protection import ProtectedMetadata
from metadata.repository import MetadataRepository


def _sample_protected(file_id: str = "file-1") -> ProtectedMetadata:
    return ProtectedMetadata(
        file_id=file_id,
        metadata_version=1,
        nonce=b"\x00" * 12,
        ciphertext=b"encrypted-payload-bytes",
        hmac_tag=b"\x01" * 32,
    )


@pytest.fixture
def repository():
    conn = sqlite3.connect(":memory:")
    return MetadataRepository(conn)


def test_ensure_schema_creates_table(repository):
    assert repository.list_file_ids() == []


def test_save_and_load_round_trip(repository):
    protected = _sample_protected()
    repository.save(protected)

    loaded = repository.load("file-1")
    assert loaded == protected


def test_load_missing_returns_none(repository):
    assert repository.load("does-not-exist") is None


def test_save_upserts_existing_record(repository):
    repository.save(_sample_protected())
    updated = _sample_protected()
    updated.ciphertext = b"new-ciphertext"
    repository.save(updated)

    loaded = repository.load("file-1")
    assert loaded.ciphertext == b"new-ciphertext"
    assert len(repository.list_file_ids()) == 1


def test_delete_removes_record(repository):
    repository.save(_sample_protected())
    assert repository.delete("file-1") is True
    assert repository.load("file-1") is None


def test_delete_missing_returns_false(repository):
    assert repository.delete("does-not-exist") is False


def test_list_file_ids_returns_all(repository):
    repository.save(_sample_protected("file-1"))
    repository.save(_sample_protected("file-2"))
    assert set(repository.list_file_ids()) == {"file-1", "file-2"}


def test_repository_works_against_real_database_manager(tmp_path, monkeypatch):
    db_path = tmp_path / "crypto_usb.db"
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: db_path)

    db_manager = DatabaseManager()
    db_manager.initialize()  # exercises the existing app_meta table too

    repository = MetadataRepository(db_manager.connect())
    repository.save(_sample_protected())

    assert repository.load("file-1") == _sample_protected()
    assert db_manager.get_schema_version() >= 1  # Phase 1 table untouched

    db_manager.close()
