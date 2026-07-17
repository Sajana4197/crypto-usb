"""Tests for the vault-key-wrapped persistence of metadata/tracking
protection keys."""

from __future__ import annotations

import base64
import os

from app.protection_keys import (
    load_or_create_metadata_protection_keys,
    load_or_create_tracking_protection_keys,
)
from database.db_manager import DatabaseManager

VAULT_KEY = os.urandom(32)
OTHER_VAULT_KEY = os.urandom(32)


def _db_manager(tmp_path, monkeypatch):
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")
    db_manager = DatabaseManager()
    db_manager.initialize()
    return db_manager


def test_metadata_keys_generated_and_persisted_round_trip(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        keys_first = load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)
        keys_second = load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)

        assert keys_first.encryption_key == keys_second.encryption_key
        assert keys_first.hmac_key == keys_second.hmac_key
    finally:
        db_manager.close()


def test_tracking_keys_generated_and_persisted_round_trip(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        keys_first = load_or_create_tracking_protection_keys(db_manager, VAULT_KEY)
        keys_second = load_or_create_tracking_protection_keys(db_manager, VAULT_KEY)

        assert keys_first.encryption_key == keys_second.encryption_key
        assert keys_first.hmac_key == keys_second.hmac_key
    finally:
        db_manager.close()


def test_metadata_keys_stored_not_in_cleartext(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        keys = load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)

        conn = db_manager.connect()
        rows = conn.execute("SELECT key, value FROM app_meta").fetchall()
        stored_values = {row[1] for row in rows}
        assert base64.b64encode(keys.encryption_key).decode("ascii") not in stored_values
        assert base64.b64encode(keys.hmac_key).decode("ascii") not in stored_values
    finally:
        db_manager.close()


def test_metadata_keys_wrong_vault_key_falls_back_to_fresh_keys(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        original = load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)
        regenerated = load_or_create_metadata_protection_keys(db_manager, OTHER_VAULT_KEY)

        assert regenerated.encryption_key != original.encryption_key
        assert regenerated.hmac_key != original.hmac_key
    finally:
        db_manager.close()


def test_old_cleartext_format_falls_back_to_fresh_keys(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        conn = db_manager.connect()
        # Simulate a pre-Phase-21 install: raw base64 key bytes, no nonce/ciphertext split.
        conn.execute(
            "INSERT OR REPLACE INTO app_meta (key, value) VALUES (?, ?)",
            ("metadata_protection_encryption_key", base64.b64encode(os.urandom(32)).decode("ascii")),
        )
        conn.execute(
            "INSERT OR REPLACE INTO app_meta (key, value) VALUES (?, ?)",
            ("metadata_protection_hmac_key", base64.b64encode(os.urandom(32)).decode("ascii")),
        )
        conn.commit()

        keys = load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)

        assert keys.encryption_key is not None
        assert keys.hmac_key is not None
    finally:
        db_manager.close()


def test_tracking_keys_wrong_vault_key_falls_back_to_fresh_keys(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        original = load_or_create_tracking_protection_keys(db_manager, VAULT_KEY)
        regenerated = load_or_create_tracking_protection_keys(db_manager, OTHER_VAULT_KEY)

        assert regenerated.encryption_key != original.encryption_key
        assert regenerated.hmac_key != original.hmac_key
    finally:
        db_manager.close()
