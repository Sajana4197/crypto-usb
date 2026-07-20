"""Tests for the vault-key-wrapped persistence of metadata/tracking
protection keys."""

from __future__ import annotations

import base64
import os

from app.protection_keys import (
    load_or_create_metadata_protection_keys,
    load_or_create_tracking_protection_keys,
    unwrap_vault_master_key_via_password,
    unwrap_vault_master_key_via_recovery,
    wrap_vault_master_key_for_password,
    wrap_vault_master_key_for_recovery,
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


# -- Vault Master Key indirection -----------------------------------------


def test_vault_master_key_unwraps_via_password_slot_after_first_use(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)

        vmk = unwrap_vault_master_key_via_password(db_manager, VAULT_KEY)
        assert vmk is not None
        assert len(vmk) == 32
    finally:
        db_manager.close()


def test_vault_master_key_recovery_slot_absent_until_populated(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)

        assert unwrap_vault_master_key_via_recovery(db_manager, os.urandom(32)) is None
    finally:
        db_manager.close()


def test_vault_master_key_recovery_slot_round_trip(tmp_path, monkeypatch):
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)
        vmk = unwrap_vault_master_key_via_password(db_manager, VAULT_KEY)

        recovery_key = os.urandom(32)
        wrap_vault_master_key_for_recovery(db_manager, vmk, recovery_key)

        assert unwrap_vault_master_key_via_recovery(db_manager, recovery_key) == vmk
    finally:
        db_manager.close()


def test_password_rotation_preserves_protection_keys_when_vmk_is_rewrapped(tmp_path, monkeypatch):
    """The core fix this indirection exists for: rewrapping the VMK into
    a new password slot (what a correct password-change flow does)
    keeps the already-encrypted metadata/tracking protection keys
    readable under the new vault key — unlike wrapping directly under
    the vault key, which orphans them on every rotation."""
    db_manager = _db_manager(tmp_path, monkeypatch)
    try:
        original_metadata = load_or_create_metadata_protection_keys(db_manager, VAULT_KEY)
        original_tracking = load_or_create_tracking_protection_keys(db_manager, VAULT_KEY)
        vmk = unwrap_vault_master_key_via_password(db_manager, VAULT_KEY)

        new_vault_key = os.urandom(32)
        wrap_vault_master_key_for_password(db_manager, vmk, new_vault_key)

        rotated_metadata = load_or_create_metadata_protection_keys(db_manager, new_vault_key)
        rotated_tracking = load_or_create_tracking_protection_keys(db_manager, new_vault_key)

        assert rotated_metadata.encryption_key == original_metadata.encryption_key
        assert rotated_metadata.hmac_key == original_metadata.hmac_key
        assert rotated_tracking.encryption_key == original_tracking.encryption_key
        assert rotated_tracking.hmac_key == original_tracking.hmac_key
    finally:
        db_manager.close()
