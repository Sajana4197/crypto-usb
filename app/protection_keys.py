"""Application-wide, persisted-once protection keys for local at-rest
bookkeeping — the metadata table's encrypt-then-MAC keys and the usage
log's encrypt-then-MAC keys.

These are not the secret that keeps a *file* confidential — that is
the RSA keypair `crypto.key_wrapper.KeyWrapper` wraps a File Encryption
Key under, which the research architecture deliberately keeps in the
user's own custody (a private key file plus passphrase only they
hold), never persisted by the application. What this module protects
instead is bookkeeping the app keeps *about itself* on the same
machine — file metadata records and the usage log — so it must be
able to read its own bookkeeping back across restarts without asking
the user to re-supply anything.

Generated once per installation and stored in the same `app_meta`
table `database.db_manager.DatabaseManager` already uses for
`schema_version`, base64-encoded so raw key bytes survive round-trip
through a TEXT column. `metadata.protection`'s own docstring
anticipates this module: "Persisting or deriving the encryption/HMAC
keys from a user credential is the responsibility of the future
authentication module" — this is that integration phase.
"""

from __future__ import annotations

import base64
import sqlite3
from typing import Optional

from database.db_manager import DatabaseManager
from metadata.protection import MetadataProtectionKeys, generate_protection_keys
from tracking.tamper_evident_log import TrackingProtectionKeys, generate_tracking_keys

_METADATA_ENCRYPTION_KEY = "metadata_protection_encryption_key"
_METADATA_HMAC_KEY = "metadata_protection_hmac_key"
_TRACKING_ENCRYPTION_KEY = "tracking_protection_encryption_key"
_TRACKING_HMAC_KEY = "tracking_protection_hmac_key"


def _load(conn: sqlite3.Connection, key: str) -> Optional[bytes]:
    cur = conn.execute("SELECT value FROM app_meta WHERE key = ?", (key,))
    row = cur.fetchone()
    return base64.b64decode(row[0]) if row is not None else None


def _save(conn: sqlite3.Connection, key: str, value: bytes) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO app_meta (key, value) VALUES (?, ?)",
        (key, base64.b64encode(value).decode("ascii")),
    )
    conn.commit()


def load_or_create_metadata_protection_keys(db_manager: DatabaseManager) -> MetadataProtectionKeys:
    """Return this installation's `MetadataProtectionKeys`, generating and
    persisting them on first use so every session protects/reads the
    same local metadata records."""
    conn = db_manager.connect()
    encryption_key = _load(conn, _METADATA_ENCRYPTION_KEY)
    hmac_key = _load(conn, _METADATA_HMAC_KEY)
    if encryption_key is not None and hmac_key is not None:
        return MetadataProtectionKeys(encryption_key=encryption_key, hmac_key=hmac_key)

    keys = generate_protection_keys()
    _save(conn, _METADATA_ENCRYPTION_KEY, keys.encryption_key)
    _save(conn, _METADATA_HMAC_KEY, keys.hmac_key)
    return keys


def load_or_create_tracking_protection_keys(db_manager: DatabaseManager) -> TrackingProtectionKeys:
    """Return this installation's `TrackingProtectionKeys`, generating and
    persisting them on first use so every session protects/reads the
    same local usage log."""
    conn = db_manager.connect()
    encryption_key = _load(conn, _TRACKING_ENCRYPTION_KEY)
    hmac_key = _load(conn, _TRACKING_HMAC_KEY)
    if encryption_key is not None and hmac_key is not None:
        return TrackingProtectionKeys(encryption_key=encryption_key, hmac_key=hmac_key)

    keys = generate_tracking_keys()
    _save(conn, _TRACKING_ENCRYPTION_KEY, keys.encryption_key)
    _save(conn, _TRACKING_HMAC_KEY, keys.hmac_key)
    return keys
