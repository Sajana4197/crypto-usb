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
`schema_version` — but not in the clear. Each key is AES-GCM-wrapped
under a "vault key" derived from the authenticated user's own
credentials (see `security.password_hasher.derive_vault_key` /
`derive_vault_key_from_bytes`, populated onto `AuthSession.vault_key`
by `security.auth_controller`), so the database key is genuinely
derived from the receiver's authenticated credentials rather than
sitting on disk as a standalone secret. This is the integration phase
`metadata.protection`'s own docstring anticipates: "Persisting or
deriving the encryption/HMAC keys from a user credential is the
responsibility of the future authentication module."
"""

from __future__ import annotations

import base64
import sqlite3
from typing import Optional

from core.logger import get_logger
from crypto import aes_cipher
from crypto.exceptions import DecryptionError
from database.db_manager import DatabaseManager
from metadata.protection import MetadataProtectionKeys, generate_protection_keys
from tracking.tamper_evident_log import TrackingProtectionKeys, generate_tracking_keys

logger = get_logger(__name__)

_METADATA_ENCRYPTION_KEY = "metadata_protection_encryption_key"
_METADATA_HMAC_KEY = "metadata_protection_hmac_key"
_TRACKING_ENCRYPTION_KEY = "tracking_protection_encryption_key"
_TRACKING_HMAC_KEY = "tracking_protection_hmac_key"


def _load_wrapped(conn: sqlite3.Connection, key: str, vault_key: bytes) -> Optional[bytes]:
    """Return the unwrapped key bytes stored under `key`, or `None` if
    absent, or if unwrapping fails (old cleartext format or wrong vault
    key) — callers must fall through to generating fresh keys in that case."""
    nonce_row = conn.execute("SELECT value FROM app_meta WHERE key = ?", (f"{key}_nonce",)).fetchone()
    ciphertext_row = conn.execute("SELECT value FROM app_meta WHERE key = ?", (f"{key}_ciphertext",)).fetchone()
    if nonce_row is None or ciphertext_row is None:
        return None

    nonce = base64.b64decode(nonce_row[0])
    ciphertext = base64.b64decode(ciphertext_row[0])
    try:
        return aes_cipher.decrypt(nonce, ciphertext, vault_key)
    except DecryptionError:
        logger.warning(
            "Found an old-format or incompatible protection key for %s; regenerating fresh keys.", key
        )
        return None


def _save_wrapped(conn: sqlite3.Connection, key: str, value: bytes, vault_key: bytes) -> None:
    nonce, ciphertext = aes_cipher.encrypt(value, vault_key)
    conn.execute(
        "INSERT OR REPLACE INTO app_meta (key, value) VALUES (?, ?)",
        (f"{key}_nonce", base64.b64encode(nonce).decode("ascii")),
    )
    conn.execute(
        "INSERT OR REPLACE INTO app_meta (key, value) VALUES (?, ?)",
        (f"{key}_ciphertext", base64.b64encode(ciphertext).decode("ascii")),
    )
    conn.commit()


def load_or_create_metadata_protection_keys(db_manager: DatabaseManager, vault_key: bytes) -> MetadataProtectionKeys:
    """Return this installation's `MetadataProtectionKeys`, generating and
    persisting them on first use so every session protects/reads the
    same local metadata records. The keys are stored AES-GCM-wrapped
    under `vault_key`, which must be derived from the authenticated
    user's own credentials."""
    conn = db_manager.connect()
    encryption_key = _load_wrapped(conn, _METADATA_ENCRYPTION_KEY, vault_key)
    hmac_key = _load_wrapped(conn, _METADATA_HMAC_KEY, vault_key)
    if encryption_key is not None and hmac_key is not None:
        return MetadataProtectionKeys(encryption_key=encryption_key, hmac_key=hmac_key)

    keys = generate_protection_keys()
    _save_wrapped(conn, _METADATA_ENCRYPTION_KEY, keys.encryption_key, vault_key)
    _save_wrapped(conn, _METADATA_HMAC_KEY, keys.hmac_key, vault_key)
    return keys


def load_or_create_tracking_protection_keys(db_manager: DatabaseManager, vault_key: bytes) -> TrackingProtectionKeys:
    """Return this installation's `TrackingProtectionKeys`, generating and
    persisting them on first use so every session protects/reads the
    same local usage log. The keys are stored AES-GCM-wrapped under
    `vault_key`, which must be derived from the authenticated user's own
    credentials."""
    conn = db_manager.connect()
    encryption_key = _load_wrapped(conn, _TRACKING_ENCRYPTION_KEY, vault_key)
    hmac_key = _load_wrapped(conn, _TRACKING_HMAC_KEY, vault_key)
    if encryption_key is not None and hmac_key is not None:
        return TrackingProtectionKeys(encryption_key=encryption_key, hmac_key=hmac_key)

    keys = generate_tracking_keys()
    _save_wrapped(conn, _TRACKING_ENCRYPTION_KEY, keys.encryption_key, vault_key)
    _save_wrapped(conn, _TRACKING_HMAC_KEY, keys.hmac_key, vault_key)
    return keys
