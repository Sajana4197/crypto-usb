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
under a Vault Master Key (VMK), itself a random key generated once and
stored in independent wrapped "slots": a password slot, unlocked by
the "vault key" derived from the authenticated user's own credentials
(see `security.password_hasher.derive_vault_key` /
`derive_vault_key_from_bytes`, populated onto `AuthSession.vault_key`
by `security.auth_controller`), and a recovery slot, unlocked by a key
derived from the account's recovery code (see
`security.password_hasher.derive_recovery_key`). Indirecting through a
stable VMK rather than wrapping the protection keys under the vault
key directly means a password change or recovery-code reset can
rewrap the VMK into a new slot without regenerating it — so
already-encrypted metadata and the tamper-evident usage log stay
readable/verifiable across a credential rotation, rather than being
silently orphaned. This is the integration phase `metadata.protection`'s
own docstring anticipates: "Persisting or deriving the
encryption/HMAC keys from a user credential is the responsibility of
the future authentication module."
"""

from __future__ import annotations

import base64
import os
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

_VAULT_MASTER_KEY_PASSWORD_SLOT = "vault_master_key_password_slot"
_VAULT_MASTER_KEY_RECOVERY_SLOT = "vault_master_key_recovery_slot"

VAULT_MASTER_KEY_SIZE_BYTES = 32


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


def _load_or_create_vault_master_key(conn: sqlite3.Connection, vault_key: bytes) -> bytes:
    """Return this installation's Vault Master Key (VMK) — the key that
    actually wraps the metadata/tracking protection keys — generating
    one on first use. `vault_key` unlocks it via the password slot; a
    second, independent slot (populated separately, see
    `wrap_vault_master_key_for_recovery`) can unlock the same VMK via a
    recovery-code-derived key instead. Indirecting through a stable VMK
    rather than wrapping the protection keys under `vault_key` directly
    means a password change/reset can rotate the vault key without
    invalidating already-encrypted metadata or the tamper-evident log —
    the VMK just gets rewrapped, never regenerated."""
    existing = _load_wrapped(conn, _VAULT_MASTER_KEY_PASSWORD_SLOT, vault_key)
    if existing is not None:
        return existing

    vmk = os.urandom(VAULT_MASTER_KEY_SIZE_BYTES)
    _save_wrapped(conn, _VAULT_MASTER_KEY_PASSWORD_SLOT, vmk, vault_key)
    return vmk


def unwrap_vault_master_key_via_password(db_manager: DatabaseManager, vault_key: bytes) -> Optional[bytes]:
    """Return the VMK unwrapped via the password slot, or `None` if
    `vault_key` doesn't unlock it (e.g. a stale/wrong password-derived key)."""
    return _load_wrapped(db_manager.connect(), _VAULT_MASTER_KEY_PASSWORD_SLOT, vault_key)


def unwrap_vault_master_key_via_recovery(db_manager: DatabaseManager, recovery_key: bytes) -> Optional[bytes]:
    """Return the VMK unwrapped via the recovery slot, or `None` if
    `recovery_key` doesn't unlock it (no recovery slot yet, or a
    since-rotated recovery code)."""
    return _load_wrapped(db_manager.connect(), _VAULT_MASTER_KEY_RECOVERY_SLOT, recovery_key)


def wrap_vault_master_key_for_password(db_manager: DatabaseManager, vmk: bytes, vault_key: bytes) -> None:
    """(Re)write the password slot so `vault_key` unlocks `vmk` — used
    when a password change/reset rotates the password-derived vault key."""
    _save_wrapped(db_manager.connect(), _VAULT_MASTER_KEY_PASSWORD_SLOT, vmk, vault_key)


def wrap_vault_master_key_for_recovery(db_manager: DatabaseManager, vmk: bytes, recovery_key: bytes) -> None:
    """(Re)write the recovery slot so `recovery_key` unlocks `vmk` —
    used whenever a fresh recovery code is issued, so it can unlock the
    same VMK the password slot does."""
    _save_wrapped(db_manager.connect(), _VAULT_MASTER_KEY_RECOVERY_SLOT, vmk, recovery_key)


def establish_vault_master_key(db_manager: DatabaseManager, vault_key: bytes, recovery_key: bytes) -> bytes:
    """Ensure a VMK exists and is wrapped under both `vault_key` (password
    slot) and `recovery_key` (recovery slot). Called at registration —
    and by a password change/reset once it has derived both the new
    vault key and the new recovery key — so the recovery slot is always
    populated alongside the password slot rather than created lazily."""
    conn = db_manager.connect()
    vmk = _load_or_create_vault_master_key(conn, vault_key)
    wrap_vault_master_key_for_recovery(db_manager, vmk, recovery_key)
    return vmk


def load_or_create_metadata_protection_keys(db_manager: DatabaseManager, vault_key: bytes) -> MetadataProtectionKeys:
    """Return this installation's `MetadataProtectionKeys`, generating and
    persisting them on first use so every session protects/reads the
    same local metadata records. The keys are stored AES-GCM-wrapped
    under the Vault Master Key (see `_load_or_create_vault_master_key`),
    which `vault_key` — derived from the authenticated user's own
    credentials — unlocks."""
    conn = db_manager.connect()
    vmk = _load_or_create_vault_master_key(conn, vault_key)

    encryption_key = _load_wrapped(conn, _METADATA_ENCRYPTION_KEY, vmk)
    hmac_key = _load_wrapped(conn, _METADATA_HMAC_KEY, vmk)
    if encryption_key is not None and hmac_key is not None:
        return MetadataProtectionKeys(encryption_key=encryption_key, hmac_key=hmac_key)

    keys = generate_protection_keys()
    _save_wrapped(conn, _METADATA_ENCRYPTION_KEY, keys.encryption_key, vmk)
    _save_wrapped(conn, _METADATA_HMAC_KEY, keys.hmac_key, vmk)
    return keys


def load_or_create_tracking_protection_keys(db_manager: DatabaseManager, vault_key: bytes) -> TrackingProtectionKeys:
    """Return this installation's `TrackingProtectionKeys`, generating and
    persisting them on first use so every session protects/reads the
    same local usage log. The keys are stored AES-GCM-wrapped under the
    Vault Master Key (see `_load_or_create_vault_master_key`), which
    `vault_key` — derived from the authenticated user's own credentials
    — unlocks."""
    conn = db_manager.connect()
    vmk = _load_or_create_vault_master_key(conn, vault_key)

    encryption_key = _load_wrapped(conn, _TRACKING_ENCRYPTION_KEY, vmk)
    hmac_key = _load_wrapped(conn, _TRACKING_HMAC_KEY, vmk)
    if encryption_key is not None and hmac_key is not None:
        return TrackingProtectionKeys(encryption_key=encryption_key, hmac_key=hmac_key)

    keys = generate_tracking_keys()
    _save_wrapped(conn, _TRACKING_ENCRYPTION_KEY, keys.encryption_key, vmk)
    _save_wrapped(conn, _TRACKING_HMAC_KEY, keys.hmac_key, vmk)
    return keys
