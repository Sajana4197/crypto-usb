"""SQLite storage for local user accounts.

Owns its own table schema rather than extending
`database.db_manager.DatabaseManager`, following the same pattern as
`metadata.repository.MetadataRepository`: any module needing
persistence manages its own table(s) against the shared connection.

Only a `PasswordCredential` digest or a `PrivateKeyCredential` public
key is ever persisted here — never a password or private key.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Optional

from core.logger import get_logger
from security.models import AuthMethod, PasswordCredential, PrivateKeyCredential, UserAccount

logger = get_logger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
    owner_id TEXT PRIMARY KEY,
    auth_method TEXT NOT NULL,
    credential_json TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT
)
"""

_CREDENTIAL_TYPES = {
    AuthMethod.PASSWORD: PasswordCredential,
    AuthMethod.PRIVATE_KEY: PrivateKeyCredential,
}


class AccountRepository:
    """Persists `UserAccount` records in SQLite, keyed by owner_id."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self.ensure_schema()

    def ensure_schema(self) -> None:
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def save(self, account: UserAccount) -> None:
        self._conn.execute(
            """
            INSERT INTO accounts
                (owner_id, auth_method, credential_json, failed_attempts, locked_until, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_id) DO UPDATE SET
                auth_method = excluded.auth_method,
                credential_json = excluded.credential_json,
                failed_attempts = excluded.failed_attempts,
                locked_until = excluded.locked_until,
                last_login_at = excluded.last_login_at
            """,
            (
                account.owner_id,
                account.auth_method.value,
                json.dumps(account.credential.to_dict()),
                account.failed_attempts,
                account.locked_until.isoformat() if account.locked_until else None,
                account.created_at.isoformat(),
                account.last_login_at.isoformat() if account.last_login_at else None,
            ),
        )
        self._conn.commit()
        logger.info("Saved account owner_id=%s method=%s", account.owner_id, account.auth_method.value)

    def load(self, owner_id: str) -> Optional[UserAccount]:
        cur = self._conn.execute(
            "SELECT owner_id, auth_method, credential_json, failed_attempts, locked_until, "
            "created_at, last_login_at FROM accounts WHERE owner_id = ?",
            (owner_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None

        auth_method = AuthMethod(row[1])
        credential = _CREDENTIAL_TYPES[auth_method].from_dict(json.loads(row[2]))

        return UserAccount(
            owner_id=row[0],
            auth_method=auth_method,
            credential=credential,
            failed_attempts=row[3],
            locked_until=datetime.fromisoformat(row[4]) if row[4] else None,
            created_at=datetime.fromisoformat(row[5]),
            last_login_at=datetime.fromisoformat(row[6]) if row[6] else None,
        )

    def exists(self, owner_id: str) -> bool:
        cur = self._conn.execute("SELECT 1 FROM accounts WHERE owner_id = ?", (owner_id,))
        return cur.fetchone() is not None

    def delete(self, owner_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM accounts WHERE owner_id = ?", (owner_id,))
        self._conn.commit()
        deleted = cur.rowcount > 0
        if deleted:
            logger.info("Deleted account owner_id=%s", owner_id)
        return deleted

    def list_owner_ids(self) -> list[str]:
        cur = self._conn.execute("SELECT owner_id FROM accounts ORDER BY created_at")
        return [row[0] for row in cur.fetchall()]
