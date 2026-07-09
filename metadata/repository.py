"""SQLite storage for protected (encrypted + HMAC'd) metadata records.

Owns its own table schema rather than extending
`database.db_manager.DatabaseManager`, so the generic database module
stays untouched — any module needing persistence follows this same
pattern of managing its own table(s) against a shared connection.

Rows are read positionally rather than via `sqlite3.Row` column
access, so this repository works regardless of the connection's
`row_factory` setting.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from core.logger import get_logger
from metadata.protection import ProtectedMetadata

logger = get_logger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS file_metadata (
    file_id TEXT PRIMARY KEY,
    metadata_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    hmac_tag BLOB NOT NULL,
    stored_at TEXT NOT NULL
)
"""


class MetadataRepository:
    """Persists `ProtectedMetadata` envelopes in SQLite, keyed by file_id."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self.ensure_schema()

    def ensure_schema(self) -> None:
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def save(self, protected: ProtectedMetadata) -> None:
        self._conn.execute(
            """
            INSERT INTO file_metadata (file_id, metadata_version, nonce, ciphertext, hmac_tag, stored_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
                metadata_version = excluded.metadata_version,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                hmac_tag = excluded.hmac_tag,
                stored_at = excluded.stored_at
            """,
            (
                protected.file_id,
                protected.metadata_version,
                protected.nonce,
                protected.ciphertext,
                protected.hmac_tag,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        logger.info("Saved metadata record for file_id=%s", protected.file_id)

    def load(self, file_id: str) -> Optional[ProtectedMetadata]:
        cur = self._conn.execute(
            "SELECT file_id, metadata_version, nonce, ciphertext, hmac_tag "
            "FROM file_metadata WHERE file_id = ?",
            (file_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return ProtectedMetadata(
            file_id=row[0],
            metadata_version=row[1],
            nonce=row[2],
            ciphertext=row[3],
            hmac_tag=row[4],
        )

    def delete(self, file_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM file_metadata WHERE file_id = ?", (file_id,))
        self._conn.commit()
        deleted = cur.rowcount > 0
        if deleted:
            logger.info("Deleted metadata record for file_id=%s", file_id)
        return deleted

    def list_file_ids(self) -> list[str]:
        cur = self._conn.execute("SELECT file_id FROM file_metadata ORDER BY stored_at")
        return [row[0] for row in cur.fetchall()]
