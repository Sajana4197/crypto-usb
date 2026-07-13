"""SQLite storage for the append-only, hash-chained usage log.

Owns its own table schema against a shared connection, following the
same pattern as `metadata.repository.MetadataRepository`. Deliberately
exposes no update or delete: the tamper-evidence the hash chain
provides only means something if entries are genuinely append-only —
anything that could rewrite history through this repository's own API
would defeat the point.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from core.logger import get_logger
from tracking.tamper_evident_log import GENESIS_HMAC, ChainedLogEntry

logger = get_logger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    prev_hmac BLOB NOT NULL,
    entry_hmac BLOB NOT NULL,
    recorded_at TEXT NOT NULL
)
"""


class TrackingRepository:
    """Appends and reads `ChainedLogEntry` rows, keyed by insertion order."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self.ensure_schema()

    def ensure_schema(self) -> None:
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def last_entry_hmac(self) -> bytes:
        """The `entry_hmac` of the most recently appended entry, or
        `GENESIS_HMAC` if the log is empty — what the next entry must
        chain onto."""
        cur = self._conn.execute("SELECT entry_hmac FROM usage_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row is not None else GENESIS_HMAC

    def append(self, session_id: str, entry: ChainedLogEntry) -> None:
        self._conn.execute(
            """
            INSERT INTO usage_log (session_id, nonce, ciphertext, prev_hmac, entry_hmac, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                entry.nonce,
                entry.ciphertext,
                entry.prev_hmac,
                entry.entry_hmac,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        logger.info("Appended usage log entry for session_id=%s", session_id)

    def list_entries(self) -> list[ChainedLogEntry]:
        """Every stored entry, in original append order — required for
        `TamperEvidentLog.verify_chain`, which walks the chain in order."""
        cur = self._conn.execute(
            "SELECT nonce, ciphertext, prev_hmac, entry_hmac FROM usage_log ORDER BY id"
        )
        return [
            ChainedLogEntry(nonce=row[0], ciphertext=row[1], prev_hmac=row[2], entry_hmac=row[3])
            for row in cur.fetchall()
        ]

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM usage_log")
        return cur.fetchone()[0]
