"""SQLite database initialization and connection management.

Only creates the database file and a minimal `schema_version` /
`app_meta` bookkeeping table in this phase. The metadata-driven access
control schema is added in a later phase.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from core.constants import SCHEMA_VERSION
from core.logger import get_logger
from utils.paths import get_database_path

logger = get_logger(__name__)


class DatabaseManager:
    """Owns the SQLite connection lifecycle for the application database."""

    def __init__(self) -> None:
        self._path = get_database_path()
        self._connection: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Create the database file (if needed) and bootstrap tables."""
        conn = self.connect()
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO app_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
        logger.info("Database initialized at %s", self._path)

    def connect(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(str(self._path))
            self._connection.row_factory = sqlite3.Row
        return self._connection

    @contextmanager
    def cursor(self):
        conn = self.connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    def get_schema_version(self) -> int:
        with self.cursor() as cur:
            cur.execute("SELECT value FROM app_meta WHERE key = 'schema_version'")
            row = cur.fetchone()
            return int(row["value"]) if row else 0

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
