"""SQLite database initialization and connection management.

Creates the database file, bootstraps a minimal `schema_version` /
`app_meta` bookkeeping table, and — since Phase 23 — opens the file
through SQLCipher rather than plain `sqlite3`, so the entire file at
rest (including the `accounts` table `security.account_repository`
must be able to read *before* login succeeds, which is why it cannot
use Phase 21's credential-derived vault key) is encrypted under a
random, locally-generated key (`database.file_key`). This is a
separate, outer layer from that vault key, not a replacement for it —
see `database.file_key`'s module docstring.

`sqlcipher3.dbapi2.Connection` is duck-type compatible with every
`sqlite3.Connection` operation the repositories in this codebase
actually use (`execute`/`commit`/`cursor`/`row_factory`), so every
repository module keeps its existing `sqlite3.Connection` type hints
unchanged — this is the only module that imports `sqlcipher3` directly.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import sqlcipher3.dbapi2 as sqlcipher

from core.constants import SCHEMA_VERSION
from core.logger import get_logger
from database.file_key import load_or_create_file_key
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
            conn = sqlcipher.connect(str(self._path))
            conn.execute(f"PRAGMA key = \"x'{load_or_create_file_key().hex()}'\"")
            try:
                conn.execute("SELECT count(*) FROM sqlite_master")
            except Exception as exc:
                conn.close()
                raise RuntimeError(
                    "Failed to unlock the encrypted database — the key file may be "
                    "missing, corrupted, or the database file predates SQLCipher encryption"
                ) from exc
            # `sqlcipher3.dbapi2.Cursor` is its own type, not a `sqlite3.Cursor`
            # subclass — `sqlite3.Row` rejects it at construction time, so the
            # row factory must be sqlcipher's own (drop-in-compatible) `Row`.
            conn.row_factory = sqlcipher.Row
            self._connection = conn
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
