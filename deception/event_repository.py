"""SQLite storage for a read-only record of deception activations.

Follows the same pattern as `metadata.repository.MetadataRepository` and
`tracking.repository.TrackingRepository`: owns its own table schema
against a shared connection. Deliberately stores only what an operator
auditing "how often is the deception module actually firing, and why"
needs — `trigger`, `content_type`, `file_id`, and `generated_at` — never
the fabricated `content` itself (nothing gained by persisting decoy
bytes, and it would just be one more place plaintext-shaped data could
leak from). This is an audit trail *of* the Deception Engine, not a
mechanism that changes what it does — nothing here is read by
`DeceptionEngine.activate` to decide behavior, only written after the
decision is already made.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from core.logger import get_logger
from deception.content_types import DeceptionContentType
from deception.triggers import DeceptionTrigger

logger = get_logger(__name__)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS deception_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger TEXT NOT NULL,
    content_type TEXT NOT NULL,
    file_id TEXT,
    generated_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL
)
"""


@dataclass(frozen=True)
class DeceptionEventRecord:
    """One past activation of the Deception Engine, for display only."""

    id: int
    trigger: DeceptionTrigger
    content_type: DeceptionContentType
    file_id: Optional[str]
    generated_at: datetime


class DeceptionEventRepository:
    """Appends and reads `DeceptionEventRecord`s, keyed by insertion order."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self.ensure_schema()

    def ensure_schema(self) -> None:
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def record(
        self,
        trigger: DeceptionTrigger,
        content_type: DeceptionContentType,
        file_id: Optional[str],
        generated_at: datetime,
    ) -> None:
        self._conn.execute(
            "INSERT INTO deception_events (trigger, content_type, file_id, generated_at, recorded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                trigger.value,
                content_type.value,
                file_id,
                generated_at.isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        logger.info("Recorded deception event (trigger=%s, file_id=%s)", trigger.value, file_id or "unknown")

    def list_events(self) -> list[DeceptionEventRecord]:
        """Every recorded event, most recent first."""
        cur = self._conn.execute(
            "SELECT id, trigger, content_type, file_id, generated_at FROM deception_events ORDER BY id DESC"
        )
        return [
            DeceptionEventRecord(
                id=row[0],
                trigger=DeceptionTrigger(row[1]),
                content_type=DeceptionContentType(row[2]),
                file_id=row[3],
                generated_at=datetime.fromisoformat(row[4]),
            )
            for row in cur.fetchall()
        ]

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM deception_events")
        return cur.fetchone()[0]
