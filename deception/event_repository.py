"""SQLite storage for a read-only record of deception activations.

Follows the same pattern as `metadata.repository.MetadataRepository` and
`tracking.repository.TrackingRepository`: owns its own table schema
against a shared connection. Deliberately stores only what an operator
auditing "how often is the deception module actually firing, and why"
needs — `trigger`, `content_type`, `file_id`, `generated_at`, and (Phase
5) whatever USB device was actually presented at that moment — never
the fabricated `content` itself (nothing gained by persisting decoy
bytes, and it would just be one more place plaintext-shaped data could
leak from). This is an audit trail *of* the Deception Engine, not a
mechanism that changes what it does — nothing here is read by
`DeceptionEngine.activate` to decide behavior, only written after the
decision is already made.

`PresentedDeviceInfo` reuses the exact identity fields Phase 2 already
established (`validation.usb_identifier.compute_usb_identifier`/
`compute_hardware_descriptor`) plus the device's own mount point/label,
so a `DEVICE_MISMATCH` event can answer "what device tried this" —
previously nothing about the presented device was captured at all. It's
optional and additive throughout: an event recorded before Phase 5 (or
one triggered with no device presented at all, e.g. a wrong-password
attempt) simply has every field `None`.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
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
    recorded_at TEXT NOT NULL,
    usb_serial TEXT,
    vendor_id TEXT,
    product_id TEXT,
    hardware_serial TEXT,
    mount_point TEXT,
    label TEXT
)
"""

# Added after the original table existed — an existing database's
# `deception_events` table predates these columns entirely, so
# `ensure_schema` adds any that are missing via `ALTER TABLE`, the same
# migration-safe pattern `security.account_repository.AccountRepository`
# already uses for `recovery_code_hash_json`. Every column is nullable:
# old rows read back with all six as `None`, never an error.
_DEVICE_COLUMNS = ("usb_serial", "vendor_id", "product_id", "hardware_serial", "mount_point", "label")


@dataclass(frozen=True)
class PresentedDeviceInfo:
    """Identifying info of whatever USB device was actually presented at
    the moment a deception was triggered — captured for forensic audit
    only. Mirrors `validation.usb_identifier.HardwareDescriptor` plus the
    device's own mount point/label; all fields `None` when no device was
    presented at all (or its identity couldn't be determined)."""

    usb_serial: Optional[str] = None
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    hardware_serial: Optional[str] = None
    mount_point: Optional[str] = None
    label: Optional[str] = None

    @property
    def is_empty(self) -> bool:
        return not any(
            (self.usb_serial, self.vendor_id, self.product_id, self.hardware_serial, self.mount_point, self.label)
        )


@dataclass(frozen=True)
class DeceptionEventRecord:
    """One past activation of the Deception Engine, for display only."""

    id: int
    trigger: DeceptionTrigger
    content_type: DeceptionContentType
    file_id: Optional[str]
    generated_at: datetime
    device_info: PresentedDeviceInfo = field(default_factory=PresentedDeviceInfo)


class DeceptionEventRepository:
    """Appends and reads `DeceptionEventRecord`s, keyed by insertion order."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self.ensure_schema()

    def ensure_schema(self) -> None:
        self._conn.execute(_CREATE_TABLE_SQL)
        existing_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(deception_events)")}
        for column in _DEVICE_COLUMNS:
            if column not in existing_columns:
                self._conn.execute(f"ALTER TABLE deception_events ADD COLUMN {column} TEXT")
        self._conn.commit()

    def record(
        self,
        trigger: DeceptionTrigger,
        content_type: DeceptionContentType,
        file_id: Optional[str],
        generated_at: datetime,
        device_info: Optional[PresentedDeviceInfo] = None,
    ) -> None:
        info = device_info or PresentedDeviceInfo()
        self._conn.execute(
            "INSERT INTO deception_events "
            "(trigger, content_type, file_id, generated_at, recorded_at, "
            "usb_serial, vendor_id, product_id, hardware_serial, mount_point, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                trigger.value,
                content_type.value,
                file_id,
                generated_at.isoformat(),
                datetime.now(timezone.utc).isoformat(),
                info.usb_serial,
                info.vendor_id,
                info.product_id,
                info.hardware_serial,
                info.mount_point,
                info.label,
            ),
        )
        self._conn.commit()
        logger.info("Recorded deception event (trigger=%s, file_id=%s)", trigger.value, file_id or "unknown")

    def list_events(self) -> list[DeceptionEventRecord]:
        """Every recorded event, most recent first."""
        cur = self._conn.execute(
            "SELECT id, trigger, content_type, file_id, generated_at, "
            "usb_serial, vendor_id, product_id, hardware_serial, mount_point, label "
            "FROM deception_events ORDER BY id DESC"
        )
        return [
            DeceptionEventRecord(
                id=row[0],
                trigger=DeceptionTrigger(row[1]),
                content_type=DeceptionContentType(row[2]),
                file_id=row[3],
                generated_at=datetime.fromisoformat(row[4]),
                device_info=PresentedDeviceInfo(
                    usb_serial=row[5],
                    vendor_id=row[6],
                    product_id=row[7],
                    hardware_serial=row[8],
                    mount_point=row[9],
                    label=row[10],
                ),
            )
            for row in cur.fetchall()
        ]

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM deception_events")
        return cur.fetchone()[0]

    def clear(self) -> int:
        """Delete every recorded event. Used only by
        `security.auth_controller.AuthController.delete_account` as part
        of a full local reset — see that method's docstring."""
        cur = self._conn.execute("DELETE FROM deception_events")
        self._conn.commit()
        if cur.rowcount:
            logger.info("Cleared all %d deception event record(s)", cur.rowcount)
        return cur.rowcount
