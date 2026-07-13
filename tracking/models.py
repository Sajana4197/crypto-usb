"""Data model for one tracked usage session.

`UsageRecord` is the plaintext, in-memory form of everything
`tracking.tracking_service.UsageTracker` tracks about one session of
accessing a file: who, on which machine and USB device, which file,
when authentication/validation/open/close happened, how long the
session lasted, and how many screen-capture attempts or tampering
events were observed during it. It is never persisted directly —
`tracking.tamper_evident_log.TamperEvidentLog` encrypts and HMAC-chains
its serialized form before `tracking.repository` writes it to SQLite,
mirroring `metadata.models.FileMetadata` / `metadata.protection`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional


@dataclass
class UsageRecord:
    session_id: str
    user: str
    machine_id: str
    file_id: str
    usb_id: Optional[str] = None
    login_time: Optional[datetime] = None
    open_time: Optional[datetime] = None
    close_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    authentication_result: Optional[bool] = None
    validation_result: Optional[bool] = None
    screen_capture_attempts: int = 0
    tampering_events: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user": self.user,
            "machine_id": self.machine_id,
            "file_id": self.file_id,
            "usb_id": self.usb_id,
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "open_time": self.open_time.isoformat() if self.open_time else None,
            "close_time": self.close_time.isoformat() if self.close_time else None,
            "duration_seconds": self.duration_seconds,
            "authentication_result": self.authentication_result,
            "validation_result": self.validation_result,
            "screen_capture_attempts": self.screen_capture_attempts,
            "tampering_events": self.tampering_events,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UsageRecord":
        return cls(
            session_id=data["session_id"],
            user=data["user"],
            machine_id=data["machine_id"],
            file_id=data["file_id"],
            usb_id=data.get("usb_id"),
            login_time=datetime.fromisoformat(data["login_time"]) if data.get("login_time") else None,
            open_time=datetime.fromisoformat(data["open_time"]) if data.get("open_time") else None,
            close_time=datetime.fromisoformat(data["close_time"]) if data.get("close_time") else None,
            duration_seconds=data.get("duration_seconds"),
            authentication_result=data.get("authentication_result"),
            validation_result=data.get("validation_result"),
            screen_capture_attempts=data.get("screen_capture_attempts", 0),
            tampering_events=data.get("tampering_events", 0),
        )
