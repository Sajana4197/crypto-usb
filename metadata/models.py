"""Data model for a file's encrypted metadata record.

`FileMetadata` is the plaintext, in-memory form of everything the
Metadata Controller tracks about a protected file. It is never
persisted directly — `metadata.protection.MetadataProtector` encrypts
and HMAC-protects its serialized form before `metadata.repository`
writes it to SQLite.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

CURRENT_METADATA_VERSION = 1


@dataclass
class ExpiryRules:
    """When a file's access rights lapse."""

    expires_at: Optional[datetime] = None
    max_access_count: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "max_access_count": self.max_access_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ExpiryRules":
        return cls(
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            max_access_count=data.get("max_access_count"),
        )


@dataclass
class DeviceBinding:
    """Which USB device (and, optionally, host machine) this file is bound to.

    `device_id`/`label` are the human-readable identifiers recorded by the
    `usb/` module. `usb_serial` and `machine_fingerprint` are the actual
    unforgeable(-ish) identity signals checked by
    `validation.device_binding_validator` — a drive letter can coincide
    across two different physical devices, but a volume serial number and
    a machine's installation GUID are far harder to collide by accident.
    """

    device_id: Optional[str] = None
    label: Optional[str] = None
    bound: bool = False
    usb_serial: Optional[str] = None
    machine_fingerprint: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "label": self.label,
            "bound": self.bound,
            "usb_serial": self.usb_serial,
            "machine_fingerprint": self.machine_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceBinding":
        return cls(
            device_id=data.get("device_id"),
            label=data.get("label"),
            bound=data.get("bound", False),
            usb_serial=data.get("usb_serial"),
            machine_fingerprint=data.get("machine_fingerprint"),
        )


@dataclass
class UsagePolicy:
    """Access rules enforced by `MetadataController.enforce_policy`."""

    one_time_access: bool = False
    allow_multiple_devices: bool = True
    notes: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "one_time_access": self.one_time_access,
            "allow_multiple_devices": self.allow_multiple_devices,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UsagePolicy":
        return cls(
            one_time_access=data.get("one_time_access", False),
            allow_multiple_devices=data.get("allow_multiple_devices", True),
            notes=data.get("notes"),
        )


@dataclass
class FileMetadata:
    file_id: str
    owner_id: str
    wrapped_key: bytes
    wrap_algorithm: str
    integrity_hash: str
    created_at: datetime
    last_accessed_at: Optional[datetime] = None
    access_count: int = 0
    expiry_rules: ExpiryRules = field(default_factory=ExpiryRules)
    device_binding: DeviceBinding = field(default_factory=DeviceBinding)
    usage_policy: UsagePolicy = field(default_factory=UsagePolicy)
    metadata_version: int = CURRENT_METADATA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "owner_id": self.owner_id,
            "wrapped_key": base64.b64encode(self.wrapped_key).decode("ascii"),
            "wrap_algorithm": self.wrap_algorithm,
            "integrity_hash": self.integrity_hash,
            "created_at": self.created_at.isoformat(),
            "last_accessed_at": self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            "access_count": self.access_count,
            "expiry_rules": self.expiry_rules.to_dict(),
            "device_binding": self.device_binding.to_dict(),
            "usage_policy": self.usage_policy.to_dict(),
            "metadata_version": self.metadata_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileMetadata":
        return cls(
            file_id=data["file_id"],
            owner_id=data["owner_id"],
            wrapped_key=base64.b64decode(data["wrapped_key"]),
            wrap_algorithm=data["wrap_algorithm"],
            integrity_hash=data["integrity_hash"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_accessed_at=(
                datetime.fromisoformat(data["last_accessed_at"])
                if data.get("last_accessed_at")
                else None
            ),
            access_count=data.get("access_count", 0),
            expiry_rules=ExpiryRules.from_dict(data.get("expiry_rules", {})),
            device_binding=DeviceBinding.from_dict(data.get("device_binding", {})),
            usage_policy=UsagePolicy.from_dict(data.get("usage_policy", {})),
            metadata_version=data.get("metadata_version", CURRENT_METADATA_VERSION),
        )
