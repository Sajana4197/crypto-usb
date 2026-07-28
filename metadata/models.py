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
from enum import Enum
from typing import Any, Optional

CURRENT_METADATA_VERSION = 1


class MachineBindingMode(str, Enum):
    """The machine-binding half of the two independent binding axes chosen
    at encryption time (Encrypt File page) — the other half is the plain
    `bind_device: bool` flag both `usb.secure_storage_service
    .SecureStorageService.store_file` and this enum's sibling parameter
    are named for. The two axes are chosen independently: a file can be
    bound to a USB device, a machine, both, or neither.

    - `NONE`: not bound to any machine.
    - `CURRENT`: bound to whichever machine is running the encryption
      right now (`validation.machine_fingerprint.compute_machine_fingerprint`).
    - `SPECIFIC`: bound to a machine identified by a fingerprint obtained
      ahead of time from that *other* machine (see the "Machine Identity"
      section of `ui.pages.settings_page.SettingsPage`) — no live
      connection between the two machines is ever needed, since the
      fingerprint is a short string the user copies across by any means.

    Cryptographic device-key wrapping (`crypto.key_wrapper
    .DeviceBoundKeyWrapper`, see `usb.secure_storage_service`) applies
    whenever `bind_device` is True and this is `NONE` — the same
    condition the pre-Phase-7 `DEVICE_ONLY` mode used, just reached
    through two independent inputs instead of one flat enum. It never
    applies for `CURRENT` or `SPECIFIC`, since baking a specific
    device's fingerprint into the key is fundamentally incompatible with
    ever validating that key against a different, if still-authorized,
    machine.
    """

    NONE = "none"
    CURRENT = "current"
    SPECIFIC = "specific"


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

    `vendor_id`/`product_id`/`hardware_serial` are a second, independent
    identity signal read straight from the USB controller's own PnP
    descriptor (`validation.usb_identifier.compute_hardware_descriptor`)
    rather than from the filesystem — a disk-image clone reproduces
    `usb_serial` (a filesystem-level value) exactly, but not the
    descriptor-level identity of the physical controller it's plugged
    into. Optional and additive: a record written before Phase 2 (or one
    where the descriptor simply couldn't be read) has all three as
    `None`, and `validation.device_binding_validator` treats that exactly
    like the pre-Phase-2 `usb_serial is None` legacy case — skip, not fail.
    """

    device_id: Optional[str] = None
    label: Optional[str] = None
    bound: bool = False
    usb_serial: Optional[str] = None
    machine_fingerprint: Optional[str] = None
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    hardware_serial: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "label": self.label,
            "bound": self.bound,
            "usb_serial": self.usb_serial,
            "machine_fingerprint": self.machine_fingerprint,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "hardware_serial": self.hardware_serial,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceBinding":
        return cls(
            device_id=data.get("device_id"),
            label=data.get("label"),
            bound=data.get("bound", False),
            usb_serial=data.get("usb_serial"),
            machine_fingerprint=data.get("machine_fingerprint"),
            vendor_id=data.get("vendor_id"),
            product_id=data.get("product_id"),
            hardware_serial=data.get("hardware_serial"),
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
