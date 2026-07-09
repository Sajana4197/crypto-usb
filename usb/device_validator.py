"""USB device validation.

Confirms a device selected in the UI is safe to write to: still
attached, genuinely removable, writable, and has enough free space for
the container about to be written. Every check is independent and
recorded on the `ValidationResult` so a caller gets a specific,
actionable reason for any failure rather than a single opaque yes/no.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from usb.device_detector import USBDevice

logger = get_logger(__name__)

# Reserve headroom beyond the exact container size so the device isn't
# filled to the very last byte (filesystem metadata, concurrent writes).
FREE_SPACE_SAFETY_MARGIN_BYTES = 4 * 1024 * 1024  # 4 MiB


@dataclass
class ValidationResult:
    """Outcome of validating a device, with a reason recorded per failed check."""

    ok: bool = True
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def add(self, name: str, passed: bool, reason: Optional[str] = None) -> None:
        self.checks[name] = passed
        if not passed:
            self.ok = False
            if reason:
                self.reasons.append(reason)


class USBDeviceValidator:
    """Validates that a `USBDevice` is safe to write a secure container to."""

    def validate(self, device: USBDevice, required_bytes: int = 0) -> ValidationResult:
        result = ValidationResult()

        mount = Path(device.mount_point)
        attached = mount.exists()
        result.add("attached", attached, f"Device is no longer attached at {device.mount_point}")
        if not attached:
            logger.warning("Validation failed for %s: not attached", device.device_id)
            return result

        result.add(
            "removable",
            device.is_removable,
            f"{device.device_id} is not a removable device",
        )

        writable = self._check_writable(mount)
        result.add("writable", writable, f"{device.mount_point} is not writable")

        needed = required_bytes + FREE_SPACE_SAFETY_MARGIN_BYTES
        has_space = device.free_bytes >= needed
        result.add(
            "sufficient_space",
            has_space,
            f"Only {device.free_bytes:,} bytes free; need at least {needed:,} bytes",
        )

        logger.info(
            "Validated device %s: ok=%s checks=%s", device.device_id, result.ok, result.checks
        )
        return result

    @staticmethod
    def _check_writable(mount: Path) -> bool:
        probe = mount / f".cryptousb_write_test_{uuid.uuid4().hex}"
        try:
            with open(probe, "wb") as fh:
                fh.write(b"probe")
            return True
        except OSError:
            return False
        finally:
            try:
                if probe.exists():
                    os.remove(probe)
            except OSError:
                pass
