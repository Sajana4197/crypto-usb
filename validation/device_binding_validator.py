"""Device Binding validation: does the currently presented USB device (and
host machine) match what a file's metadata says it was bound to?

Three distinct rejection reasons are distinguished, matching the
Validation Engine's requirements:

- `unauthorized_device`: the file requires a bound device, but none — or
  a device with no matching identifier at all — is presented.
- `cloned_usb`: the presented device's recorded volume label matches, but
  its physical USB identifier (volume serial) does not — the signature
  of a naively cloned or substituted drive. This is a heuristic, not
  proof: a byte-for-byte image copy can preserve the serial too.
- `machine_fingerprint` mismatch: the file requires a specific host
  machine, and the current machine's fingerprint does not match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.logger import get_logger
from metadata.models import DeviceBinding
from usb.device_detector import USBDevice

logger = get_logger(__name__)


@dataclass
class DeviceBindingResult:
    ok: bool = True
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def add(self, name: str, passed: bool, reason: Optional[str] = None) -> None:
        self.checks[name] = passed
        if not passed:
            self.ok = False
            if reason:
                self.reasons.append(reason)


class DeviceBindingValidator:
    """Validates a file's `DeviceBinding` against the currently presented device/machine."""

    def validate(
        self,
        device_binding: DeviceBinding,
        current_device: Optional[USBDevice],
        current_usb_identifier: Optional[str],
        current_machine_fingerprint: Optional[str],
    ) -> DeviceBindingResult:
        result = DeviceBindingResult()

        if not device_binding.bound:
            result.add("device_binding", True)
            return result

        if current_usb_identifier is None:
            result.add("device_binding", False)
            result.add(
                "unauthorized_device", False, "No USB device is currently presented, but this file requires one"
            )
            self._log(result)
            return result

        if device_binding.usb_serial is None:
            # Bound before a physical serial was recorded (legacy record):
            # fall back to comparing the recorded device_id only.
            matches = device_binding.device_id is None or device_binding.device_id == current_usb_identifier
            result.add("usb_identifier", matches, None if matches else "Bound device_id does not match the presented device")
            result.add("device_binding", matches)
            if not matches:
                result.add("unauthorized_device", False, "Presented USB device does not match the device this file is bound to")
            self._log(result)
            return result

        if device_binding.usb_serial == current_usb_identifier:
            result.add("usb_identifier", True)
        else:
            label_matches = (
                device_binding.label is not None
                and current_device is not None
                and device_binding.label == current_device.label
            )
            result.add("usb_identifier", False, "Presented USB device's identifier does not match the enrolled device")
            if label_matches:
                result.add(
                    "cloned_usb",
                    False,
                    "Presented device reports the same volume label but a different physical identifier (possible clone)",
                )
            else:
                result.add("unauthorized_device", False, "Presented USB device does not match the device this file is bound to")

        if device_binding.machine_fingerprint is not None:
            matches_machine = device_binding.machine_fingerprint == current_machine_fingerprint
            result.add(
                "machine_fingerprint", matches_machine, None if matches_machine else "This file is bound to a different machine"
            )

        result.add("device_binding", result.ok)
        self._log(result)
        return result

    @staticmethod
    def _log(result: DeviceBindingResult) -> None:
        if result.ok:
            logger.info("Device binding check passed: %s", result.checks)
        else:
            logger.warning("Device binding check failed: checks=%s reasons=%s", result.checks, result.reasons)
