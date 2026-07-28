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

`hardware_descriptor` (Phase 2) is a second, independent identity check
against `vendor_id`/`product_id`/`hardware_serial` — read from the USB
controller's own PnP descriptor rather than the filesystem, so it
survives the kind of disk-image clone that reproduces `usb_serial`
exactly. It is purely additive, following the same pattern as the
existing `usb_serial is None` legacy fallback below: a record written
before Phase 2 has all three fields `None`, and the check is skipped
entirely rather than failed.

Device binding (`bound`) and machine binding (`machine_fingerprint is not
None`) are two independent axes (Phase 7) — a file may have either, both,
or neither. Each is checked independently: an unbound-to-device file
skips straight past every USB/hardware check below, but still has its
machine fingerprint checked if one is recorded, and vice versa. Neither
axis short-circuits the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.logger import get_logger
from metadata.models import DeviceBinding
from usb.device_detector import USBDevice
from validation.usb_identifier import HardwareDescriptor

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
        current_hardware_descriptor: Optional[HardwareDescriptor] = None,
    ) -> DeviceBindingResult:
        result = DeviceBindingResult()

        if device_binding.bound:
            self._check_device(result, device_binding, current_device, current_usb_identifier, current_hardware_descriptor)

        if device_binding.machine_fingerprint is not None:
            matches_machine = device_binding.machine_fingerprint == current_machine_fingerprint
            result.add(
                "machine_fingerprint", matches_machine, None if matches_machine else "This file is bound to a different machine"
            )

        result.add("device_binding", result.ok)
        self._log(result)
        return result

    @staticmethod
    def _check_device(
        result: DeviceBindingResult,
        device_binding: DeviceBinding,
        current_device: Optional[USBDevice],
        current_usb_identifier: Optional[str],
        current_hardware_descriptor: Optional[HardwareDescriptor],
    ) -> None:
        """Every USB-identity check (`unauthorized_device`/`cloned_usb`/
        `usb_identifier`/`hardware_descriptor`), run only when
        `device_binding.bound` — entirely independent of whether a
        machine fingerprint is also recorded, see the module docstring.
        """
        if current_usb_identifier is None:
            result.add(
                "unauthorized_device", False, "No USB device is currently presented, but this file requires one"
            )
            return

        if device_binding.usb_serial is None:
            # Bound before a physical serial was recorded (legacy record):
            # fall back to comparing the recorded device_id only.
            matches = device_binding.device_id is None or device_binding.device_id == current_usb_identifier
            result.add("usb_identifier", matches, None if matches else "Bound device_id does not match the presented device")
            if not matches:
                result.add("unauthorized_device", False, "Presented USB device does not match the device this file is bound to")
            return

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

        if (
            device_binding.vendor_id is not None
            or device_binding.product_id is not None
            or device_binding.hardware_serial is not None
        ):
            matches_hardware = current_hardware_descriptor is not None and (
                (device_binding.vendor_id is None or device_binding.vendor_id == current_hardware_descriptor.vendor_id)
                and (
                    device_binding.product_id is None
                    or device_binding.product_id == current_hardware_descriptor.product_id
                )
                and (
                    device_binding.hardware_serial is None
                    or device_binding.hardware_serial == current_hardware_descriptor.hardware_serial
                )
            )
            result.add(
                "hardware_descriptor",
                matches_hardware,
                None
                if matches_hardware
                else "Presented USB device's hardware descriptor (vendor/product/serial) does not match the enrolled device",
            )

    @staticmethod
    def _log(result: DeviceBindingResult) -> None:
        if result.ok:
            logger.info("Device binding check passed: %s", result.checks)
        else:
            logger.warning("Device binding check failed: checks=%s reasons=%s", result.checks, result.reasons)
