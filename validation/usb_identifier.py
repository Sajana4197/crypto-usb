"""Stable USB device identity, independent of drive letter.

Drive letters and mount points are not a reliable identity for a
physical USB device — they can change across insertions and, more
importantly, two entirely different physical drives can end up with
the same drive letter across separate sessions. The Windows volume
serial number assigned at format time is a much stronger signal.
Combined with filesystem type and reported capacity, it's a
reasonable, standard-practice fingerprint for detecting device
substitution or naive cloning — though not an unforgeable hardware ID
(a byte-for-byte image copy can preserve it), which is why
`validation.device_binding_validator` treats a mismatch here as
suspicious rather than as absolute proof either way.

`compute_hardware_descriptor` below is a second, independent identity
signal read from the USB controller's own PnP descriptor rather than
the filesystem: vendor ID, product ID, and hardware serial, recovered
by walking the standard WMI association chain from a drive letter down
to its physical disk (`Win32_LogicalDisk` -> `Win32_LogicalDiskToPartition`
-> `Win32_DiskPartition` -> `Win32_DiskDriveToDiskPartition` ->
`Win32_DiskDrive`), then parsing that disk's `PNPDeviceID`. A disk-image
clone reproduces the volume serial exactly, but not this descriptor —
it belongs to the physical USB controller, not the filesystem written
onto it.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Callable, Optional

from usb.device_detector import USBDevice

# A USBSTOR PNPDeviceID looks like:
#   USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00\4C530001A2B3C4D5&0
# `VEN_`/`PROD_` are the descriptor-level vendor/product tokens; the last
# path segment before the trailing "&<n>" is the device's own hardware
# serial (assigned by the controller, not the filesystem).
_PNP_VENDOR_PATTERN = re.compile(r"VEN_([^&\\]+)", re.IGNORECASE)
_PNP_PRODUCT_PATTERN = re.compile(r"PROD_([^&\\]+)", re.IGNORECASE)
_PNP_SERIAL_PATTERN = re.compile(r"\\([^&\\]+)&\d+$")


@dataclass(frozen=True)
class HardwareDescriptor:
    """Descriptor-level USB identity, independent of the filesystem."""

    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    hardware_serial: Optional[str] = None


def _default_volume_serial(mount_point: str) -> Optional[int]:
    if sys.platform != "win32":
        return None
    try:
        import win32api

        info = win32api.GetVolumeInformation(mount_point)
        return info[1]
    except Exception:
        return None


def parse_pnp_device_id(pnp_device_id: str) -> Optional[HardwareDescriptor]:
    """Extract vendor/product/serial tokens from a `Win32_DiskDrive.PNPDeviceID`
    string. Returns None if none of the three tokens can be found at all."""
    vendor_match = _PNP_VENDOR_PATTERN.search(pnp_device_id)
    product_match = _PNP_PRODUCT_PATTERN.search(pnp_device_id)
    serial_match = _PNP_SERIAL_PATTERN.search(pnp_device_id)

    vendor_id = vendor_match.group(1) if vendor_match else None
    product_id = product_match.group(1) if product_match else None
    hardware_serial = serial_match.group(1) if serial_match else None

    if vendor_id is None and product_id is None and hardware_serial is None:
        return None
    return HardwareDescriptor(vendor_id=vendor_id, product_id=product_id, hardware_serial=hardware_serial)


def _default_pnp_device_id(mount_point: str) -> Optional[str]:
    """Resolve `mount_point` (e.g. "E:\\") to its physical disk's
    `PNPDeviceID`, by joining `Win32_LogicalDisk` to `Win32_DiskDrive`
    through the standard WMI association chain. Returns None off-Windows,
    if WMI is unavailable, or if the drive letter doesn't resolve to any
    disk drive (e.g. a network share)."""
    if sys.platform != "win32":
        return None
    try:
        import win32com.client

        drive_letter = mount_point.rstrip("\\")
        wmi = win32com.client.GetObject("winmgmts:")
        for partition in wmi.ExecQuery(
            "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='"
            + drive_letter
            + "'} WHERE AssocClass = Win32_LogicalDiskToPartition"
        ):
            for disk in wmi.ExecQuery(
                "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='"
                + partition.DeviceID
                + "'} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
            ):
                if disk.PNPDeviceID:
                    return disk.PNPDeviceID
        return None
    except Exception:
        return None


def compute_usb_identifier(
    device: USBDevice,
    volume_serial_fn: Callable[[str], Optional[int]] = _default_volume_serial,
) -> str:
    """A stable identifier for `device`: volume serial + filesystem + capacity."""
    serial = volume_serial_fn(device.mount_point)
    serial_component = f"{serial:08X}" if serial is not None else "UNKNOWN"
    return f"{serial_component}:{device.filesystem}:{device.total_bytes}"


def compute_hardware_descriptor(
    device: USBDevice,
    pnp_device_id_fn: Callable[[str], Optional[str]] = _default_pnp_device_id,
) -> Optional[HardwareDescriptor]:
    """The USB controller's own vendor ID, product ID, and hardware
    serial for `device`, or None if it couldn't be determined (off-Windows,
    WMI unavailable, or the drive letter doesn't resolve to a disk drive)."""
    pnp_device_id = pnp_device_id_fn(device.mount_point)
    if not pnp_device_id:
        return None
    return parse_pnp_device_id(pnp_device_id)


def device_fingerprint_material(
    usb_serial: Optional[str], hardware_descriptor: Optional[HardwareDescriptor]
) -> bytes:
    """Deterministically combine `usb_serial` (`compute_usb_identifier`)
    and `hardware_descriptor` (`compute_hardware_descriptor`) into one
    byte string, for `crypto.key_manager.derive_device_binding_key` to
    stretch into a device-bound key — only when a file is bound to its
    USB device with no machine binding (`bind_device=True`,
    `metadata.models.MachineBindingMode.NONE`; see
    `usb.secure_storage_service`).

    Callers on both the write side (`usb.secure_storage_service`) and the
    read side (`usb.secure_access_service`) must build this from the
    *same* two inputs for a legitimate device to derive the same key —
    the entire point is that a different device (different serial, or a
    different/missing hardware descriptor) derives a different, wrong
    key instead of merely failing a policy check. A missing descriptor
    field (`None`, e.g. unresolvable on this host) is folded in as an
    empty string rather than skipped, so it still participates in a
    stable, well-defined way rather than silently changing the shape of
    the derivation input.
    """
    descriptor = hardware_descriptor or HardwareDescriptor()
    parts = (
        usb_serial or "",
        descriptor.vendor_id or "",
        descriptor.product_id or "",
        descriptor.hardware_serial or "",
    )
    return "|".join(parts).encode("utf-8")
