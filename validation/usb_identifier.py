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
"""

from __future__ import annotations

import sys
from typing import Callable, Optional

from usb.device_detector import USBDevice


def _default_volume_serial(mount_point: str) -> Optional[int]:
    if sys.platform != "win32":
        return None
    try:
        import win32api

        info = win32api.GetVolumeInformation(mount_point)
        return info[1]
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
