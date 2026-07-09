"""USB device detection.

Enumerates removable storage devices attached to the system using
`psutil` for partition/usage data and, on Windows, `win32file` to
distinguish genuinely removable drives (USB flash drives, SD cards)
from fixed, network, and optical drives — psutil's partition options
alone cannot reliably tell these apart on Windows. Every OS call is
reached through an injectable function so tests can simulate arbitrary
device sets without touching real hardware.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, Optional

import psutil

from core.logger import get_logger

logger = get_logger(__name__)

# win32file.DRIVE_REMOVABLE, duplicated here so this module has no hard
# dependency on pywin32 being importable on non-Windows platforms.
_DRIVE_REMOVABLE = 2


@dataclass(frozen=True)
class USBDevice:
    """A removable storage device currently attached and mounted."""

    device_id: str
    mount_point: str
    label: str
    filesystem: str
    total_bytes: int
    free_bytes: int
    is_removable: bool

    @property
    def free_display(self) -> str:
        from utils.formatting import format_file_size

        return format_file_size(self.free_bytes)

    @property
    def total_display(self) -> str:
        from utils.formatting import format_file_size

        return format_file_size(self.total_bytes)

    @property
    def display_name(self) -> str:
        return f"{self.label} ({self.mount_point})" if self.label else self.mount_point


def _default_drive_type(mount_point: str) -> Optional[int]:
    """Return the Windows drive type for `mount_point`, or None off-Windows."""
    if sys.platform != "win32":
        return None
    try:
        import win32file

        return win32file.GetDriveType(mount_point)
    except Exception:
        return None


def _default_volume_label(mount_point: str) -> str:
    if sys.platform == "win32":
        try:
            import win32api

            info = win32api.GetVolumeInformation(mount_point)
            return info[0] or ""
        except Exception:
            return ""
    return ""


class USBDeviceDetector:
    """Enumerates removable storage devices currently attached to the system."""

    def __init__(
        self,
        partitions_fn: Callable[[], list] = lambda: psutil.disk_partitions(all=False),
        usage_fn: Callable[[str], object] = psutil.disk_usage,
        drive_type_fn: Callable[[str], Optional[int]] = _default_drive_type,
        volume_label_fn: Callable[[str], str] = _default_volume_label,
    ) -> None:
        self._partitions_fn = partitions_fn
        self._usage_fn = usage_fn
        self._drive_type_fn = drive_type_fn
        self._volume_label_fn = volume_label_fn

    def detect_devices(self) -> list[USBDevice]:
        """Return every currently attached device that looks like removable USB media."""
        devices: list[USBDevice] = []
        try:
            partitions = self._partitions_fn()
        except OSError as exc:
            logger.error("Failed to enumerate disk partitions: %s", exc)
            return devices

        for part in partitions:
            if not self._is_removable(part):
                continue
            try:
                usage = self._usage_fn(part.mountpoint)
            except OSError as exc:
                logger.warning("Skipping unreadable partition %s: %s", part.mountpoint, exc)
                continue

            device = USBDevice(
                device_id=part.device,
                mount_point=part.mountpoint,
                label=self._volume_label_fn(part.mountpoint),
                filesystem=part.fstype,
                total_bytes=usage.total,
                free_bytes=usage.free,
                is_removable=True,
            )
            devices.append(device)

        logger.info("Detected %d USB/removable device(s)", len(devices))
        return devices

    def _is_removable(self, part) -> bool:
        drive_type = self._drive_type_fn(part.mountpoint)
        if drive_type is not None:
            return drive_type == _DRIVE_REMOVABLE
        # Non-Windows fallback: rely on psutil-reported mount options.
        opts = getattr(part, "opts", "") or ""
        return "removable" in opts.lower()
