"""Stable machine fingerprint for binding protected files to a specific host.

Prefers the Windows-assigned `MachineGuid`
(`HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`) — a value
generated once at OS installation and stable across reboots, network
changes, and most hardware changes, unlike a MAC address or hostname
(both of which can change or be spoofed trivially). Falls back to a
hash of hostname + MAC address off-Windows or if the registry value
can't be read.
"""

from __future__ import annotations

import hashlib
import platform
import sys
import uuid
from typing import Callable, Optional


def _read_windows_machine_guid() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return value
    except OSError:
        return None


def _fallback_fingerprint() -> str:
    raw = f"{platform.node()}:{uuid.getnode()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_machine_fingerprint(
    machine_guid_fn: Callable[[], Optional[str]] = _read_windows_machine_guid,
) -> str:
    """A stable SHA-256 fingerprint identifying the current machine."""
    guid = machine_guid_fn()
    if guid:
        return hashlib.sha256(guid.encode("utf-8")).hexdigest()
    return _fallback_fingerprint()
