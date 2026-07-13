"""Best-effort Windows screen-capture mitigation for the secure viewer.

Windows offers no API that guarantees a window's content can never be
captured by *any* mechanism. This module implements the strongest
mitigation Microsoft documents for a desktop window
(`SetWindowDisplayAffinity`) plus a lightweight, polling-based Print
Screen *detector* (a second line of defense, not a blocker), and is
explicit — here and in `viewer.secure_viewer_widget` — about exactly
what each does and does not cover, as required for this phase.

What `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` covers,
per Microsoft's documentation, on Windows 10 version 2004 (May 2020
Update) and later:

- The Windows Graphics Capture API — used by the modern Snipping Tool's
  region/window capture, Xbox Game Bar's screenshot and recording
  capture, and most current screen-recording/remote-assistance tools
  built on that API — renders the excluded window as absent from the
  captured surface.
- Classic GDI capture (`BitBlt` against the window's device context) —
  the mechanism behind the traditional Print Screen path and many
  older third-party screenshot tools — is excluded as well.

Known, documented limitations (there is no complete blocking mechanism
on Windows for a windowed desktop application):

- `WDA_EXCLUDEFROMCAPTURE` requires Windows 10 version 2004 or later.
  On older Windows 10 builds and Windows 7/8, `apply_capture_protection`
  falls back to `WDA_MONITOR` (supported since Windows 7), which
  blanks the window to a solid black rectangle in captures instead of
  excluding it outright — a real mitigation (no content is recoverable
  from the captured image), but the window's *presence* remains
  visible where `WDA_EXCLUDEFROMCAPTURE` would hide it entirely.
- `PrintWindow` called with the `PW_RENDERFULLCONTENT` flag has been
  reported, on some Windows version/driver combinations, to bypass
  display-affinity exclusion for hardware-accelerated (DirectX/OpenGL)
  window content. This is a platform limitation outside any
  application's control; this module cannot detect or prevent it.
- None of this stops a second physical device (a phone camera, another
  computer's camera during a video call) from photographing the
  screen, a hypervisor/virtual-machine host capturing the guest's
  framebuffer, or a remote desktop client capturing frames on its own
  side of an RDP/VNC session the user is legitimately running.
- Protection only takes effect once the window has a native handle
  (after it is shown); there is no protection for the moment before
  that, and none at all on non-Windows platforms (this module is a
  documented no-op there).

Print Screen *detection* (`PrintScreenWatcher`) is a different kind of
mitigation. Windows does not reliably deliver a Print Screen key event
to the focused application's message queue at all — the OS shell
typically intercepts `VK_SNAPSHOT` before any window sees it — so this
watcher polls the key's *global* state via `GetAsyncKeyState` instead.
That means detection here is: (a) best-effort and racing against
however long the OS's own screenshot handler takes — by the time a
poll fires, the capture may already be complete; and (b) global, not
scoped to this window having focus. It exists so the application can
log and react to a Print Screen press; it is not, and cannot be, proof
that no screenshot was taken.
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from PySide6.QtCore import QObject, QTimer, Signal

from core.logger import get_logger

logger = get_logger(__name__)

# SetWindowDisplayAffinity() flags (winuser.h) — not exposed by ctypes,
# so the documented numeric values are used directly.
WDA_NONE = 0x00000000
WDA_MONITOR = 0x00000001
WDA_EXCLUDEFROMCAPTURE = 0x00000011

VK_SNAPSHOT = 0x2C  # Print Screen virtual-key code


class CaptureProtectionLevel(Enum):
    NONE = auto()
    MONITOR_BLACKOUT = auto()
    EXCLUDED_FROM_CAPTURE = auto()


@dataclass
class CaptureProtectionResult:
    level: CaptureProtectionLevel
    detail: str


def _user32():
    """Indirection point so tests can substitute a fake `user32` without
    needing a real Windows API call to succeed or fail through."""
    return ctypes.windll.user32  # type: ignore[attr-defined]


def apply_capture_protection(hwnd: int) -> CaptureProtectionResult:
    """Apply the strongest available capture exclusion to `hwnd`.

    Tries `WDA_EXCLUDEFROMCAPTURE` first, falls back to `WDA_MONITOR`
    on failure (older Windows), and falls back again to reporting no
    protection if neither call succeeds (non-Windows platform, or a
    window with no real native handle) — always returning a result
    rather than raising, so callers can log the outcome uniformly
    instead of wrapping every call site in its own try/except.
    """
    if sys.platform != "win32" or not hwnd:
        return CaptureProtectionResult(
            CaptureProtectionLevel.NONE, "Not running on Windows, or no native window handle"
        )

    try:
        if _user32().SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE):
            return CaptureProtectionResult(
                CaptureProtectionLevel.EXCLUDED_FROM_CAPTURE,
                "WDA_EXCLUDEFROMCAPTURE applied (requires Windows 10 2004+)",
            )
    except OSError as exc:
        logger.warning("SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) failed: %s", exc)

    try:
        if _user32().SetWindowDisplayAffinity(hwnd, WDA_MONITOR):
            return CaptureProtectionResult(
                CaptureProtectionLevel.MONITOR_BLACKOUT,
                "WDA_EXCLUDEFROMCAPTURE unavailable; fell back to WDA_MONITOR "
                "(window will render as a black rectangle in captures)",
            )
    except OSError as exc:
        logger.warning("SetWindowDisplayAffinity(WDA_MONITOR) failed: %s", exc)

    logger.warning(
        "No screen-capture protection could be applied to window %s "
        "(SetWindowDisplayAffinity unavailable on this platform/window)",
        hwnd,
    )
    return CaptureProtectionResult(CaptureProtectionLevel.NONE, "SetWindowDisplayAffinity unavailable")


def remove_capture_protection(hwnd: int) -> None:
    """Reset `hwnd` to no display-affinity restriction. Best-effort; never raises."""
    if sys.platform != "win32" or not hwnd:
        return
    try:
        _user32().SetWindowDisplayAffinity(hwnd, WDA_NONE)
    except OSError as exc:
        logger.warning("Failed to reset display affinity for window %s: %s", hwnd, exc)


class PrintScreenWatcher(QObject):
    """Polls global Print Screen key state and emits a signal on each press.

    See the module docstring for why polling `GetAsyncKeyState` is used
    instead of a window/key event: Print Screen is not reliably
    delivered to any application's message queue on Windows.
    """

    printscreen_detected = Signal()

    def __init__(self, interval_ms: int = 150, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._was_down = False
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)

    def start(self) -> None:
        if sys.platform == "win32":
            self._was_down = False
            self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    @property
    def is_active(self) -> bool:
        return self._timer.isActive()

    def _poll(self) -> None:
        is_down = self._is_key_down()
        if is_down and not self._was_down:
            logger.warning("Print Screen key press detected while the secure viewer is open")
            self.printscreen_detected.emit()
        self._was_down = is_down

    @staticmethod
    def _is_key_down() -> bool:
        if sys.platform != "win32":
            return False
        try:
            state = _user32().GetAsyncKeyState(VK_SNAPSHOT)
        except OSError:
            return False
        return bool(state & 0x8000)
