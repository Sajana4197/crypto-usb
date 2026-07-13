"""Tests for the Windows screen-capture mitigation helpers.

`ctypes.windll.user32` is never called against the real OS here — every
test substitutes `viewer.screen_capture_protection._user32` with a fake
so the fallback chain (EXCLUDEFROMCAPTURE -> MONITOR -> NONE) can be
exercised deterministically regardless of the Windows version running
the test.
"""

import pytest
from PySide6.QtWidgets import QApplication

import viewer.screen_capture_protection as scp
from viewer.screen_capture_protection import (
    VK_SNAPSHOT,
    WDA_EXCLUDEFROMCAPTURE,
    WDA_MONITOR,
    WDA_NONE,
    CaptureProtectionLevel,
    PrintScreenWatcher,
    apply_capture_protection,
    remove_capture_protection,
)


class _FakeUser32:
    """Records every call and returns a scripted result per affinity flag."""

    def __init__(self, results: dict[int, int] | None = None, key_state: int = 0) -> None:
        self._results = results or {}
        self._key_state = key_state
        self.affinity_calls: list[tuple[int, int]] = []
        self.key_state_calls = 0

    def SetWindowDisplayAffinity(self, hwnd: int, flag: int) -> int:
        self.affinity_calls.append((hwnd, flag))
        return self._results.get(flag, 0)

    def GetAsyncKeyState(self, vk: int) -> int:
        self.key_state_calls += 1
        return self._key_state


class _RaisingUser32:
    def SetWindowDisplayAffinity(self, hwnd: int, flag: int) -> int:
        raise OSError("SetWindowDisplayAffinity is not supported on this platform")

    def GetAsyncKeyState(self, vk: int) -> int:
        raise OSError("GetAsyncKeyState is not supported on this platform")


# -- apply_capture_protection -------------------------------------------


def test_prefers_exclude_from_capture_when_supported(monkeypatch):
    fake = _FakeUser32(results={WDA_EXCLUDEFROMCAPTURE: 1})
    monkeypatch.setattr(scp, "_user32", lambda: fake)

    result = apply_capture_protection(hwnd=42)

    assert result.level is CaptureProtectionLevel.EXCLUDED_FROM_CAPTURE
    assert fake.affinity_calls == [(42, WDA_EXCLUDEFROMCAPTURE)]


def test_falls_back_to_monitor_blackout_when_exclude_unsupported(monkeypatch):
    fake = _FakeUser32(results={WDA_EXCLUDEFROMCAPTURE: 0, WDA_MONITOR: 1})
    monkeypatch.setattr(scp, "_user32", lambda: fake)

    result = apply_capture_protection(hwnd=42)

    assert result.level is CaptureProtectionLevel.MONITOR_BLACKOUT
    assert fake.affinity_calls == [(42, WDA_EXCLUDEFROMCAPTURE), (42, WDA_MONITOR)]


def test_reports_none_when_both_calls_fail(monkeypatch):
    fake = _FakeUser32(results={WDA_EXCLUDEFROMCAPTURE: 0, WDA_MONITOR: 0})
    monkeypatch.setattr(scp, "_user32", lambda: fake)

    result = apply_capture_protection(hwnd=42)

    assert result.level is CaptureProtectionLevel.NONE


def test_survives_oserror_and_reports_none(monkeypatch):
    monkeypatch.setattr(scp, "_user32", lambda: _RaisingUser32())

    result = apply_capture_protection(hwnd=42)

    assert result.level is CaptureProtectionLevel.NONE


def test_skips_the_call_entirely_when_hwnd_is_falsy(monkeypatch):
    def _fail_if_called():
        raise AssertionError("user32 must not be consulted for a falsy hwnd")

    monkeypatch.setattr(scp, "_user32", _fail_if_called)

    result = apply_capture_protection(hwnd=0)

    assert result.level is CaptureProtectionLevel.NONE


def test_skips_the_call_on_non_windows_platforms(monkeypatch):
    def _fail_if_called():
        raise AssertionError("user32 must not be consulted off Windows")

    monkeypatch.setattr(scp, "_user32", _fail_if_called)
    monkeypatch.setattr(scp.sys, "platform", "linux")

    result = apply_capture_protection(hwnd=42)

    assert result.level is CaptureProtectionLevel.NONE


# -- remove_capture_protection -------------------------------------------


def test_remove_capture_protection_resets_to_wda_none(monkeypatch):
    fake = _FakeUser32(results={WDA_NONE: 1})
    monkeypatch.setattr(scp, "_user32", lambda: fake)

    remove_capture_protection(hwnd=42)

    assert fake.affinity_calls == [(42, WDA_NONE)]


def test_remove_capture_protection_survives_oserror(monkeypatch):
    monkeypatch.setattr(scp, "_user32", lambda: _RaisingUser32())

    remove_capture_protection(hwnd=42)  # must not raise


def test_remove_capture_protection_noop_for_falsy_hwnd(monkeypatch):
    def _fail_if_called():
        raise AssertionError("user32 must not be consulted for a falsy hwnd")

    monkeypatch.setattr(scp, "_user32", _fail_if_called)

    remove_capture_protection(hwnd=0)  # must not raise or call user32


# -- PrintScreenWatcher ----------------------------------------------------


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_poll_emits_once_on_press_transition(app):
    watcher = PrintScreenWatcher()
    events = []
    watcher.printscreen_detected.connect(lambda: events.append(1))

    watcher._was_down = False
    watcher._is_key_down = lambda: True  # type: ignore[method-assign]
    watcher._poll()

    assert events == [1]


def test_poll_does_not_repeat_while_key_is_held(app):
    watcher = PrintScreenWatcher()
    events = []
    watcher.printscreen_detected.connect(lambda: events.append(1))
    watcher._is_key_down = lambda: True  # type: ignore[method-assign]

    watcher._poll()
    watcher._poll()
    watcher._poll()

    assert events == [1]


def test_poll_emits_again_after_release_and_repress(app):
    watcher = PrintScreenWatcher()
    events = []
    watcher.printscreen_detected.connect(lambda: events.append(1))

    states = iter([True, False, True])
    watcher._is_key_down = lambda: next(states)  # type: ignore[method-assign]

    watcher._poll()
    watcher._poll()
    watcher._poll()

    assert events == [1, 1]


def test_start_and_stop_control_the_timer(app):
    watcher = PrintScreenWatcher()
    assert watcher.is_active is False

    watcher.start()
    assert watcher.is_active is True

    watcher.stop()
    assert watcher.is_active is False


def test_is_key_down_uses_the_high_bit_of_the_key_state(monkeypatch, app):
    fake = _FakeUser32(key_state=0x8001)  # currently down + was pressed since last call
    monkeypatch.setattr(scp, "_user32", lambda: fake)

    assert PrintScreenWatcher._is_key_down() is True
    assert fake.key_state_calls == 1


def test_is_key_down_false_when_high_bit_unset(monkeypatch, app):
    fake = _FakeUser32(key_state=0x0001)
    monkeypatch.setattr(scp, "_user32", lambda: fake)

    assert PrintScreenWatcher._is_key_down() is False


def test_vk_snapshot_is_the_documented_print_screen_code():
    assert VK_SNAPSHOT == 0x2C
