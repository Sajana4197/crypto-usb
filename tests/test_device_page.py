"""Tests for the Device Validation UI page (pure device detection/validation,
no write path — see ui.pages.encryption_page.EncryptionPage for that)."""

from PySide6.QtWidgets import QApplication

from ui.pages.device_page import DevicePage
from usb.device_detector import USBDevice


def _make_page():
    QApplication.instance() or QApplication([])
    return DevicePage()


def _device(mount_point, free_bytes=100_000_000):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="TESTUSB",
        filesystem="FAT32",
        total_bytes=free_bytes * 2,
        free_bytes=free_bytes,
        is_removable=True,
    )


class _StubDetector:
    def __init__(self, devices):
        self._devices = devices

    def detect_devices(self):
        return self._devices


def test_refresh_devices_populates_table(tmp_path):
    page = _make_page()
    device = _device(str(tmp_path))
    page._detector = _StubDetector([device])

    page._refresh_devices()

    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == str(tmp_path)


def test_no_devices_shows_zero_summary():
    page = _make_page()
    page._detector = _StubDetector([])

    page._refresh_devices()

    assert page.table.rowCount() == 0
    assert "No removable" in page.device_summary_label.text()


def test_selecting_device_enables_validate_button(tmp_path):
    page = _make_page()
    device = _device(str(tmp_path))
    page._devices = [device]
    page._populate_table()

    page.table.selectRow(0)

    assert page._selected_device is not None
    assert page.validate_button.isEnabled() is True


def test_validate_selected_device_shows_pass(tmp_path):
    page = _make_page()
    device = _device(str(tmp_path))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    page._on_validate_clicked()

    assert "✓" in page.validation_label.text()


def test_validate_selected_device_does_not_require_a_file_size(tmp_path):
    """Validation on this page is generic — it never had a file to size
    itself against (that's `EncryptionPage`'s job now)."""
    page = _make_page()
    device = _device(str(tmp_path), free_bytes=10 * 1024 * 1024)  # comfortably above the safety margin
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    page._on_validate_clicked()

    assert "✓ Sufficient Space" in page.validation_label.text()


def test_validate_selected_device_fails_when_free_space_below_safety_margin(tmp_path):
    page = _make_page()
    device = _device(str(tmp_path), free_bytes=1024)  # far below the safety margin
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    page._on_validate_clicked()

    assert "✗ Sufficient Space" in page.validation_label.text()


# -- Automatic device-list polling ------------------------------------------


def test_device_poll_timer_is_running_after_construction():
    page = _make_page()

    assert page._device_poll_timer.isActive() is True


def test_refresh_devices_is_a_noop_when_device_list_is_unchanged(tmp_path, monkeypatch):
    page = _make_page()
    device = _device(str(tmp_path))
    page._detector = _StubDetector([device])
    page._refresh_devices()

    rebuild_calls = []
    monkeypatch.setattr(page, "_populate_table", lambda: rebuild_calls.append(None))

    page._refresh_devices()  # same detector, same device list

    assert rebuild_calls == []


def test_refresh_devices_preserves_selection_when_a_new_device_appears(tmp_path):
    page = _make_page()
    device_a_dir = tmp_path / "a"
    device_a_dir.mkdir()
    device_a = _device(str(device_a_dir))
    page._detector = _StubDetector([device_a])
    page._refresh_devices()
    page.table.selectRow(0)
    assert page._selected_device is not None

    device_b_dir = tmp_path / "b"
    device_b_dir.mkdir()
    device_b = _device(str(device_b_dir))
    page._detector = _StubDetector([device_a, device_b])

    page._refresh_devices()

    assert page.table.rowCount() == 2
    assert page._selected_device is not None
    assert page._selected_device.device_id == device_a.device_id


def test_refresh_devices_clears_selection_when_selected_device_disappears(tmp_path):
    page = _make_page()
    device_dir = tmp_path / "a"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._detector = _StubDetector([device])
    page._refresh_devices()
    page.table.selectRow(0)
    assert page._selected_device is not None

    page._detector = _StubDetector([])

    page._refresh_devices()

    assert page._selected_device is None
    assert page.validate_button.isEnabled() is False
