"""Tests for the Device Validation / Secure Storage UI page."""

from PySide6.QtWidgets import QApplication

from ui.pages.device_page import DevicePage
from usb.device_detector import USBDevice
from usb.exceptions import ContainerOverwriteError
from usb.secure_storage_service import SecureWriteResult


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


def test_write_button_disabled_until_device_and_file_chosen(tmp_path):
    page = _make_page()
    assert page.write_button.isEnabled() is False

    device = _device(str(tmp_path))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    assert page.write_button.isEnabled() is False  # no file chosen yet

    page._source_path = tmp_path / "does-not-matter.txt"
    page._update_write_button_state()
    assert page.write_button.isEnabled() is True


def test_write_container_end_to_end(tmp_path):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    written = list(device_dir.glob("*.cusc"))
    assert len(written) == 1
    assert b"top secret contents" not in written[0].read_bytes()
    assert "verified" in page.status_label.text().lower()


def test_write_container_overwrite_declined_shows_cancel_message(tmp_path, monkeypatch):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    def _raise(*args, **kwargs):
        raise ContainerOverwriteError("exists")

    monkeypatch.setattr(page._service, "store_file", _raise)
    monkeypatch.setattr(page, "_confirm_overwrite", lambda: False)

    page._on_write_clicked()

    assert "cancelled" in page.status_label.text().lower()


def test_write_container_overwrite_confirmed_retries_write(tmp_path, monkeypatch):
    from metadata.protection import generate_protection_keys

    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    fake_destination = device_dir / "fixed-id.cusc"
    fake_result = SecureWriteResult(
        file_id="fixed-id",
        destination=fake_destination,
        container_size_bytes=4,
        protection_keys=generate_protection_keys(),
    )
    calls = {"count": 0}

    def _store(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ContainerOverwriteError("exists")
        fake_destination.write_bytes(b"stub")
        return fake_result

    monkeypatch.setattr(page._service, "store_file", _store)
    monkeypatch.setattr(page, "_confirm_overwrite", lambda: True)
    monkeypatch.setattr(page._service, "verify_stored_file", lambda *a, **kw: True)

    page._on_write_clicked()

    assert calls["count"] == 2
    assert "verified" in page.status_label.text().lower()
