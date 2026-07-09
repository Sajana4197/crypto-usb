"""Tests for USB device validation."""

from usb.device_detector import USBDevice
from usb.device_validator import FREE_SPACE_SAFETY_MARGIN_BYTES, USBDeviceValidator


def _device(mount_point, free_bytes=100_000_000, is_removable=True):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="TEST",
        filesystem="FAT32",
        total_bytes=free_bytes * 2,
        free_bytes=free_bytes,
        is_removable=is_removable,
    )


def test_validate_passes_for_attached_removable_writable_device(tmp_path):
    device = _device(str(tmp_path))
    result = USBDeviceValidator().validate(device)

    assert result.ok is True
    assert result.checks["attached"] is True
    assert result.checks["removable"] is True
    assert result.checks["writable"] is True
    assert result.checks["sufficient_space"] is True


def test_validate_fails_for_missing_mount_point(tmp_path):
    missing = tmp_path / "does-not-exist"
    device = _device(str(missing))
    result = USBDeviceValidator().validate(device)

    assert result.ok is False
    assert result.checks["attached"] is False
    assert result.reasons


def test_validate_fails_for_non_removable_device(tmp_path):
    device = _device(str(tmp_path), is_removable=False)
    result = USBDeviceValidator().validate(device)

    assert result.ok is False
    assert result.checks["removable"] is False


def test_validate_fails_for_insufficient_space(tmp_path):
    device = _device(str(tmp_path), free_bytes=100)
    result = USBDeviceValidator().validate(device, required_bytes=1000)

    assert result.ok is False
    assert result.checks["sufficient_space"] is False


def test_validate_accounts_for_safety_margin(tmp_path):
    device = _device(str(tmp_path), free_bytes=FREE_SPACE_SAFETY_MARGIN_BYTES)
    result = USBDeviceValidator().validate(device, required_bytes=1)

    assert result.checks["sufficient_space"] is False


def test_write_probe_file_is_cleaned_up(tmp_path):
    device = _device(str(tmp_path))
    USBDeviceValidator().validate(device)

    assert list(tmp_path.glob(".cryptousb_write_test_*")) == []
