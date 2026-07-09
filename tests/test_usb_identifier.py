"""Tests for stable USB device identifier computation."""

from usb.device_detector import USBDevice
from validation.usb_identifier import compute_usb_identifier


def _device(mount_point="E:\\", filesystem="FAT32", total_bytes=1_000_000):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="TEST",
        filesystem=filesystem,
        total_bytes=total_bytes,
        free_bytes=500_000,
        is_removable=True,
    )


def test_identifier_includes_serial_filesystem_capacity():
    device = _device()
    identifier = compute_usb_identifier(device, volume_serial_fn=lambda mp: 0xDEADBEEF)

    assert "DEADBEEF" in identifier
    assert "FAT32" in identifier
    assert "1000000" in identifier


def test_identifier_stable_for_same_device():
    device = _device()
    a = compute_usb_identifier(device, volume_serial_fn=lambda mp: 0x12345678)
    b = compute_usb_identifier(device, volume_serial_fn=lambda mp: 0x12345678)

    assert a == b


def test_identifier_differs_for_different_serial():
    device = _device()
    a = compute_usb_identifier(device, volume_serial_fn=lambda mp: 0x11111111)
    b = compute_usb_identifier(device, volume_serial_fn=lambda mp: 0x22222222)

    assert a != b


def test_identifier_differs_for_different_capacity():
    a = compute_usb_identifier(_device(total_bytes=1_000_000), volume_serial_fn=lambda mp: 0x1)
    b = compute_usb_identifier(_device(total_bytes=2_000_000), volume_serial_fn=lambda mp: 0x1)

    assert a != b


def test_identifier_handles_unavailable_serial():
    device = _device()
    identifier = compute_usb_identifier(device, volume_serial_fn=lambda mp: None)

    assert "UNKNOWN" in identifier
