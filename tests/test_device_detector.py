"""Tests for USB device detection."""

from types import SimpleNamespace

from usb.device_detector import USBDevice, USBDeviceDetector


def _partition(device="E:\\", mountpoint="E:\\", fstype="FAT32", opts=""):
    return SimpleNamespace(device=device, mountpoint=mountpoint, fstype=fstype, opts=opts)


def _usage(total=1_000_000, free=500_000):
    return SimpleNamespace(total=total, free=free, used=total - free, percent=50.0)


def test_detects_removable_drive_via_drive_type():
    detector = USBDeviceDetector(
        partitions_fn=lambda: [_partition()],
        usage_fn=lambda mp: _usage(),
        drive_type_fn=lambda mp: 2,  # DRIVE_REMOVABLE
        volume_label_fn=lambda mp: "MYUSB",
    )
    devices = detector.detect_devices()

    assert len(devices) == 1
    assert devices[0].mount_point == "E:\\"
    assert devices[0].label == "MYUSB"
    assert devices[0].is_removable is True


def test_skips_fixed_drive():
    detector = USBDeviceDetector(
        partitions_fn=lambda: [_partition(device="C:\\", mountpoint="C:\\")],
        usage_fn=lambda mp: _usage(),
        drive_type_fn=lambda mp: 3,  # DRIVE_FIXED
        volume_label_fn=lambda mp: "",
    )
    assert detector.detect_devices() == []


def test_non_windows_fallback_uses_opts():
    detector = USBDeviceDetector(
        partitions_fn=lambda: [_partition(opts="rw,removable")],
        usage_fn=lambda mp: _usage(),
        drive_type_fn=lambda mp: None,
        volume_label_fn=lambda mp: "",
    )
    assert len(detector.detect_devices()) == 1


def test_non_windows_fallback_skips_non_removable():
    detector = USBDeviceDetector(
        partitions_fn=lambda: [_partition(opts="rw")],
        usage_fn=lambda mp: _usage(),
        drive_type_fn=lambda mp: None,
        volume_label_fn=lambda mp: "",
    )
    assert detector.detect_devices() == []


def test_skips_partition_with_unreadable_usage():
    def _raise_usage(mp):
        raise OSError("device not ready")

    detector = USBDeviceDetector(
        partitions_fn=lambda: [_partition()],
        usage_fn=_raise_usage,
        drive_type_fn=lambda mp: 2,
        volume_label_fn=lambda mp: "",
    )
    assert detector.detect_devices() == []


def test_partitions_enumeration_failure_returns_empty_list():
    def _raise_partitions():
        raise OSError("enumeration failed")

    detector = USBDeviceDetector(partitions_fn=_raise_partitions)
    assert detector.detect_devices() == []


def test_device_display_helpers():
    device = USBDevice(
        device_id="E:\\",
        mount_point="E:\\",
        label="MYUSB",
        filesystem="FAT32",
        total_bytes=1_073_741_824,
        free_bytes=536_870_912,
        is_removable=True,
    )
    assert device.display_name == "MYUSB (E:\\)"
    assert "GB" in device.total_display
    assert device.free_display  # non-empty, exact unit not asserted
