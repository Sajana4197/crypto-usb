"""Tests for device binding validation."""

from metadata.models import DeviceBinding
from usb.device_detector import USBDevice
from validation.device_binding_validator import DeviceBindingValidator


def _device(mount_point="E:\\", label="MYUSB"):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label=label,
        filesystem="FAT32",
        total_bytes=1_000_000,
        free_bytes=500_000,
        is_removable=True,
    )


def test_unbound_file_always_passes():
    result = DeviceBindingValidator().validate(DeviceBinding(bound=False), None, None, None)
    assert result.ok is True


def test_no_device_presented_is_unauthorized():
    binding = DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD1234:FAT32:1000000")
    result = DeviceBindingValidator().validate(binding, None, None, None)

    assert result.ok is False
    assert result.checks["unauthorized_device"] is False


def test_matching_usb_serial_passes():
    binding = DeviceBinding(bound=True, device_id="E:\\", label="MYUSB", usb_serial="ABCD1234:FAT32:1000000")
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", None)

    assert result.ok is True
    assert result.checks["usb_identifier"] is True


def test_same_label_different_serial_flagged_as_cloned():
    binding = DeviceBinding(bound=True, device_id="E:\\", label="MYUSB", usb_serial="ABCD1234:FAT32:1000000")
    device = _device(label="MYUSB")

    result = DeviceBindingValidator().validate(binding, device, "DIFFERENT:FAT32:1000000", None)

    assert result.ok is False
    assert result.checks["cloned_usb"] is False
    assert "unauthorized_device" not in result.checks


def test_different_label_and_serial_flagged_as_unauthorized():
    binding = DeviceBinding(bound=True, device_id="E:\\", label="MYUSB", usb_serial="ABCD1234:FAT32:1000000")
    device = _device(label="OTHERUSB")

    result = DeviceBindingValidator().validate(binding, device, "DIFFERENT:FAT32:1000000", None)

    assert result.ok is False
    assert result.checks["unauthorized_device"] is False
    assert "cloned_usb" not in result.checks


def test_legacy_record_without_serial_falls_back_to_device_id():
    binding = DeviceBinding(bound=True, device_id="E:\\", usb_serial=None)
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "E:\\", None)

    assert result.ok is True


def test_legacy_record_without_serial_rejects_mismatched_device_id():
    binding = DeviceBinding(bound=True, device_id="E:\\", usb_serial=None)
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "F:\\", None)

    assert result.ok is False


def test_machine_fingerprint_mismatch_rejected():
    binding = DeviceBinding(
        bound=True, device_id="E:\\", usb_serial="ABCD1234:FAT32:1000000", machine_fingerprint="machine-a"
    )
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", "machine-b")

    assert result.ok is False
    assert result.checks["machine_fingerprint"] is False


def test_machine_fingerprint_match_passes():
    binding = DeviceBinding(
        bound=True, device_id="E:\\", usb_serial="ABCD1234:FAT32:1000000", machine_fingerprint="machine-a"
    )
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", "machine-a")

    assert result.ok is True


def test_no_machine_fingerprint_requirement_skips_check():
    binding = DeviceBinding(
        bound=True, device_id="E:\\", usb_serial="ABCD1234:FAT32:1000000", machine_fingerprint=None
    )
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", None)

    assert result.ok is True
    assert "machine_fingerprint" not in result.checks
