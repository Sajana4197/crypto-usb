"""Tests for device binding validation."""

from metadata.models import DeviceBinding
from usb.device_detector import USBDevice
from validation.device_binding_validator import DeviceBindingValidator
from validation.usb_identifier import HardwareDescriptor


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


def test_unbound_file_with_machine_fingerprint_still_checks_it():
    """Phase 7: device binding and machine binding are independent axes.
    A file with `bound=False` (no USB binding) but a recorded
    `machine_fingerprint` must still have that machine check enforced --
    previously the early return on `bound=False` skipped it entirely."""
    binding = DeviceBinding(bound=False, machine_fingerprint="machine-a")

    matching = DeviceBindingValidator().validate(binding, None, None, "machine-a")
    mismatched = DeviceBindingValidator().validate(binding, None, None, "machine-b")

    assert matching.ok is True
    assert mismatched.ok is False
    assert mismatched.checks["machine_fingerprint"] is False


def test_unbound_file_with_no_machine_fingerprint_always_passes():
    binding = DeviceBinding(bound=False, machine_fingerprint=None)

    result = DeviceBindingValidator().validate(binding, None, None, None)

    assert result.ok is True
    assert "machine_fingerprint" not in result.checks


def test_no_machine_fingerprint_requirement_skips_check():
    binding = DeviceBinding(
        bound=True, device_id="E:\\", usb_serial="ABCD1234:FAT32:1000000", machine_fingerprint=None
    )
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", None)

    assert result.ok is True
    assert "machine_fingerprint" not in result.checks


# -- Rich hardware descriptor: vendor/product/serial (Phase 2) --------------


def _binding_with_hardware(**overrides):
    defaults = dict(
        bound=True,
        device_id="E:\\",
        usb_serial="ABCD1234:FAT32:1000000",
        vendor_id="SANDISK",
        product_id="CRUZER_BLADE",
        hardware_serial="4C530001A2B3C4D5",
    )
    defaults.update(overrides)
    return DeviceBinding(**defaults)


def test_no_hardware_descriptor_requirement_skips_check():
    """Legacy record (pre-Phase-2): none of vendor_id/product_id/hardware_serial
    are set, so the check must be skipped entirely -- exactly like the
    existing machine_fingerprint-absent case."""
    binding = DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD1234:FAT32:1000000")
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", None)

    assert result.ok is True
    assert "hardware_descriptor" not in result.checks


def test_matching_hardware_descriptor_passes():
    binding = _binding_with_hardware()
    device = _device()
    current = HardwareDescriptor(
        vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="4C530001A2B3C4D5"
    )

    result = DeviceBindingValidator().validate(
        binding, device, "ABCD1234:FAT32:1000000", None, current_hardware_descriptor=current
    )

    assert result.ok is True
    assert result.checks["hardware_descriptor"] is True


def test_mismatched_hardware_serial_fails_even_with_matching_usb_serial():
    """A cloned drive can reproduce the volume-level usb_serial exactly, but
    not the USB controller's own hardware serial -- this is the whole
    point of Phase 2."""
    binding = _binding_with_hardware()
    device = _device()
    current = HardwareDescriptor(
        vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="DIFFERENT_SERIAL"
    )

    result = DeviceBindingValidator().validate(
        binding, device, "ABCD1234:FAT32:1000000", None, current_hardware_descriptor=current
    )

    assert result.ok is False
    assert result.checks["hardware_descriptor"] is False


def test_missing_current_hardware_descriptor_fails_when_binding_requires_it():
    binding = _binding_with_hardware()
    device = _device()

    result = DeviceBindingValidator().validate(
        binding, device, "ABCD1234:FAT32:1000000", None, current_hardware_descriptor=None
    )

    assert result.ok is False
    assert result.checks["hardware_descriptor"] is False


def test_hardware_descriptor_defaults_to_none_when_caller_omits_it():
    """Callers that don't pass `current_hardware_descriptor` at all (e.g.
    older call sites) must not crash -- it defaults to None, which fails
    the check exactly like an explicit None would, when the binding
    requires it."""
    binding = _binding_with_hardware()
    device = _device()

    result = DeviceBindingValidator().validate(binding, device, "ABCD1234:FAT32:1000000", None)

    assert result.ok is False
    assert result.checks["hardware_descriptor"] is False
