"""Tests for stable USB device identifier computation."""

from usb.device_detector import USBDevice
from validation.usb_identifier import (
    HardwareDescriptor,
    compute_hardware_descriptor,
    compute_usb_identifier,
    device_fingerprint_material,
    parse_pnp_device_id,
)


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


# -- Rich hardware descriptor: vendor/product/serial (Phase 2) --------------


def test_parse_pnp_device_id_extracts_vendor_product_serial():
    pnp = r"USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00\4C530001A2B3C4D5&0"
    descriptor = parse_pnp_device_id(pnp)

    assert descriptor == HardwareDescriptor(
        vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="4C530001A2B3C4D5"
    )


def test_parse_pnp_device_id_is_case_insensitive_for_tokens():
    pnp = r"usbstor\disk&ven_kingston&prod_datatraveler&rev_1.00\0123456789AB&0"
    descriptor = parse_pnp_device_id(pnp)

    assert descriptor.vendor_id == "kingston"
    assert descriptor.product_id == "datatraveler"
    assert descriptor.hardware_serial == "0123456789AB"


def test_parse_pnp_device_id_returns_none_for_unrecognized_format():
    assert parse_pnp_device_id("SCSI\\DISK&Standard_disk_drives") is None


def test_parse_pnp_device_id_returns_none_for_empty_string():
    assert parse_pnp_device_id("") is None


def test_compute_hardware_descriptor_parses_resolved_pnp_device_id():
    device = _device()
    pnp = r"USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.00\4C530001A2B3C4D5&0"

    descriptor = compute_hardware_descriptor(device, pnp_device_id_fn=lambda mp: pnp)

    assert descriptor == HardwareDescriptor(
        vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="4C530001A2B3C4D5"
    )


def test_compute_hardware_descriptor_none_when_pnp_device_id_unavailable():
    device = _device()

    descriptor = compute_hardware_descriptor(device, pnp_device_id_fn=lambda mp: None)

    assert descriptor is None


def test_compute_hardware_descriptor_passes_mount_point_to_injected_fn():
    device = _device(mount_point="F:\\")
    captured = {}

    def _fake(mount_point):
        captured["mount_point"] = mount_point
        return None

    compute_hardware_descriptor(device, pnp_device_id_fn=_fake)

    assert captured["mount_point"] == "F:\\"


# -- device_fingerprint_material (Phase 3: cryptographic device binding) ----


def test_device_fingerprint_material_is_deterministic():
    descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="ABC123")
    a = device_fingerprint_material("SERIAL:FAT32:1000", descriptor)
    b = device_fingerprint_material("SERIAL:FAT32:1000", descriptor)
    assert a == b


def test_device_fingerprint_material_differs_for_different_usb_serial():
    descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="ABC123")
    a = device_fingerprint_material("SERIAL-A:FAT32:1000", descriptor)
    b = device_fingerprint_material("SERIAL-B:FAT32:1000", descriptor)
    assert a != b


def test_device_fingerprint_material_differs_for_different_hardware_descriptor():
    a = device_fingerprint_material(
        "SERIAL:FAT32:1000", HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="ABC123")
    )
    b = device_fingerprint_material(
        "SERIAL:FAT32:1000", HardwareDescriptor(vendor_id="KINGSTON", product_id="DT", hardware_serial="XYZ789")
    )
    assert a != b


def test_device_fingerprint_material_treats_none_descriptor_like_all_empty_fields():
    a = device_fingerprint_material("SERIAL:FAT32:1000", None)
    b = device_fingerprint_material("SERIAL:FAT32:1000", HardwareDescriptor())
    assert a == b


def test_device_fingerprint_material_treats_none_usb_serial_as_empty_string():
    descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="ABC123")
    a = device_fingerprint_material(None, descriptor)
    b = device_fingerprint_material("", descriptor)
    assert a == b
