"""Tests for FileMetadata and its nested dataclasses' (de)serialization."""

from datetime import datetime, timedelta, timezone

from metadata.models import (
    CURRENT_METADATA_VERSION,
    DeviceBinding,
    ExpiryRules,
    FileMetadata,
    UsagePolicy,
)


def _sample_metadata() -> FileMetadata:
    now = datetime.now(timezone.utc)
    return FileMetadata(
        file_id="file-123",
        owner_id="owner-abc",
        wrapped_key=b"\x01\x02\x03wrapped-key-bytes",
        wrap_algorithm="RSA-OAEP",
        integrity_hash="a" * 64,
        created_at=now,
        last_accessed_at=now + timedelta(minutes=5),
        access_count=3,
        expiry_rules=ExpiryRules(expires_at=now + timedelta(days=7), max_access_count=10),
        device_binding=DeviceBinding(device_id="dev-1", label="My USB", bound=True),
        usage_policy=UsagePolicy(one_time_access=True, allow_multiple_devices=False, notes="test"),
        metadata_version=CURRENT_METADATA_VERSION,
    )


def test_to_dict_from_dict_round_trip():
    original = _sample_metadata()
    restored = FileMetadata.from_dict(original.to_dict())
    assert restored == original


def test_to_dict_base64_encodes_wrapped_key():
    original = _sample_metadata()
    data = original.to_dict()
    assert isinstance(data["wrapped_key"], str)
    assert data["wrapped_key"] != original.wrapped_key


def test_to_dict_isoformats_datetimes():
    original = _sample_metadata()
    data = original.to_dict()
    assert isinstance(data["created_at"], str)
    assert isinstance(data["last_accessed_at"], str)


def test_defaults_when_optional_fields_absent():
    now = datetime.now(timezone.utc)
    metadata = FileMetadata(
        file_id="file-456",
        owner_id="owner-xyz",
        wrapped_key=b"key-bytes",
        wrap_algorithm="RSA-OAEP",
        integrity_hash="b" * 64,
        created_at=now,
    )
    assert metadata.last_accessed_at is None
    assert metadata.access_count == 0
    assert metadata.expiry_rules == ExpiryRules()
    assert metadata.device_binding == DeviceBinding()
    assert metadata.usage_policy == UsagePolicy()


def test_expiry_rules_round_trip_with_none_values():
    rules = ExpiryRules()
    assert ExpiryRules.from_dict(rules.to_dict()) == rules


def test_device_binding_round_trip_with_usb_serial_and_machine_fingerprint():
    binding = DeviceBinding(
        device_id="E:\\",
        label="My USB",
        bound=True,
        usb_serial="ABCD1234:FAT32:1000000",
        machine_fingerprint="a" * 64,
    )
    assert DeviceBinding.from_dict(binding.to_dict()) == binding


def test_device_binding_defaults_usb_serial_and_machine_fingerprint_to_none():
    binding = DeviceBinding()
    assert binding.usb_serial is None
    assert binding.machine_fingerprint is None


def test_device_binding_from_dict_without_new_fields_defaults_to_none():
    legacy_data = {"device_id": "E:\\", "label": "My USB", "bound": True}
    binding = DeviceBinding.from_dict(legacy_data)
    assert binding.usb_serial is None
    assert binding.machine_fingerprint is None


def test_round_trip_via_json():
    import json

    original = _sample_metadata()
    payload = json.dumps(original.to_dict())
    restored = FileMetadata.from_dict(json.loads(payload))
    assert restored == original
