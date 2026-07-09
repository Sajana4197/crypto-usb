"""Tests for the Validation Engine orchestration."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from metadata.controller import MetadataController
from metadata.hashing import compute_integrity_hash
from metadata.models import DeviceBinding, ExpiryRules, UsagePolicy
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from usb.device_detector import USBDevice
from validation.exceptions import ValidationFailedError
from validation.validation_engine import ValidationEngine

ENCRYPTED_BYTES = b"pretend-encrypted-file-content"


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return MetadataRepository(connection)


@pytest.fixture
def protector():
    return MetadataProtector(generate_protection_keys())


@pytest.fixture
def controller(repository, protector):
    return MetadataController(repository, protector)


@pytest.fixture
def engine(repository, protector):
    return ValidationEngine(repository, protector)


def _create_metadata(controller, file_id="file-1", **kwargs):
    integrity_hash = compute_integrity_hash(ENCRYPTED_BYTES)
    return controller.create(
        file_id=file_id,
        owner_id="owner-1",
        wrapped_key=b"wrapped-key-bytes",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=integrity_hash,
        **kwargs,
    )


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


# -- Happy path / missing record ----------------------------------------


def test_validate_passes_for_healthy_unbound_file(controller, engine):
    _create_metadata(controller)
    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.ok is True
    assert report.checks["hmac"] is True
    assert report.checks["metadata_integrity"] is True
    assert report.checks["file_integrity"] is True
    assert report.checks["expiry"] is True
    assert report.checks["access_count"] is True
    assert report.checks["reused_access"] is True
    assert report.checks["device_binding"] is True


def test_validate_missing_metadata(engine):
    report = engine.validate("nonexistent", ENCRYPTED_BYTES)

    assert report.ok is False
    assert report.checks["metadata_present"] is False


# -- Modified metadata / HMAC / file integrity ---------------------------


def test_validate_detects_tampered_metadata_hmac(controller, engine, repository):
    _create_metadata(controller)
    protected = repository.load("file-1")
    tampered_tag = bytearray(protected.hmac_tag)
    tampered_tag[0] ^= 0xFF
    protected.hmac_tag = bytes(tampered_tag)
    repository.save(protected)

    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.ok is False
    assert report.checks["hmac"] is False


def test_validate_detects_file_integrity_mismatch(controller, engine):
    _create_metadata(controller)
    report = engine.validate("file-1", b"different content entirely")

    assert report.ok is False
    assert report.checks["file_integrity"] is False


# -- Expiry / access count / reused access -------------------------------


def test_validate_detects_expired_access(controller, engine):
    _create_metadata(
        controller,
        expiry_rules=ExpiryRules(expires_at=datetime.now(timezone.utc) - timedelta(days=1)),
    )
    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.ok is False
    assert report.checks["expiry"] is False


def test_validate_detects_access_count_exceeded(controller, engine):
    _create_metadata(controller, expiry_rules=ExpiryRules(max_access_count=1))
    controller.record_access("file-1")

    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.ok is False
    assert report.checks["access_count"] is False


def test_validate_passes_within_access_count_limit(controller, engine):
    _create_metadata(controller, expiry_rules=ExpiryRules(max_access_count=5))
    controller.record_access("file-1")

    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.ok is True


def test_validate_detects_reused_one_time_access(controller, engine):
    _create_metadata(controller, usage_policy=UsagePolicy(one_time_access=True))
    controller.record_access("file-1")

    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.ok is False
    assert report.checks["reused_access"] is False


# -- Device binding / cloned USB / unauthorized device -------------------


def test_validate_device_binding_rejects_unauthorized_device(controller, engine):
    _create_metadata(
        controller,
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000"),
    )

    report = engine.validate("file-1", ENCRYPTED_BYTES, current_usb_identifier=None)

    assert report.ok is False
    assert report.checks["unauthorized_device"] is False


def test_validate_device_binding_passes_with_matching_device(controller, engine):
    _create_metadata(
        controller,
        device_binding=DeviceBinding(bound=True, device_id="E:\\", label="MYUSB", usb_serial="ABCD:FAT32:1000"),
    )

    report = engine.validate(
        "file-1", ENCRYPTED_BYTES, current_device=_device(), current_usb_identifier="ABCD:FAT32:1000"
    )

    assert report.ok is True


def test_validate_device_binding_flags_cloned_usb(controller, engine):
    _create_metadata(
        controller,
        device_binding=DeviceBinding(
            bound=True, device_id="E:\\", label="MYUSB", usb_serial="ORIGINAL:FAT32:1000000"
        ),
    )

    report = engine.validate(
        "file-1", ENCRYPTED_BYTES, current_device=_device(), current_usb_identifier="CLONE:FAT32:1000000"
    )

    assert report.ok is False
    assert report.checks["cloned_usb"] is False


def test_validate_device_binding_machine_fingerprint_mismatch(controller, engine):
    _create_metadata(
        controller,
        device_binding=DeviceBinding(
            bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000", machine_fingerprint="machine-a"
        ),
    )

    report = engine.validate(
        "file-1",
        ENCRYPTED_BYTES,
        current_device=_device(),
        current_usb_identifier="ABCD:FAT32:1000",
        current_machine_fingerprint="machine-b",
    )

    assert report.ok is False
    assert report.checks["machine_fingerprint"] is False


# -- validate_or_raise / side effects -------------------------------------


def test_validate_or_raise_raises_on_failure(engine):
    with pytest.raises(ValidationFailedError) as exc_info:
        engine.validate_or_raise("nonexistent", ENCRYPTED_BYTES)
    assert exc_info.value.report.ok is False


def test_validate_or_raise_returns_report_on_success(controller, engine):
    _create_metadata(controller)
    report = engine.validate_or_raise("file-1", ENCRYPTED_BYTES)
    assert report.ok is True


def test_validate_does_not_mutate_access_count(controller, engine):
    _create_metadata(controller)
    engine.validate("file-1", ENCRYPTED_BYTES)
    engine.validate("file-1", ENCRYPTED_BYTES)

    metadata = controller.read("file-1")
    assert metadata.access_count == 0


def test_validate_report_carries_decrypted_metadata(controller, engine):
    _create_metadata(controller)
    report = engine.validate("file-1", ENCRYPTED_BYTES)

    assert report.metadata is not None
    assert report.metadata.file_id == "file-1"
