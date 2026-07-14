"""Tests for `SecureAccessService`: validate -> decrypt -> (burn) -> deceive."""

import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from crypto.file_encryptor import FileEncryptor
from crypto.key_wrapper import RSAOAEPKeyWrapper
from crypto.secure_cleanup import CleanupReason
from deception.triggers import DeceptionTrigger
from metadata.controller import MetadataController
from metadata.hashing import compute_integrity_hash
from metadata.models import DeviceBinding, ExpiryRules, UsagePolicy
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from usb.device_detector import USBDevice
from usb.secure_access_service import SecureAccessService, _map_validation_failure_to_trigger
from validation.validation_engine import ValidationReport

PLAINTEXT = b"the confidential document content"
FORBIDDEN_PHRASES = [b"access denied", b"authentication failed", b"unauthorized access"]


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return MetadataRepository(connection)


@pytest.fixture
def keys():
    return generate_protection_keys()


@pytest.fixture
def controller(repository, keys):
    return MetadataController(repository, MetadataProtector(keys))


@pytest.fixture
def wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


@pytest.fixture
def container(wrapper):
    return FileEncryptor().encrypt_bytes(PLAINTEXT, wrapper)


@pytest.fixture
def container_bytes(container):
    return container.serialize()


def _create(controller, container, container_bytes, file_id="file-1", **kwargs):
    integrity_hash = compute_integrity_hash(container_bytes)
    return controller.create(
        file_id=file_id,
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
        **kwargs,
    )


@pytest.fixture
def service(repository):
    return SecureAccessService(repository)


class _Collector:
    """An `on_granted` callback that records what it was handed."""

    def __init__(self):
        self.calls: list[bytes] = []

    def __call__(self, buffer, metadata):
        self.calls.append(bytes(buffer))
        self.last_metadata = metadata


# -- Granted access, including the one-time burn --------------------------


def test_first_access_to_one_time_file_is_granted(controller, container, container_bytes, service, wrapper, keys):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    on_granted = _Collector()

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, on_granted)

    assert outcome.granted is True
    assert outcome.deception is None
    assert on_granted.calls == [PLAINTEXT]


def test_first_access_burns_a_one_time_file(controller, container, container_bytes, service, wrapper, keys, repository):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.protection_keys is not None
    assert outcome.protection_keys.encryption_key != keys.encryption_key

    reopened = MetadataProtector(outcome.protection_keys).unprotect(repository.load("file-1"))
    assert reopened.access_count == 0
    assert reopened.wrapped_key != container.wrapped_key


def test_reusable_file_is_not_burned_and_can_be_accessed_repeatedly(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=False))
    on_granted = _Collector()

    first = service.attempt_access("file-1", container_bytes, wrapper, keys, on_granted)
    second = service.attempt_access("file-1", container_bytes, wrapper, keys, on_granted)

    assert first.granted is True
    assert second.granted is True
    assert first.protection_keys.encryption_key == keys.encryption_key
    assert second.protection_keys.encryption_key == keys.encryption_key
    assert on_granted.calls == [PLAINTEXT, PLAINTEXT]


def test_on_granted_receives_the_metadata_object(controller, container, container_bytes, service, wrapper, keys):
    _create(controller, container, container_bytes)
    on_granted = _Collector()

    service.attempt_access("file-1", container_bytes, wrapper, keys, on_granted)

    assert on_granted.last_metadata.file_id == "file-1"


def test_on_granted_exception_prevents_burn(controller, container, container_bytes, service, wrapper, keys, repository):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))

    def _failing_viewer(buffer, metadata):
        raise RuntimeError("viewer crashed before the user actually saw anything")

    with pytest.raises(RuntimeError):
        service.attempt_access("file-1", container_bytes, wrapper, keys, _failing_viewer)

    reopened = MetadataProtector(keys).unprotect(repository.load("file-1"))
    assert reopened.wrapped_key == container.wrapped_key  # unburned
    assert reopened.access_count == 0


# -- Future access attempts activate the Deception Module -----------------


def test_second_access_with_rotated_keys_is_deceived_as_access_already_used(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    first = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    second_seen = _Collector()
    second = service.attempt_access(
        "file-1", container_bytes, wrapper, first.protection_keys, second_seen
    )

    assert second.granted is False
    assert second.deception is not None
    assert second.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED
    assert second_seen.calls == []  # the real content is never handed to the caller again


def test_second_access_with_stale_keys_is_deceived_as_metadata_tampering(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    # An attacker who doesn't know the rotated keys tries again with the
    # (now stale) original protection keys.
    second = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert second.granted is False
    assert second.deception.trigger is DeceptionTrigger.METADATA_TAMPERING


def test_repeated_access_attempts_are_all_deceived(controller, container, container_bytes, service, wrapper, keys):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    first = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())
    rotated_keys = first.protection_keys

    for _ in range(3):
        outcome = service.attempt_access(
            "file-1", container_bytes, wrapper, rotated_keys, _Collector()
        )
        assert outcome.granted is False
        assert outcome.deception is not None
        assert outcome.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED


def test_deception_response_never_contains_the_real_plaintext(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(
        controller,
        container,
        container_bytes,
        usage_policy=UsagePolicy(one_time_access=True),
    )
    first = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    second = service.attempt_access(
        "file-1", container_bytes, wrapper, first.protection_keys, _Collector()
    )

    assert PLAINTEXT not in second.deception.content
    lowered = second.deception.content.decode("latin-1").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.decode() not in lowered


def test_original_container_bytes_are_never_modified(controller, container, container_bytes, service, wrapper, keys):
    original = bytes(container_bytes)

    service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())
    service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert container_bytes == original


# -- Validation failures also route to deception, with the right trigger --


def test_hmac_tamper_triggers_metadata_tampering_deception(
    controller, container, container_bytes, service, wrapper, keys, repository
):
    _create(controller, container, container_bytes)
    protected = repository.load("file-1")
    tampered_tag = bytearray(protected.hmac_tag)
    tampered_tag[0] ^= 0xFF
    protected.hmac_tag = bytes(tampered_tag)
    repository.save(protected)

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.METADATA_TAMPERING


def test_file_integrity_mismatch_triggers_integrity_failure_deception(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes)

    outcome = service.attempt_access("file-1", b"corrupted-container-bytes", wrapper, keys, _Collector())

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.INTEGRITY_FAILURE


def test_expired_access_triggers_access_already_used_deception(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(
        controller,
        container,
        container_bytes,
        expiry_rules=ExpiryRules(expires_at=datetime.now(timezone.utc) - timedelta(days=1)),
    )

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED


def test_unauthorized_device_triggers_device_mismatch_deception(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(
        controller,
        container,
        container_bytes,
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000"),
    )

    outcome = service.attempt_access(
        "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
    )

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH


def test_missing_metadata_triggers_metadata_tampering_deception(service, wrapper, keys):
    outcome = service.attempt_access("nonexistent-file", b"whatever", wrapper, keys, _Collector())

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.METADATA_TAMPERING


# -- Trigger-mapping pure logic --------------------------------------------


def _report(**checks) -> ValidationReport:
    report = ValidationReport(file_id="f")
    for name, passed in checks.items():
        report.add(name, passed)
    return report


def test_mapping_hmac_failure_to_metadata_tampering():
    assert _map_validation_failure_to_trigger(_report(hmac=False)) is DeceptionTrigger.METADATA_TAMPERING


def test_mapping_metadata_present_failure_to_metadata_tampering():
    assert (
        _map_validation_failure_to_trigger(_report(metadata_present=False))
        is DeceptionTrigger.METADATA_TAMPERING
    )


def test_mapping_metadata_integrity_failure_to_metadata_tampering():
    assert (
        _map_validation_failure_to_trigger(_report(hmac=True, metadata_integrity=False))
        is DeceptionTrigger.METADATA_TAMPERING
    )


def test_mapping_file_integrity_failure_to_integrity_failure():
    assert (
        _map_validation_failure_to_trigger(_report(hmac=True, metadata_integrity=True, file_integrity=False))
        is DeceptionTrigger.INTEGRITY_FAILURE
    )


@pytest.mark.parametrize("failing_check", ["expiry", "access_count", "reused_access"])
def test_mapping_policy_failures_to_access_already_used(failing_check):
    checks = {"hmac": True, "metadata_integrity": True, "file_integrity": True, failing_check: False}
    assert _map_validation_failure_to_trigger(_report(**checks)) is DeceptionTrigger.ACCESS_ALREADY_USED


@pytest.mark.parametrize(
    "failing_check",
    ["device_binding", "unauthorized_device", "cloned_usb", "usb_identifier", "machine_fingerprint"],
)
def test_mapping_device_failures_to_device_mismatch(failing_check):
    checks = {
        "hmac": True,
        "metadata_integrity": True,
        "file_integrity": True,
        "expiry": True,
        "access_count": True,
        "reused_access": True,
        failing_check: False,
    }
    assert _map_validation_failure_to_trigger(_report(**checks)) is DeceptionTrigger.DEVICE_MISMATCH


def test_mapping_falls_back_to_integrity_failure_for_unrecognized_failure():
    report = ValidationReport(file_id="f")
    report.ok = False  # a failure with no matching named check at all
    assert _map_validation_failure_to_trigger(report) is DeceptionTrigger.INTEGRITY_FAILURE


# -- Secure cleanup runs after both granted and denied outcomes -----------


def test_successful_view_runs_secure_cleanup(controller, container, container_bytes, service, wrapper, keys):
    _create(controller, container, container_bytes)

    with patch("usb.secure_access_service.cleanup") as mock_cleanup:
        outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.granted is True
    mock_cleanup.assert_called_once_with(CleanupReason.SUCCESSFUL_VIEW)


def test_validation_failure_runs_secure_cleanup(controller, container, container_bytes, service, wrapper, keys):
    _create(controller, container, container_bytes)

    with patch("usb.secure_access_service.cleanup") as mock_cleanup:
        outcome = service.attempt_access("file-1", b"corrupted-container-bytes", wrapper, keys, _Collector())

    assert outcome.granted is False
    mock_cleanup.assert_called_once_with(CleanupReason.VALIDATION_FAILURE)


def test_decrypt_failure_after_validation_pass_runs_secure_cleanup(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    first = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())
    assert first.granted is True

    with patch("usb.secure_access_service.cleanup") as mock_cleanup:
        # Reusing the now-stale `keys` after the file was burned reaches the
        # decrypt-failure branch (metadata tampering is checked first only
        # when the protection keys themselves are stale; here they are not,
        # so this exercises the post-validation decrypt failure path).
        outcome = service.attempt_access("file-1", container_bytes, wrapper, first.protection_keys, _Collector())

    assert outcome.granted is False
    mock_cleanup.assert_called_once_with(CleanupReason.VALIDATION_FAILURE)
