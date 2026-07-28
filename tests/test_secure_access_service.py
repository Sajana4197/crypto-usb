"""Tests for `SecureAccessService`: validate -> decrypt -> (burn) -> deceive."""

import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from crypto.file_encryptor import FileEncryptor
from crypto.key_wrapper import RSAOAEPKeyWrapper
from crypto.secure_cleanup import CleanupReason
from deception.deception_engine import DeceptionEngine
from deception.event_repository import DeceptionEventRepository, PresentedDeviceInfo
from deception.triggers import DeceptionTrigger
from metadata.controller import MetadataController
from metadata.hashing import compute_integrity_hash
from metadata.models import DeviceBinding, ExpiryRules, UsagePolicy
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from security.device_mismatch_throttle import DeviceMismatchThrottle
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from usb.device_detector import USBDevice
from usb.secure_access_service import SecureAccessService, _map_validation_failure_to_trigger
from validation.usb_identifier import HardwareDescriptor
from validation.validation_engine import ValidationEngine, ValidationReport

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


@pytest.fixture
def tracker():
    return MagicMock()


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


def test_mismatched_hardware_descriptor_triggers_device_mismatch_deception(
    controller, container, container_bytes, service, wrapper, keys
):
    """A cloned drive reproducing the volume-level usb_serial exactly is
    still caught here via the descriptor-level hardware serial (Phase 2)."""
    _create(
        controller,
        container,
        container_bytes,
        device_binding=DeviceBinding(
            bound=True,
            device_id="E:\\",
            usb_serial="ABCD:FAT32:1000",
            vendor_id="SANDISK",
            product_id="CRUZER_BLADE",
            hardware_serial="4C530001A2B3C4D5",
        ),
    )

    outcome = service.attempt_access(
        "file-1",
        container_bytes,
        wrapper,
        keys,
        _Collector(),
        current_usb_identifier="ABCD:FAT32:1000",
        current_hardware_descriptor=HardwareDescriptor(
            vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="CLONED_SERIAL"
        ),
    )

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH


# -- Cryptographic USB binding via HKDF (Phase 3) ----------------------------


def _create_device_only_file(controller, wrapper, usb_serial: str, descriptor: HardwareDescriptor, file_id="file-1"):
    """Unlike `_create`, builds its own container wrapped with a
    `DeviceBoundKeyWrapper` derived from `usb_serial`/`descriptor` — the
    shared `container`/`container_bytes` fixtures are wrapped with the
    plain `wrapper` only, which a DEVICE_ONLY record must never be."""
    from crypto.file_encryptor import FileEncryptor
    from crypto.key_manager import derive_device_binding_key
    from crypto.key_wrapper import DeviceBoundKeyWrapper
    from metadata.hashing import compute_integrity_hash
    from validation.usb_identifier import device_fingerprint_material

    device_key = derive_device_binding_key(device_fingerprint_material(usb_serial, descriptor))
    device_bound_wrapper = DeviceBoundKeyWrapper(wrapper, device_key)
    container = FileEncryptor().encrypt_bytes(PLAINTEXT, device_bound_wrapper)
    container_bytes = container.serialize()
    integrity_hash = compute_integrity_hash(container_bytes)
    controller.create(
        file_id=file_id,
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
        device_binding=DeviceBinding(
            bound=True,
            device_id="E:\\",
            usb_serial=usb_serial,
            vendor_id=descriptor.vendor_id,
            product_id=descriptor.product_id,
            hardware_serial=descriptor.hardware_serial,
        ),
    )
    return container_bytes


def test_device_only_file_with_matching_device_decrypts_successfully(controller, wrapper, service, keys):
    usb_serial = "SERIAL-A:FAT32:1000000"
    descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="AAA111")
    container_bytes = _create_device_only_file(controller, wrapper, usb_serial, descriptor)
    on_granted = _Collector()

    outcome = service.attempt_access(
        "file-1",
        container_bytes,
        wrapper,
        keys,
        on_granted,
        current_usb_identifier=usb_serial,
        current_hardware_descriptor=descriptor,
    )

    assert outcome.granted is True
    assert on_granted.calls == [PLAINTEXT]


def test_device_only_file_with_a_different_device_is_denied(controller, wrapper, service, keys):
    """End-to-end: a different device is caught by
    `validation.device_binding_validator`'s policy check before
    `attempt_access` ever attempts to decrypt — the pure crypto-layer
    proof (no validation involved at all) lives in
    `tests.test_secure_storage_service`."""
    usb_serial = "SERIAL-A:FAT32:1000000"
    descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="AAA111")
    container_bytes = _create_device_only_file(controller, wrapper, usb_serial, descriptor)

    outcome = service.attempt_access(
        "file-1",
        container_bytes,
        wrapper,
        keys,
        _Collector(),
        current_usb_identifier="SERIAL-B:FAT32:1000000",
        current_hardware_descriptor=HardwareDescriptor(
            vendor_id="KINGSTON", product_id="DATATRAVELER", hardware_serial="BBB222"
        ),
    )

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH


# -- Forensic logging of the presented device (Phase 5) ---------------------


def test_device_mismatch_records_the_presented_devices_identity(controller, repository, wrapper, keys):
    """The core Phase 5 proof: a DEVICE_MISMATCH deception ends up in the
    audit trail carrying the *presented* (wrong) device's identity, not
    just the fact that a mismatch occurred."""
    usb_serial = "SERIAL-A:FAT32:1000000"
    descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="AAA111")
    container_bytes = _create_device_only_file(controller, wrapper, usb_serial, descriptor)

    conn = sqlite3.connect(":memory:")
    event_repository = DeceptionEventRepository(conn)
    deception_engine = DeceptionEngine(event_repository=event_repository)
    service = SecureAccessService(repository, deception_engine=deception_engine)

    presented_device = USBDevice(
        device_id="F:\\",
        mount_point="F:\\",
        label="ROGUE-USB",
        filesystem="FAT32",
        total_bytes=2_000_000,
        free_bytes=1_000_000,
        is_removable=True,
    )
    outcome = service.attempt_access(
        "file-1",
        container_bytes,
        wrapper,
        keys,
        _Collector(),
        current_device=presented_device,
        current_usb_identifier="SERIAL-B:FAT32:2000000",
        current_hardware_descriptor=HardwareDescriptor(
            vendor_id="KINGSTON", product_id="DATATRAVELER", hardware_serial="BBB222"
        ),
    )
    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH

    events = event_repository.list_events()
    assert len(events) == 1
    assert events[0].device_info == PresentedDeviceInfo(
        usb_serial="SERIAL-B:FAT32:2000000",
        vendor_id="KINGSTON",
        product_id="DATATRAVELER",
        hardware_serial="BBB222",
        mount_point="F:\\",
        label="ROGUE-USB",
    )
    # Never the enrolled (correct) device's identity -- this is a record
    # of what actually tried to open the file.
    assert events[0].device_info.usb_serial != usb_serial


def test_wrong_credentials_deception_records_no_device_when_none_presented(repository, wrapper, keys):
    """A trigger unrelated to any device (e.g. a decoy session) still
    writes a well-formed, empty `PresentedDeviceInfo` -- never crashes,
    never fabricates a device that wasn't actually there."""
    conn = sqlite3.connect(":memory:")
    event_repository = DeceptionEventRepository(conn)
    deception_engine = DeceptionEngine(event_repository=event_repository)
    service = SecureAccessService(repository, deception_engine=deception_engine)

    outcome = service.attempt_access(
        "file-1", b"whatever-bytes", wrapper, keys, _Collector(), force_deception=True
    )

    assert outcome.granted is False
    events = event_repository.list_events()
    assert len(events) == 1
    assert events[0].device_info == PresentedDeviceInfo()


# -- Device-mismatch rate-limiting (Phase 4) ---------------------------------


def _spy_on_validate(monkeypatch) -> list:
    """Patches `ValidationEngine.validate` with a wrapper that still calls
    through to the real implementation (so behavior is unaffected) but
    records each call -- used to prove a throttled attempt skips
    validation entirely, rather than merely failing it again. A plain
    `MagicMock(wraps=...)` doesn't work here: replacing a class method
    with a `MagicMock` instance loses Python's normal descriptor-based
    `self` binding, so a real (non-throttled) call would crash trying to
    use the `file_id` argument as `self`.
    """
    original_validate = ValidationEngine.validate
    calls: list = []

    def _spy(self, *args, **kwargs):
        calls.append((args, kwargs))
        return original_validate(self, *args, **kwargs)

    monkeypatch.setattr(ValidationEngine, "validate", _spy)
    return calls


def test_repeated_device_mismatches_lock_out_further_attempts_without_revalidating(
    controller, container, container_bytes, service, wrapper, keys, monkeypatch
):
    _create(
        controller,
        container,
        container_bytes,
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000"),
    )

    for _ in range(MAX_FAILED_ATTEMPTS):
        outcome = service.attempt_access(
            "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
        )
        assert outcome.granted is False
        assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH

    # Now throttled: spy on ValidationEngine.validate to prove the next
    # attempt is deceived WITHOUT re-running validation at all -- a real
    # rate limit, not just another ordinary validation failure.
    calls = _spy_on_validate(monkeypatch)

    outcome = service.attempt_access(
        "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
    )

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH
    assert calls == []


def test_successful_access_resets_the_device_mismatch_counter(
    controller, container, container_bytes, service, wrapper, keys, monkeypatch
):
    # `machine_fingerprint` is deliberately set (DEVICE_AND_MACHINE-shaped,
    # not DEVICE_ONLY) -- a binding with `bound=True` and no
    # `machine_fingerprint` is Phase 3's DEVICE_ONLY signature, which would
    # require this test's plain (non-device-bound) `container`/`wrapper`
    # fixtures to be wrapped with a `DeviceBoundKeyWrapper` to decrypt.
    _create(
        controller,
        container,
        container_bytes,
        device_binding=DeviceBinding(
            bound=True,
            device_id="E:\\",
            label="MYUSB",
            usb_serial="ABCD:FAT32:1000",
            machine_fingerprint="fixed-machine-fingerprint",
        ),
    )

    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        outcome = service.attempt_access(
            "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
        )
        assert outcome.granted is False

    matching_device = USBDevice(
        device_id="E:\\",
        mount_point="E:\\",
        label="MYUSB",
        filesystem="FAT32",
        total_bytes=1_000_000,
        free_bytes=500_000,
        is_removable=True,
    )
    outcome = service.attempt_access(
        "file-1",
        container_bytes,
        wrapper,
        keys,
        _Collector(),
        current_device=matching_device,
        current_usb_identifier="ABCD:FAT32:1000",
        current_machine_fingerprint="fixed-machine-fingerprint",
    )
    assert outcome.granted is True

    # One more mismatch alone must NOT be throttled -- proving the
    # near-threshold count from before the successful access was reset,
    # not merely paused. Spying on ValidationEngine.validate confirms
    # this denial came from a genuine re-validation, not a short-circuit.
    calls = _spy_on_validate(monkeypatch)

    outcome = service.attempt_access(
        "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
    )

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH
    assert len(calls) == 1


def test_device_mismatch_lockout_never_affects_a_different_file_id(
    controller, container, container_bytes, service, wrapper, keys, monkeypatch
):
    _create(
        controller,
        container,
        container_bytes,
        file_id="file-locked",
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000"),
    )
    _create(
        controller,
        container,
        container_bytes,
        file_id="file-other",
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="WXYZ:FAT32:2000"),
    )

    for _ in range(MAX_FAILED_ATTEMPTS):
        service.attempt_access(
            "file-locked", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
        )

    # "file-locked" is now throttled -- an unrelated file_id must still
    # run real validation, proven the same way: ValidationEngine.validate
    # is actually invoked for it.
    calls = _spy_on_validate(monkeypatch)

    outcome = service.attempt_access(
        "file-other", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
    )

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH
    assert len(calls) == 1


def test_device_mismatch_throttle_instance_is_reused_across_service_calls_when_supplied(
    controller, container, container_bytes, repository, wrapper, keys
):
    """Confirms the constructor wiring: an explicitly supplied throttle
    accumulates state across separate `SecureAccessService` instances,
    exactly like `ui.pages.decryption_page.DecryptionPage` relies on
    (a fresh service per view attempt, one shared throttle)."""
    _create(
        controller,
        container,
        container_bytes,
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000"),
    )
    throttle = DeviceMismatchThrottle()

    for _ in range(MAX_FAILED_ATTEMPTS):
        fresh_service = SecureAccessService(repository, device_mismatch_throttle=throttle)
        fresh_service.attempt_access(
            "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
        )

    assert throttle.is_locked("file-1") is True


def test_missing_metadata_triggers_metadata_tampering_deception(service, wrapper, keys):
    outcome = service.attempt_access("nonexistent-file", b"whatever", wrapper, keys, _Collector())

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.METADATA_TAMPERING


# -- record_tampering_event fires only for genuine tampering triggers -----


def test_metadata_tampering_deception_records_tampering_event(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(controller, container, container_bytes)
    protected = repository.load("file-1")
    tampered_tag = bytearray(protected.hmac_tag)
    tampered_tag[0] ^= 0xFF
    protected.hmac_tag = bytes(tampered_tag)
    repository.save(protected)
    service = SecureAccessService(repository, usage_tracker=tracker)

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.deception.trigger is DeceptionTrigger.METADATA_TAMPERING
    tracker.record_tampering_event.assert_called_once_with(tracker.start_session.return_value)


def test_integrity_failure_deception_records_tampering_event(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(controller, container, container_bytes)
    service = SecureAccessService(repository, usage_tracker=tracker)

    outcome = service.attempt_access("file-1", b"corrupted-container-bytes", wrapper, keys, _Collector())

    assert outcome.deception.trigger is DeceptionTrigger.INTEGRITY_FAILURE
    tracker.record_tampering_event.assert_called_once_with(tracker.start_session.return_value)


def test_device_mismatch_deception_does_not_record_tampering_event(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(
        controller,
        container,
        container_bytes,
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD:FAT32:1000"),
    )
    service = SecureAccessService(repository, usage_tracker=tracker)

    outcome = service.attempt_access(
        "file-1", container_bytes, wrapper, keys, _Collector(), current_usb_identifier=None
    )

    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH
    tracker.record_tampering_event.assert_not_called()


def test_access_already_used_deception_does_not_record_tampering_event(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(
        controller,
        container,
        container_bytes,
        expiry_rules=ExpiryRules(expires_at=datetime.now(timezone.utc) - timedelta(days=1)),
    )
    service = SecureAccessService(repository, usage_tracker=tracker)

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED
    tracker.record_tampering_event.assert_not_called()


def test_decrypt_failure_after_validation_pass_does_not_record_tampering_event(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    # The reuse-of-a-burned-file path (decrypt fails despite validation
    # passing) maps to ACCESS_ALREADY_USED too, but via a different branch
    # than the validation-failure one above — confirm it's equally excluded.
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    service = SecureAccessService(repository, usage_tracker=tracker)
    first = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())
    assert first.granted is True
    tracker.record_tampering_event.reset_mock()

    outcome = service.attempt_access("file-1", container_bytes, wrapper, first.protection_keys, _Collector())

    assert outcome.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED
    tracker.record_tampering_event.assert_not_called()


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


# -- force_deception short-circuits before any real work happens ----------


def test_force_deception_returns_denied_outcome_with_deception(service, wrapper, keys):
    outcome = service.attempt_access(
        "file-1", b"whatever-bytes", wrapper, keys, _Collector(), force_deception=True
    )

    assert outcome.granted is False
    assert outcome.deception is not None
    assert outcome.deception.trigger is DeceptionTrigger.WRONG_CREDENTIALS


def test_force_deception_never_calls_on_granted(service, wrapper, keys):
    on_granted = _Collector()

    service.attempt_access("file-1", b"whatever-bytes", wrapper, keys, on_granted, force_deception=True)

    assert on_granted.calls == []


def test_force_deception_does_not_touch_metadata_or_validation(
    controller, container, container_bytes, service, wrapper, keys, repository
):
    # A real, valid record exists — proving force_deception short-circuits
    # before ValidationEngine runs, not merely that validation happens to
    # fail for this input.
    _create(controller, container, container_bytes)

    with patch("usb.secure_access_service.ValidationEngine") as mock_engine_cls:
        outcome = service.attempt_access(
            "file-1", container_bytes, wrapper, keys, _Collector(), force_deception=True
        )

    mock_engine_cls.assert_not_called()
    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.WRONG_CREDENTIALS
    # The real record is untouched: access_count was never incremented.
    reopened = MetadataProtector(keys).unprotect(repository.load("file-1"))
    assert reopened.access_count == 0


def test_force_deception_does_not_start_a_usage_tracker_session(
    controller, container, container_bytes, wrapper, keys, repository
):
    _create(controller, container, container_bytes)
    tracker = MagicMock()
    service = SecureAccessService(repository, usage_tracker=tracker)

    service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector(), force_deception=True)

    tracker.start_session.assert_not_called()


def test_force_deception_does_not_run_cleanup_paths_that_imply_real_access(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes)

    with patch("usb.secure_access_service.cleanup") as mock_cleanup:
        service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector(), force_deception=True)

    mock_cleanup.assert_not_called()


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


# -- record_close only fires via the returned callback (Phase 22) ---------


def test_no_usage_tracker_means_no_view_closed_or_capture_callbacks(
    controller, container, container_bytes, service, wrapper, keys
):
    _create(controller, container, container_bytes)

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.on_view_closed is None
    assert outcome.on_screen_capture_detected is None


def test_force_deception_outcome_has_no_view_closed_or_capture_callbacks(service, wrapper, keys):
    outcome = service.attempt_access(
        "file-1", b"whatever-bytes", wrapper, keys, _Collector(), force_deception=True
    )

    assert outcome.on_view_closed is None
    assert outcome.on_screen_capture_detected is None


def test_validation_failure_populates_callbacks_without_closing_synchronously(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(controller, container, container_bytes)
    service = SecureAccessService(repository, usage_tracker=tracker)

    outcome = service.attempt_access("file-1", b"corrupted-container-bytes", wrapper, keys, _Collector())

    assert outcome.granted is False
    assert outcome.on_view_closed is not None
    assert outcome.on_screen_capture_detected is not None
    tracker.record_close.assert_not_called()
    tracker.record_screen_capture_attempt.assert_not_called()

    outcome.on_view_closed()
    tracker.record_close.assert_called_once_with(tracker.start_session.return_value)

    outcome.on_screen_capture_detected()
    tracker.record_screen_capture_attempt.assert_called_once_with(tracker.start_session.return_value)


def test_decrypt_failure_populates_callbacks_without_closing_synchronously(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(controller, container, container_bytes, usage_policy=UsagePolicy(one_time_access=True))
    service = SecureAccessService(repository, usage_tracker=tracker)
    first = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())
    assert first.granted is True
    tracker.record_close.reset_mock()

    outcome = service.attempt_access("file-1", container_bytes, wrapper, first.protection_keys, _Collector())

    assert outcome.granted is False
    assert outcome.on_view_closed is not None
    assert outcome.on_screen_capture_detected is not None
    tracker.record_close.assert_not_called()

    outcome.on_view_closed()
    tracker.record_close.assert_called_once_with(tracker.start_session.return_value)


def test_successful_access_populates_callbacks_without_closing_synchronously(
    controller, container, container_bytes, wrapper, keys, repository, tracker
):
    _create(controller, container, container_bytes)
    service = SecureAccessService(repository, usage_tracker=tracker)

    outcome = service.attempt_access("file-1", container_bytes, wrapper, keys, _Collector())

    assert outcome.granted is True
    assert outcome.on_view_closed is not None
    assert outcome.on_screen_capture_detected is not None
    tracker.record_close.assert_not_called()
    tracker.record_screen_capture_attempt.assert_not_called()

    outcome.on_view_closed()
    tracker.record_close.assert_called_once_with(tracker.start_session.return_value)

    outcome.on_screen_capture_detected()
    tracker.record_screen_capture_attempt.assert_called_once_with(tracker.start_session.return_value)
