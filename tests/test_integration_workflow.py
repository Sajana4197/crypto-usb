"""Phase 14: end-to-end integration tests wiring together every completed
module — Sender, Encryption, Metadata, USB Storage, Authentication,
Validation, RAM Decryption, Viewer, Usage Tracking, One-Time Access, and
Deception — through the real service layer, no mocks.

Each test drives the exact sequence the approved research architecture
describes: a plaintext file (Sender) is hybrid-encrypted (Encryption)
and written to a USB device as a self-contained secure container with
its metadata also persisted locally (Metadata, USB Storage); an
authenticated user (Authentication) later reads it back, subject to
every access-time check (Validation) and — if all checks pass — RAM-only
decryption (RAM Decryption) and on-screen rendering (Viewer); every
attempt is recorded in the tamper-evident usage log (Usage Tracking);
a one-time-access file is unusable after its single legitimate view
(One-Time Access); and any failure at any stage is met with fabricated
content (Deception) rather than a revealing error.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from crypto.key_wrapper import RSAOAEPKeyWrapper
from deception.triggers import DeceptionTrigger
from metadata.models import ExpiryRules, UsagePolicy
from metadata.protection import generate_protection_keys
from metadata.repository import MetadataRepository
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.exceptions import InvalidCredentialsError
from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
from usb.device_detector import USBDevice
from usb.secure_access_service import SecureAccessService
from usb.secure_storage_service import SecureStorageService
from validation.machine_fingerprint import compute_machine_fingerprint
from validation.usb_identifier import compute_usb_identifier
from viewer.secure_viewer_widget import CONTENT_TYPE_TXT, SecureViewerWidget

PLAINTEXT = b"The quarterly research findings are strictly confidential."


def _device(mount_point: str, free_bytes: int = 100_000_000) -> USBDevice:
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="RESEARCH-USB",
        filesystem="FAT32",
        total_bytes=free_bytes * 2,
        free_bytes=free_bytes,
        is_removable=True,
    )


class _Collector:
    """An `on_granted` callback that renders through the real Secure Viewer
    and records what it was handed."""

    def __init__(self, viewer: SecureViewerWidget):
        self.viewer = viewer
        self.calls: list[bytes] = []

    def __call__(self, buffer, metadata) -> None:
        content = bytes(buffer)
        self.calls.append(content)
        self.viewer.display(content, CONTENT_TYPE_TXT)


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def db_connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def auth_controller(db_connection):
    return AuthController(AccountRepository(db_connection))


@pytest.fixture
def metadata_repository(db_connection):
    return MetadataRepository(db_connection)


@pytest.fixture
def tracker(db_connection):
    return UsageTracker(generate_tracking_keys(), TrackingRepository(db_connection))


@pytest.fixture
def protection_keys():
    return generate_protection_keys()


@pytest.fixture
def key_wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


@pytest.fixture
def other_key_wrapper(other_rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key)


@pytest.fixture
def device(tmp_path):
    mount = tmp_path / "usb"
    mount.mkdir()
    return _device(str(mount))


@pytest.fixture
def source_file(tmp_path):
    path = tmp_path / "findings.txt"
    path.write_bytes(PLAINTEXT)
    return path


@pytest.fixture
def authenticated_session(auth_controller):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    return auth_controller.authenticate_password("owner-1", "correct-horse-battery")


def _store(write_service, source_file, device, key_wrapper, session, metadata_repository, **kwargs):
    return write_service.store_file(
        source_file,
        device,
        key_wrapper,
        owner_id=session.owner_id,
        metadata_repository=metadata_repository,
        bind_to_device=True,
        **kwargs,
    )


def _access_service(metadata_repository, tracker):
    return SecureAccessService(metadata_repository, usage_tracker=tracker)


# -- The golden path: every module connected, end to end -------------------


def test_full_pipeline_write_then_authenticated_view(
    app, authenticated_session, metadata_repository, protection_keys, key_wrapper, device, source_file, tracker
):
    write_service = SecureStorageService()
    result = _store(
        write_service, source_file, device, key_wrapper, authenticated_session, metadata_repository,
        protection_keys=protection_keys,
    )
    assert result.destination.exists()
    assert Path(result.destination).read_bytes().find(PLAINTEXT) == -1  # never plaintext on disk

    file_id, encrypted_bytes = write_service.read_encrypted_file_bytes(result.destination)
    assert file_id == result.file_id

    viewer = SecureViewerWidget()
    collector = _Collector(viewer)
    try:
        outcome = _access_service(metadata_repository, tracker).attempt_access(
            file_id,
            encrypted_bytes,
            key_wrapper,
            result.protection_keys,
            collector,
            current_device=device,
            current_usb_identifier=compute_usb_identifier(device),
            current_machine_fingerprint=compute_machine_fingerprint(),
            user=authenticated_session.owner_id,
        )

        assert outcome.granted is True
        assert outcome.deception is None
        assert collector.calls == [PLAINTEXT]
        assert viewer._text_view.toPlainText() == PLAINTEXT.decode("utf-8")
    finally:
        viewer.close()

    records = tracker.read_all_records()
    assert len(records) == 1
    assert records[0].user == "owner-1"
    assert records[0].authentication_result is True
    assert records[0].validation_result is True
    assert records[0].open_time is not None
    assert records[0].close_time is not None
    assert tracker.verify_log_integrity().ok is True


def test_one_time_access_is_unusable_after_its_single_view(
    app, authenticated_session, metadata_repository, protection_keys, key_wrapper, device, source_file, tracker
):
    write_service = SecureStorageService()
    result = _store(
        write_service, source_file, device, key_wrapper, authenticated_session, metadata_repository,
        protection_keys=protection_keys, usage_policy=UsagePolicy(one_time_access=True),
    )
    file_id, encrypted_bytes = write_service.read_encrypted_file_bytes(result.destination)
    access_service = _access_service(metadata_repository, tracker)

    viewer = SecureViewerWidget()
    try:
        first = access_service.attempt_access(
            file_id, encrypted_bytes, key_wrapper, result.protection_keys, _Collector(viewer),
            current_device=device, current_usb_identifier=compute_usb_identifier(device),
            current_machine_fingerprint=compute_machine_fingerprint(), user=authenticated_session.owner_id,
        )
        assert first.granted is True

        # Second attempt: same on-device container, rotated protection keys
        # from the burn — this is the only legitimate way a real caller
        # would still have working credentials for the metadata record.
        second = access_service.attempt_access(
            file_id, encrypted_bytes, key_wrapper, first.protection_keys, _Collector(viewer),
            current_device=device, current_usb_identifier=compute_usb_identifier(device),
            current_machine_fingerprint=compute_machine_fingerprint(), user=authenticated_session.owner_id,
        )
    finally:
        viewer.close()

    assert second.granted is False
    assert second.deception is not None
    assert second.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED
    assert PLAINTEXT not in second.deception.content

    records = tracker.read_all_records()
    assert len(records) == 2
    assert records[0].validation_result is True
    assert records[1].validation_result is True  # validation passes; decrypt is what fails
    assert tracker.verify_log_integrity().ok is True


def test_device_mismatch_triggers_deception_not_a_revealing_error(
    app, authenticated_session, metadata_repository, protection_keys, key_wrapper, device, source_file, tracker
):
    write_service = SecureStorageService()
    result = _store(
        write_service, source_file, device, key_wrapper, authenticated_session, metadata_repository,
        protection_keys=protection_keys,
    )
    file_id, encrypted_bytes = write_service.read_encrypted_file_bytes(result.destination)

    viewer = SecureViewerWidget()
    try:
        outcome = _access_service(metadata_repository, tracker).attempt_access(
            file_id, encrypted_bytes, key_wrapper, result.protection_keys, _Collector(viewer),
            current_device=None, current_usb_identifier=None, current_machine_fingerprint=None,
            user=authenticated_session.owner_id,
        )
    finally:
        viewer.close()

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.DEVICE_MISMATCH
    assert PLAINTEXT not in outcome.deception.content

    records = tracker.read_all_records()
    assert records[0].validation_result is False


def test_wrong_key_wrapper_is_deceived_not_raised(
    app, authenticated_session, metadata_repository, protection_keys, key_wrapper, other_key_wrapper,
    device, source_file, tracker,
):
    write_service = SecureStorageService()
    result = _store(
        write_service, source_file, device, key_wrapper, authenticated_session, metadata_repository,
        protection_keys=protection_keys,
    )
    file_id, encrypted_bytes = write_service.read_encrypted_file_bytes(result.destination)

    viewer = SecureViewerWidget()
    try:
        outcome = _access_service(metadata_repository, tracker).attempt_access(
            file_id, encrypted_bytes, other_key_wrapper, result.protection_keys, _Collector(viewer),
            current_device=device, current_usb_identifier=compute_usb_identifier(device),
            current_machine_fingerprint=compute_machine_fingerprint(), user=authenticated_session.owner_id,
        )
    finally:
        viewer.close()

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED


def test_expired_file_is_deceived(
    app, authenticated_session, metadata_repository, protection_keys, key_wrapper, device, source_file, tracker
):
    from datetime import datetime, timedelta, timezone

    write_service = SecureStorageService()
    result = _store(
        write_service, source_file, device, key_wrapper, authenticated_session, metadata_repository,
        protection_keys=protection_keys,
        expiry_rules=ExpiryRules(expires_at=datetime.now(timezone.utc) - timedelta(days=1)),
    )
    file_id, encrypted_bytes = write_service.read_encrypted_file_bytes(result.destination)

    viewer = SecureViewerWidget()
    try:
        outcome = _access_service(metadata_repository, tracker).attempt_access(
            file_id, encrypted_bytes, key_wrapper, result.protection_keys, _Collector(viewer),
            current_device=device, current_usb_identifier=compute_usb_identifier(device),
            current_machine_fingerprint=compute_machine_fingerprint(), user=authenticated_session.owner_id,
        )
    finally:
        viewer.close()

    assert outcome.granted is False
    assert outcome.deception.trigger is DeceptionTrigger.ACCESS_ALREADY_USED


# -- Authentication gates the whole workflow -------------------------------


def test_failed_authentication_never_reaches_the_file(auth_controller):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")

    with pytest.raises(InvalidCredentialsError):
        auth_controller.authenticate_password("owner-1", "wrong-password")


# -- Metadata + USB Storage: both persisted copies agree -------------------


def test_embedded_and_repository_metadata_copies_agree(
    authenticated_session, metadata_repository, protection_keys, key_wrapper, device, source_file
):
    write_service = SecureStorageService()
    result = _store(
        write_service, source_file, device, key_wrapper, authenticated_session, metadata_repository,
        protection_keys=protection_keys,
    )

    container = write_service._storage_writer.read_container(result.destination)
    from metadata.protection import MetadataProtector

    protector = MetadataProtector(protection_keys)
    embedded = protector.unprotect(container.protected_metadata)
    from_repository = protector.unprotect(metadata_repository.load(result.file_id))

    assert embedded.integrity_hash == from_repository.integrity_hash
    assert embedded.wrapped_key == from_repository.wrapped_key
    assert embedded.device_binding.usb_serial == from_repository.device_binding.usb_serial
    assert from_repository.device_binding.bound is True
