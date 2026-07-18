"""Integration test: `EncryptionPage` writes a secure container and exports
its file-wrapping private key exactly as a user would; `DecryptionPage`
reads the same container back through the real service layer, sharing
the same `MetadataRepository` / `MetadataProtectionKeys` /
`SessionManager` / `UsageTracker` that `ui.main_window.MainWindow`
wires between them in the real application.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog

from deception.event_repository import DeceptionEventRepository
from metadata.protection import generate_protection_keys
from metadata.repository import MetadataRepository
from security.auth_session import AuthSession, SessionManager
from security.models import AuthMethod
from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
from ui.pages.decryption_page import DecryptionPage
from ui.pages.encryption_page import EncryptionPage
from usb.device_detector import USBDevice


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


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def db_connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def metadata_repository(db_connection):
    return MetadataRepository(db_connection)


@pytest.fixture
def protection_keys():
    return generate_protection_keys()


@pytest.fixture
def session_manager():
    manager = SessionManager()
    manager.set(
        AuthSession(owner_id="owner-1", method=AuthMethod.PASSWORD, authenticated_at=datetime.now(timezone.utc))
    )
    return manager


@pytest.fixture
def tracker(db_connection):
    return UsageTracker(generate_tracking_keys(), TrackingRepository(db_connection))


@pytest.fixture
def encryption_page(app, metadata_repository, protection_keys, session_manager):
    return EncryptionPage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=session_manager
    )


@pytest.fixture
def decryption_page(app, metadata_repository, protection_keys, session_manager, tracker):
    page = DecryptionPage(
        metadata_repository=metadata_repository,
        protection_keys=protection_keys,
        session_manager=session_manager,
        usage_tracker=tracker,
    )
    yield page
    if page._active_viewer is not None and not page._active_viewer.is_closed:
        page._active_viewer.close()


def test_encryption_page_writes_and_decryption_page_reads_it_back(tmp_path, encryption_page, decryption_page, tracker):
    source = tmp_path / "findings.txt"
    plaintext = "the quarterly figures are confidential"
    source.write_text(plaintext, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    # -- Write via EncryptionPage, exactly as a user driving the UI would. --
    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    encryption_page._on_write_clicked()

    written = list(device_dir.glob("*.cusc"))
    assert len(written) == 1
    assert "verified" in encryption_page.status_label.text().lower()

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()
    assert exported_key_path.exists()

    # -- Read it back via DecryptionPage. --
    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()
    assert decryption_page._containers == written

    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("a-strong-passphrase")
    decryption_page._on_load_key_clicked()
    assert decryption_page._key_wrapper is not None
    assert "loaded" in decryption_page.status_label.text().lower()

    decryption_page.container_table.selectRow(0)
    assert decryption_page._selected_container == written[0]
    assert decryption_page.view_button.isEnabled() is True

    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == plaintext

    # The usage session is only sealed when the viewer is actually closed
    # (Phase 22) — not when decryption finished, which already happened
    # above with the viewer still open.
    assert tracker.read_all_records() == []
    decryption_page._active_viewer.close()

    records = tracker.read_all_records()
    assert len(records) == 1
    assert records[0].user == "owner-1"
    assert records[0].authentication_result is True
    assert records[0].validation_result is True
    assert tracker.verify_log_integrity().ok is True


def test_view_refused_without_an_authenticated_session(tmp_path, metadata_repository, protection_keys, app):
    unauthenticated = SessionManager()
    page = DecryptionPage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=unauthenticated
    )
    page._selected_container = tmp_path / "does-not-matter.cusc"
    page._key_wrapper = object()  # any non-None sentinel; the auth check short-circuits first

    page._on_view_clicked()

    assert page._active_viewer is None
    assert "signed in" in page.status_label.text().lower()


def test_wrong_passphrase_fails_to_load_key(tmp_path, decryption_page):
    from crypto import rsa_keypair

    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(pem)

    decryption_page.key_path_label.setText(str(key_path))
    decryption_page.passphrase_edit.setText("wrong-passphrase")
    decryption_page._on_load_key_clicked()

    assert decryption_page._key_wrapper is None
    assert "failed" in decryption_page.status_label.text().lower()


def test_corrupt_container_shows_an_error_instead_of_crashing(tmp_path, decryption_page):
    corrupt = tmp_path / "corrupt.cusc"
    corrupt.write_bytes(b"not a real secure container")

    decryption_page._selected_container = corrupt
    decryption_page._key_wrapper = object()  # any non-None sentinel

    decryption_page._on_view_clicked()  # must not raise

    assert decryption_page._active_viewer is None
    assert "could not read" in decryption_page.status_label.text().lower()


def test_deleted_container_shows_an_error_instead_of_crashing(tmp_path, decryption_page):
    missing = tmp_path / "gone.cusc"

    decryption_page._selected_container = missing
    decryption_page._key_wrapper = object()

    decryption_page._on_view_clicked()  # must not raise

    assert decryption_page._active_viewer is None
    assert "could not read" in decryption_page.status_label.text().lower()


# -- force_deception is threaded from a decoy session (Phase 20) -----------


def _stub_attempt_access_call(page, tmp_path, granted: bool = False):
    """Wire up `page` to call a mocked `SecureAccessService.attempt_access`
    instead of the real storage/decrypt path, and return the mock so the
    caller can inspect how it was invoked."""
    page._selected_container = tmp_path / "container.cusc"
    page._key_wrapper = object()  # any non-None sentinel
    page._storage_service = MagicMock()
    page._storage_service.read_encrypted_file_bytes.return_value = ("file-1", b"encrypted-bytes")

    mock_deception = MagicMock()
    mock_deception.content = b"decoy content"
    mock_deception.mime_type = "text/plain"
    mock_deception.trigger.value = "wrong_credentials"

    mock_outcome = MagicMock(granted=granted, deception=None if granted else mock_deception)
    return mock_outcome


def test_view_click_forces_deception_for_a_decoy_session(tmp_path, app, metadata_repository, protection_keys):
    decoy_session_manager = SessionManager()
    decoy_session_manager.set(
        AuthSession(
            owner_id="owner-1",
            method=AuthMethod.PASSWORD,
            authenticated_at=datetime.now(timezone.utc),
            is_decoy=True,
        )
    )
    page = DecryptionPage(
        metadata_repository=metadata_repository,
        protection_keys=protection_keys,
        session_manager=decoy_session_manager,
    )
    mock_outcome = _stub_attempt_access_call(page, tmp_path)

    try:
        with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
            mock_service_cls.return_value.attempt_access.return_value = mock_outcome
            page._on_view_clicked()

        _, kwargs = mock_service_cls.return_value.attempt_access.call_args
        assert kwargs["force_deception"] is True
    finally:
        if page._active_viewer is not None and not page._active_viewer.is_closed:
            page._active_viewer.close()


def test_view_click_does_not_force_deception_for_a_real_session(
    tmp_path, decryption_page
):
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path, granted=True)

    try:
        with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
            mock_service_cls.return_value.attempt_access.return_value = mock_outcome
            decryption_page._on_view_clicked()

        _, kwargs = mock_service_cls.return_value.attempt_access.call_args
        assert kwargs["force_deception"] is False
    finally:
        if decryption_page._active_viewer is not None and not decryption_page._active_viewer.is_closed:
            decryption_page._active_viewer.close()


def test_view_click_with_decoy_session_and_no_metadata_repository_reaches_deception(
    tmp_path, app, protection_keys
):
    """A decoy session never gets a real `metadata_repository`
    (`MainWindow._build_shared_services` returns `None` whenever there's
    no `vault_key`, which is always true for a decoy session) — viewing
    a file must still reach the deception path instead of being
    intercepted by the "no metadata repository" guard."""
    decoy_session_manager = SessionManager()
    decoy_session_manager.set(
        AuthSession(
            owner_id="owner-1",
            method=AuthMethod.PASSWORD,
            authenticated_at=datetime.now(timezone.utc),
            is_decoy=True,
        )
    )
    page = DecryptionPage(
        metadata_repository=None,
        protection_keys=protection_keys,
        session_manager=decoy_session_manager,
    )
    mock_outcome = _stub_attempt_access_call(page, tmp_path)

    try:
        with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
            mock_service_cls.return_value.attempt_access.return_value = mock_outcome
            page._on_view_clicked()

        assert "no metadata repository" not in page.status_label.text().lower()
        mock_service_cls.return_value.attempt_access.assert_called_once()
        _, kwargs = mock_service_cls.return_value.attempt_access.call_args
        assert kwargs["force_deception"] is True
        assert page._active_viewer is not None
        assert page._active_viewer._text_view.toPlainText() == "decoy content"
    finally:
        if page._active_viewer is not None and not page._active_viewer.is_closed:
            page._active_viewer.close()


def test_view_click_with_no_metadata_repository_and_real_session_shows_real_error(
    tmp_path, app, protection_keys, session_manager
):
    """A genuinely misconfigured non-decoy session (no `db_manager` at
    all) must still get the real error, not be waved through as if it
    were a decoy."""
    page = DecryptionPage(
        metadata_repository=None,
        protection_keys=protection_keys,
        session_manager=session_manager,
    )
    page._selected_container = tmp_path / "container.cusc"
    page._key_wrapper = object()  # any non-None sentinel

    with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
        page._on_view_clicked()
        mock_service_cls.assert_not_called()

    assert page._active_viewer is None
    assert "no metadata repository is available in this session" in page.status_label.text().lower()


# -- Viewer close / screen-capture wiring (Phase 22) ------------------------


def test_viewer_closed_signal_is_wired_to_outcome_on_view_closed(tmp_path, decryption_page):
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path, granted=True)
    mock_outcome.on_view_closed = MagicMock()
    mock_outcome.on_screen_capture_detected = MagicMock()

    with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
        mock_service_cls.return_value.attempt_access.return_value = mock_outcome
        decryption_page._on_view_clicked()

    viewer = decryption_page._active_viewer
    mock_outcome.on_view_closed.assert_not_called()

    viewer.close()

    mock_outcome.on_view_closed.assert_called_once_with()


def test_screen_capture_handler_is_wired_to_outcome_on_screen_capture_detected(tmp_path, decryption_page):
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path, granted=True)
    mock_outcome.on_view_closed = MagicMock()
    mock_outcome.on_screen_capture_detected = MagicMock()

    with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
        mock_service_cls.return_value.attempt_access.return_value = mock_outcome
        decryption_page._on_view_clicked()

    viewer = decryption_page._active_viewer
    viewer._on_printscreen_detected()

    mock_outcome.on_screen_capture_detected.assert_called_once_with()
    assert viewer.is_closed is True


def test_viewer_closed_by_capture_detection_shows_capture_status_message(tmp_path, decryption_page):
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path, granted=True)
    mock_outcome.on_view_closed = MagicMock()
    mock_outcome.on_screen_capture_detected = MagicMock()

    with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
        mock_service_cls.return_value.attempt_access.return_value = mock_outcome
        decryption_page._on_view_clicked()

    decryption_page._active_viewer._on_printscreen_detected()

    assert "screen capture attempt was detected" in decryption_page.status_label.text().lower()


def test_viewer_closed_normally_shows_plain_closed_status_message(tmp_path, decryption_page):
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path, granted=True)
    mock_outcome.on_view_closed = MagicMock()
    mock_outcome.on_screen_capture_detected = MagicMock()

    with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
        mock_service_cls.return_value.attempt_access.return_value = mock_outcome
        decryption_page._on_view_clicked()

    decryption_page._active_viewer.close()

    assert decryption_page.status_label.text() == "Secure viewer closed."


def test_no_view_closed_wiring_when_outcome_has_none(tmp_path, decryption_page):
    """When no usage tracker session exists, `on_view_closed` is `None` —
    closing the viewer must not raise from trying to call it."""
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path, granted=True)
    mock_outcome.on_view_closed = None
    mock_outcome.on_screen_capture_detected = None

    with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
        mock_service_cls.return_value.attempt_access.return_value = mock_outcome
        decryption_page._on_view_clicked()

    decryption_page._active_viewer.close()  # must not raise

    assert decryption_page.status_label.text() == "Secure viewer closed."


# -- Deception events are recorded through the page's own engine -----------


def test_denied_attempt_through_the_page_is_recorded_in_the_shared_event_repository(
    tmp_path, app, metadata_repository, protection_keys, session_manager, tracker, db_connection
):
    event_repository = DeceptionEventRepository(db_connection)
    page = DecryptionPage(
        metadata_repository=metadata_repository,
        protection_keys=protection_keys,
        session_manager=session_manager,
        usage_tracker=tracker,
        deception_event_repository=event_repository,
    )

    source = tmp_path / "findings.txt"
    source.write_text("secret", encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    encryption_page_helper = EncryptionPage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=session_manager
    )
    encryption_page_helper._devices = [device]
    encryption_page_helper._populate_table()
    encryption_page_helper.table.selectRow(0)
    encryption_page_helper._source_path = source
    encryption_page_helper._update_write_button_state()
    encryption_page_helper._on_write_clicked()
    written = list(device_dir.glob("*.cusc"))[0]

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page_helper._on_export_key_clicked()

    page.key_path_label.setText(str(exported_key_path))
    page.passphrase_edit.setText("a-strong-passphrase")
    page._on_load_key_clicked()

    # No device selected at all -> validation fails -> deception fires.
    page._devices = []
    page._selected_device = None
    page._selected_container = written

    page._on_view_clicked()

    try:
        events = event_repository.list_events()
        assert len(events) == 1
        assert events[0].file_id is not None
    finally:
        if page._active_viewer is not None and not page._active_viewer.is_closed:
            page._active_viewer.close()


# -- Automatic device-list polling ------------------------------------------


class _StubDetector:
    def __init__(self, devices):
        self._devices = devices

    def detect_devices(self):
        return self._devices


def test_device_poll_timer_is_running_after_construction(app):
    page = DecryptionPage()

    assert page._device_poll_timer.isActive() is True


def test_refresh_devices_is_a_noop_when_device_list_is_unchanged(app, tmp_path, monkeypatch):
    page = DecryptionPage()
    device = _device(str(tmp_path))
    page._detector = _StubDetector([device])
    page._refresh_devices()

    rebuild_calls = []
    monkeypatch.setattr(page, "_append_device_row", lambda device: rebuild_calls.append(device))

    page._refresh_devices()  # same detector, same device list

    assert rebuild_calls == []


def test_refresh_devices_preserves_selection_when_a_new_device_appears(app, tmp_path):
    page = DecryptionPage()
    device_a_dir = tmp_path / "a"
    device_a_dir.mkdir()
    device_a = _device(str(device_a_dir))
    page._detector = _StubDetector([device_a])
    page._refresh_devices()
    page.table.selectRow(0)
    assert page._selected_device is not None

    device_b_dir = tmp_path / "b"
    device_b_dir.mkdir()
    device_b = _device(str(device_b_dir))
    page._detector = _StubDetector([device_a, device_b])

    page._refresh_devices()

    assert page.table.rowCount() == 2
    assert page._selected_device is not None
    assert page._selected_device.device_id == device_a.device_id


def test_refresh_devices_clears_selection_when_selected_device_disappears(app, tmp_path):
    page = DecryptionPage()
    device_dir = tmp_path / "a"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._detector = _StubDetector([device])
    page._refresh_devices()
    page.table.selectRow(0)
    assert page._selected_device is not None

    page._detector = _StubDetector([])

    page._refresh_devices()

    assert page._selected_device is None
