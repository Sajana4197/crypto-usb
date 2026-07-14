"""Integration test: `DevicePage` writes a secure container and exports
its file-wrapping private key exactly as a user would; `DecryptionPage`
reads the same container back through the real service layer, sharing
the same `MetadataRepository` / `MetadataProtectionKeys` /
`SessionManager` / `UsageTracker` that `ui.main_window.MainWindow`
wires between them in the real application.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import patch

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
from ui.pages.device_page import DevicePage
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
def device_page(app, metadata_repository, protection_keys, session_manager):
    return DevicePage(
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


def test_device_page_writes_and_decryption_page_reads_it_back(tmp_path, device_page, decryption_page, tracker):
    source = tmp_path / "findings.txt"
    plaintext = "the quarterly figures are confidential"
    source.write_text(plaintext, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    # -- Write via DevicePage, exactly as a user driving the UI would. --
    device_page._devices = [device]
    device_page._populate_table()
    device_page.table.selectRow(0)
    device_page._source_path = source
    device_page._update_write_button_state()
    device_page._on_write_clicked()

    written = list(device_dir.glob("*.cusc"))
    assert len(written) == 1
    assert "verified" in device_page.status_label.text().lower()

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        device_page._on_export_key_clicked()
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

    device_page_helper = DevicePage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=session_manager
    )
    device_page_helper._devices = [device]
    device_page_helper._populate_table()
    device_page_helper.table.selectRow(0)
    device_page_helper._source_path = source
    device_page_helper._update_write_button_state()
    device_page_helper._on_write_clicked()
    written = list(device_dir.glob("*.cusc"))[0]

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        device_page_helper._on_export_key_clicked()

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
