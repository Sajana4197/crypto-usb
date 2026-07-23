"""Cross-machine portability test (Phase C).

Simulates two completely independent laptops — each with its own
in-memory SQLite database, its own `MetadataRepository`, and its own
random `MetadataProtectionKeys` that share nothing with the other —
and proves a file written on "laptop A" can be validated, decrypted,
and viewed on "laptop B" using only the single `.cusc` container (its
portable metadata embedded directly inside it) and the correct
private key + passphrase. Laptop B's local database is asserted empty
throughout: the read never touches or requires it.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog

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

PASSPHRASE = "the-same-passphrase-on-both-laptops"


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def mock_popups(monkeypatch):
    """`EncryptionPage`/`DecryptionPage` both pop up real, blocking
    `QMessageBox`/info dialogs on success (write, export, key load) --
    autoused so this file's writes and reads don't hang on one."""
    mock = MagicMock()
    monkeypatch.setattr("ui.pages.encryption_page.show_result_popup", mock)
    monkeypatch.setattr("ui.pages.decryption_page.show_result_popup", mock)
    monkeypatch.setattr("ui.pages.decryption_page.show_info_popup", mock)
    return mock


def _device(mount_point: str, free_bytes: int = 100_000_000) -> USBDevice:
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="SHARED-USB",
        filesystem="FAT32",
        total_bytes=free_bytes * 2,
        free_bytes=free_bytes,
        is_removable=True,
    )


def _session(owner_id: str) -> SessionManager:
    manager = SessionManager()
    manager.set(AuthSession(owner_id=owner_id, method=AuthMethod.PASSWORD, authenticated_at=datetime.now(timezone.utc)))
    return manager


def test_file_written_on_one_laptop_is_viewable_on_another_via_portable_metadata(app, tmp_path):
    # -- "Laptop A": its own database, its own random protection keys. --
    db_a = sqlite3.connect(":memory:")
    metadata_repository_a = MetadataRepository(db_a)
    protection_keys_a = generate_protection_keys()
    session_a = _session("researcher-a")

    encryption_page = EncryptionPage(
        metadata_repository=metadata_repository_a, protection_keys=protection_keys_a, session_manager=session_a
    )

    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    source = tmp_path / "findings.txt"
    plaintext = "cross-machine confidential research findings"
    source.write_text(plaintext, encoding="utf-8")

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()

    with patch.object(QInputDialog, "getText", return_value=(PASSPHRASE, True)):
        encryption_page._on_write_clicked()

    from usb.storage_writer import SecureStorageWriter

    cusc_files = list(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 1
    assert SecureStorageWriter().read_container(cusc_files[0]).portable_metadata is not None, (
        "the write must embed a portable metadata section in the .cusc container"
    )

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=(PASSPHRASE, True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()
    assert exported_key_path.exists()

    db_a.close()  # "Laptop A" is now gone -- only the USB device and the exported key remain.

    # -- "Laptop B": a totally separate database that has never heard of --
    #    this file, and its own unrelated protection keys.
    db_b = sqlite3.connect(":memory:")
    metadata_repository_b = MetadataRepository(db_b)
    protection_keys_b = generate_protection_keys()
    session_b = _session("researcher-b")

    assert metadata_repository_b.list_file_ids() == []

    decryption_page = DecryptionPage(
        metadata_repository=metadata_repository_b, protection_keys=protection_keys_b, session_manager=session_b
    )

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()
    assert decryption_page._containers == cusc_files

    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText(PASSPHRASE)
    decryption_page._on_load_key_clicked()
    assert decryption_page._key_wrapper is not None

    decryption_page.container_table.selectRow(0)
    assert decryption_page._selected_container == cusc_files[0]

    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == plaintext
    assert "opened" in decryption_page.status_label.text().lower()

    # The whole point: laptop B's local database was never touched.
    assert metadata_repository_b.list_file_ids() == []

    decryption_page._active_viewer.close()
    db_b.close()


def test_one_time_access_burn_on_laptop_b_is_visible_from_a_third_independent_laptop(app, tmp_path):
    """A one-time-access file written on "laptop A" and opened once on
    "laptop B" must not be legitimately re-openable from a third,
    completely independent "laptop C" either -- proving the burn
    (`metadata.one_time_access.OneTimeAccessEnforcer`) actually lands on
    the USB-resident `.cusc` file's embedded portable section itself,
    not just in laptop B's own in-memory session or local database.
    Also exercises usage tracking over the portable-metadata path end
    to end."""
    # -- "Laptop A": writes a one-time-access file. --
    db_a = sqlite3.connect(":memory:")
    metadata_repository_a = MetadataRepository(db_a)
    encryption_page = EncryptionPage(
        metadata_repository=metadata_repository_a, protection_keys=generate_protection_keys(), session_manager=_session("researcher-a")
    )

    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    source = tmp_path / "secret.txt"
    plaintext = "burn me after reading"
    source.write_text(plaintext, encoding="utf-8")

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    encryption_page.one_time_access_checkbox.setChecked(True)
    with patch.object(QInputDialog, "getText", return_value=(PASSPHRASE, True)):
        encryption_page._on_write_clicked()

    from usb.storage_writer import SecureStorageWriter

    cusc_files = list(device_dir.glob("*.cusc"))
    assert SecureStorageWriter().read_container(cusc_files[0]).portable_metadata is not None, (
        "one-time-access files must still get an embedded portable metadata section"
    )

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=(PASSPHRASE, True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()

    db_a.close()

    # -- "Laptop B": separate database, separate keys, its own usage tracker. --
    db_b = sqlite3.connect(":memory:")
    tracker_b = UsageTracker(generate_tracking_keys(), TrackingRepository(db_b))
    decryption_page_b = DecryptionPage(
        metadata_repository=MetadataRepository(sqlite3.connect(":memory:")),
        protection_keys=generate_protection_keys(),
        session_manager=_session("researcher-b"),
        usage_tracker=tracker_b,
    )
    decryption_page_b._devices = [device]
    decryption_page_b._selected_device = device
    decryption_page_b._refresh_containers()
    decryption_page_b.key_path_label.setText(str(exported_key_path))
    decryption_page_b.passphrase_edit.setText(PASSPHRASE)
    decryption_page_b._on_load_key_clicked()
    decryption_page_b.container_table.selectRow(0)
    decryption_page_b._on_view_clicked()

    assert decryption_page_b._active_viewer is not None
    assert decryption_page_b._active_viewer._text_view.toPlainText() == plaintext
    decryption_page_b._active_viewer.close()

    # Usage tracking must have recorded this session over the portable path.
    records_b = tracker_b.read_all_records()
    assert len(records_b) == 1
    assert records_b[0].authentication_result is True
    assert records_b[0].validation_result is True
    assert records_b[0].open_time is not None
    assert records_b[0].close_time is not None

    # -- "Laptop C": a third, completely independent laptop. --
    db_c = sqlite3.connect(":memory:")
    decryption_page_c = DecryptionPage(
        metadata_repository=MetadataRepository(db_c),
        protection_keys=generate_protection_keys(),
        session_manager=_session("researcher-c"),
    )
    decryption_page_c._devices = [device]
    decryption_page_c._selected_device = device
    decryption_page_c._refresh_containers()

    # The burn from laptop B also deleted the .cusc file from the USB
    # itself (see SecureAccessService.attempt_access's container_path) --
    # laptop C, which has never touched any database involved so far,
    # finds nothing left to even attempt opening.
    assert decryption_page_c._containers == [], (
        "the one-time-access file consumed on laptop B must be gone from the device entirely, "
        "not just undecryptable"
    )
    db_b.close()
    db_c.close()


def test_falls_back_to_local_repository_when_no_portable_metadata_present(app, tmp_path):
    """Same-machine behavior (no embedded portable section) is unchanged
    -- the local `metadata_repository` is still consulted and still works."""
    db_connection = sqlite3.connect(":memory:")
    metadata_repository = MetadataRepository(db_connection)
    protection_keys = generate_protection_keys()
    session = _session("owner-1")

    encryption_page = EncryptionPage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=session
    )
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    source = tmp_path / "findings.txt"
    plaintext = "same-machine content"
    source.write_text(plaintext, encoding="utf-8")

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()

    # Passphrase prompt cancelled -- no portable metadata is written.
    with patch.object(QInputDialog, "getText", return_value=("", False)):
        encryption_page._on_write_clicked()

    from usb.storage_writer import SecureStorageWriter

    cusc_files = list(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 1
    assert SecureStorageWriter().read_container(cusc_files[0]).portable_metadata is None

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("export-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()

    decryption_page = DecryptionPage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=session
    )
    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()

    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("export-passphrase")
    decryption_page._on_load_key_clicked()

    decryption_page.container_table.selectRow(0)
    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == plaintext
    decryption_page._active_viewer.close()
    db_connection.close()
