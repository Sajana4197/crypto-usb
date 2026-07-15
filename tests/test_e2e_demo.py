"""End-to-end test following the actual presentation demo script:
register -> sign in -> write a one-time-access file to a USB device ->
export its key -> a wrong passphrase is rejected -> the correct key
opens and views the file exactly once -> a second attempt is silently
deceived -> a tampered/foreign device is also deceived -> repeated
wrong passwords lock the account -> the tamper-evident usage log
records every attempt and verifies clean. Also confirms the full
application (every page, including the still-stub ones) boots without
error, since a demo audience will see the whole window, not just the
two working pages.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog

from deception.triggers import DeceptionTrigger
from metadata.models import UsagePolicy
from metadata.protection import generate_protection_keys
from metadata.repository import MetadataRepository
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.auth_session import AuthSession, SessionManager
from security.exceptions import AccountLockedError
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from security.models import AuthMethod
from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
from ui.main_window import MainWindow
from ui.pages.decryption_page import DecryptionPage
from ui.pages.device_page import DevicePage
from usb.device_detector import USBDevice
from app.config import ConfigManager
from ui.theme.theme_manager import ThemeManager
from database.db_manager import DatabaseManager

PLAINTEXT = "Confidential final-year research findings — do not distribute."


def _device(mount_point: str, free_bytes: int = 100_000_000) -> USBDevice:
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="DEMO-USB",
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
def auth_controller(db_connection):
    return AuthController(AccountRepository(db_connection))


@pytest.fixture
def metadata_repository(db_connection):
    return MetadataRepository(db_connection)


@pytest.fixture
def protection_keys():
    return generate_protection_keys()


@pytest.fixture
def tracker(db_connection):
    return UsageTracker(generate_tracking_keys(), TrackingRepository(db_connection))


def test_full_demo_script(app, tmp_path, auth_controller, metadata_repository, protection_keys, tracker):
    # -- 1. Registration and sign-in (Authentication) --------------------
    auth_controller.register_password_account("owner-1", "correct-horse-battery-staple")
    session = auth_controller.authenticate_password("owner-1", "correct-horse-battery-staple")
    assert session.method == AuthMethod.PASSWORD

    session_manager = SessionManager()
    session_manager.set(session)

    device_page = DevicePage(
        metadata_repository=metadata_repository, protection_keys=protection_keys, session_manager=session_manager
    )
    decryption_page = DecryptionPage(
        metadata_repository=metadata_repository,
        protection_keys=protection_keys,
        session_manager=session_manager,
        usage_tracker=tracker,
    )

    # -- 2. Write a one-time-access file to a "USB device" (Sender ->
    #    Encryption -> Metadata -> USB Storage) -------------------------
    source = tmp_path / "findings.txt"
    source.write_text(PLAINTEXT, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    device_page._devices = [device]
    device_page._populate_table()
    device_page.table.selectRow(0)
    device_page._source_path = source
    device_page._update_write_button_state()
    # Mark the freshly-generated FEK's file as one-time access before the
    # write happens, by driving the lower-level service directly with the
    # same key wrapper DevicePage will keep using for the rest of the demo.
    key_wrapper = device_page._get_key_wrapper()
    result = device_page._service.store_file(
        source_path=source,
        device=device,
        key_wrapper=key_wrapper,
        owner_id=session.owner_id,
        metadata_repository=metadata_repository,
        protection_keys=protection_keys,
        bind_to_device=True,
        usage_policy=UsagePolicy(one_time_access=True),
    )
    written = device_dir / f"{result.file_id}.cusc"
    assert written.exists()
    assert PLAINTEXT.encode() not in written.read_bytes()

    # -- 3. Export the file-wrapping private key -------------------------
    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        device_page._on_export_key_clicked()
    assert exported_key_path.exists()

    # -- 4. Wrong passphrase is rejected, no crash -----------------------
    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("definitely-wrong")
    decryption_page._on_load_key_clicked()
    assert decryption_page._key_wrapper is None
    assert "failed" in decryption_page.status_label.text().lower()

    # -- 5. Correct key opens and views the file exactly once ------------
    decryption_page.passphrase_edit.setText("a-strong-passphrase")
    decryption_page._on_load_key_clicked()
    assert decryption_page._key_wrapper is not None

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()
    decryption_page.container_table.selectRow(0)
    assert decryption_page._selected_container == written

    decryption_page._on_view_clicked()
    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == PLAINTEXT
    decryption_page._active_viewer.close()

    # -- 6. A second attempt at the same file is silently deceived -------
    second_viewer_content = {}

    def _capture(buffer, metadata) -> None:
        second_viewer_content["real"] = bytes(buffer)

    from usb.secure_access_service import SecureAccessService

    file_id, encrypted_bytes = device_page._service.read_encrypted_file_bytes(written)
    access_service = SecureAccessService(metadata_repository, usage_tracker=tracker)
    second_outcome = access_service.attempt_access(
        file_id, encrypted_bytes, key_wrapper, result.protection_keys, _capture, user=session.owner_id
    )
    assert second_outcome.granted is False
    assert second_outcome.deception is not None
    # Either trigger is a correct "you cannot access this again" outcome:
    # METADATA_TAMPERING if the caller doesn't have the just-rotated
    # protection keys DecryptionPage's view already burned this file
    # under (as here, since this call reuses the original `result.protection_keys`),
    # or ACCESS_ALREADY_USED if it does.
    assert second_outcome.deception.trigger in (
        DeceptionTrigger.METADATA_TAMPERING,
        DeceptionTrigger.ACCESS_ALREADY_USED,
    )
    assert PLAINTEXT.encode() not in second_outcome.deception.content
    assert "real" not in second_viewer_content  # on_granted never ran

    # -- 7. A foreign/tampered device is also deceived, not a crash ------
    third_outcome = access_service.attempt_access(
        file_id,
        encrypted_bytes,
        key_wrapper,
        result.protection_keys,
        _capture,
        current_device=None,
        current_usb_identifier=None,
        current_machine_fingerprint=None,
        user=session.owner_id,
    )
    assert third_outcome.granted is False
    assert third_outcome.deception is not None

    # -- 8. Repeated wrong passwords are deceived, then lock the account --
    for _ in range(MAX_FAILED_ATTEMPTS):
        decoy_session = auth_controller.authenticate_password("owner-1", "wrong-password")
        assert decoy_session.is_decoy is True
    with pytest.raises(AccountLockedError):
        auth_controller.authenticate_password("owner-1", "correct-horse-battery-staple")

    # -- 9. The tamper-evident usage log recorded every attempt ----------
    records = tracker.read_all_records()
    assert len(records) == 3
    assert [r.validation_result for r in records] == [True, False, False]
    assert tracker.verify_log_integrity().ok is True


def test_full_application_boots_with_every_page(tmp_path, monkeypatch):
    """A demo audience sees the whole window — every nav page, including
    the still-stub ones, must construct and be reachable without error."""
    monkeypatch.setattr("app.config.get_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("database.db_manager.get_database_path", lambda: tmp_path / "db.sqlite")

    QApplication.instance() or QApplication([])

    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    db_manager.initialize()
    session_manager = SessionManager()
    session_manager.set(
        AuthSession(owner_id="owner-1", method=AuthMethod.PASSWORD, authenticated_at=datetime.now(timezone.utc))
    )
    theme_manager = ThemeManager(QApplication.instance(), theme="dark")
    theme_manager.apply()

    window = MainWindow(config_manager, theme_manager, db_manager=db_manager, session_manager=session_manager)
    try:
        for page_id in window._page_index:
            window._navigate_to(page_id)
            assert window.stack.currentWidget() is window._pages[page_id]
    finally:
        window.close()
        db_manager.close()
