"""Integration test: `EncryptionPage` writes a secure container and exports
its file-wrapping private key exactly as a user would; `DecryptionPage`
reads the same container back through the real service layer, sharing
the same `MetadataRepository` / `MetadataProtectionKeys` /
`SessionManager` / `UsageTracker` that `ui.main_window.MainWindow`
wires between them in the real application.
"""

from __future__ import annotations

import random
import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog

from deception.content_types import DeceptionContentType
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


class _FakeTextOnlyRandom(random.Random):
    """A `random.Random` that always resolves `DeceptionEngine.activate`'s
    content-type roll to `FAKE_TEXT`, leaving every other call (filename
    stem/number) genuinely random -- lets a test pin down which widget
    `SecureViewerWidget.display` will use without stubbing out content
    generation entirely."""

    def choice(self, seq):
        if list(seq) == list(DeceptionContentType):
            return DeceptionContentType.FAKE_TEXT
        return super().choice(seq)


@pytest.fixture(autouse=True)
def mock_result_popup(monkeypatch):
    """`important=True` status calls now pop up a real, blocking
    `QMessageBox` -- autouse so every test in this file is safe by
    default; tests that specifically assert on popup behavior can still
    take this fixture as a parameter to inspect the same mock. Patches
    both modules: this file's integration tests drive `EncryptionPage`
    writes (also `important=True` now) as well as `DecryptionPage`."""
    mock = MagicMock()
    monkeypatch.setattr("ui.pages.decryption_page.show_result_popup", mock)
    monkeypatch.setattr("ui.pages.encryption_page.show_result_popup", mock)
    return mock


@pytest.fixture(autouse=True)
def mock_info_popup(monkeypatch):
    """Private-key-loaded popups use the neutral `show_info_popup` (never
    "Success"/"Error" framing -- see `_on_load_key_clicked`), not
    `show_result_popup`; patched separately so those tests aren't
    blocked on a real modal `QMessageBox`."""
    mock = MagicMock()
    monkeypatch.setattr("ui.pages.decryption_page.show_info_popup", mock)
    return mock


@pytest.fixture(autouse=True)
def mock_passphrase_prompt(monkeypatch):
    """`EncryptionPage._on_write_clicked` derives portable metadata keys
    and prompts for a passphrase via `QInputDialog.getText` (see
    `_prompt_passphrase`) -- autouse a valid default so
    this file's writes, driven exactly as a user would (unlike
    `test_e2e_demo.py`, which calls the service layer directly), don't
    hang on a real modal dialog. Tests that explicitly patch
    `QInputDialog.getText` themselves (e.g. for `_on_export_key_clicked`)
    still work, nested inside their own `with patch.object(...)` block."""
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("a-valid-default-passphrase", True))


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
    # Same passphrase re-entered by hand at write time (portable metadata
    # derivation) and export time (PEM encryption) below -- both prompts
    # are independent (see `_prompt_passphrase`), so a real user must
    # supply this consistency themselves for the container's embedded
    # portable-metadata section to be re-derivable after loading the
    # exported key with that same passphrase.
    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)):
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


def test_view_open_and_close_do_not_pop_up_but_reset_the_loaded_key(
    tmp_path, encryption_page, decryption_page, mock_result_popup
):
    source = tmp_path / "findings.txt"
    source.write_text("the quarterly figures are confidential", encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)):
        encryption_page._on_write_clicked()

    # Export reuses the passphrase the write above just prompted for
    # (see `_on_export_key_clicked`) -- no `QInputDialog.getText` patch
    # needed here.
    exported_key_path = tmp_path / "key.pem"
    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")):
        encryption_page._on_export_key_clicked()

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()

    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("a-strong-passphrase")
    decryption_page._on_load_key_clicked()
    mock_result_popup.reset_mock()  # only care about view-open/close popups below

    decryption_page.container_table.selectRow(0)
    decryption_page._on_view_clicked()

    # Opening the viewer is not a pass/fail action in its own right --
    # no popup.
    mock_result_popup.assert_not_called()

    decryption_page._active_viewer.close()

    # Nor is closing it.
    mock_result_popup.assert_not_called()

    # The loaded key was scoped to that viewing session -- it must not
    # silently remain usable for a different container without the user
    # deliberately reloading it.
    assert decryption_page._key_wrapper is None
    assert decryption_page.key_path_label.text() == "No private key loaded."
    assert decryption_page.passphrase_edit.text() == ""
    assert decryption_page.view_button.isEnabled() is False


def test_load_key_success_pops_up_success_notice(tmp_path, decryption_page, mock_info_popup, mock_result_popup):
    from crypto import rsa_keypair

    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(pem)

    decryption_page.key_path_label.setText(str(key_path))
    decryption_page.passphrase_edit.setText("correct-passphrase")
    decryption_page._on_load_key_clicked()

    mock_result_popup.assert_called_once_with(decryption_page, "Private key loaded.", ok=True)
    mock_info_popup.assert_not_called()


def test_load_key_failure_activates_deception_instead_of_reporting_an_error(
    tmp_path, decryption_page, mock_info_popup, mock_result_popup
):
    """Matching the proposal's Deceptive Protection Mechanism (see
    `security.auth_controller.authenticate_private_key`): a wrong key
    file or passphrase must look exactly like a successful load, never
    an error -- otherwise it would confirm to an attacker that they
    guessed wrong. Unlike a real load, though, the popup itself carries
    no "Success" framing (`show_info_popup`, not `show_result_popup`)."""
    from crypto import rsa_keypair

    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(pem)

    decryption_page.key_path_label.setText(str(key_path))
    decryption_page.passphrase_edit.setText("wrong-passphrase")
    decryption_page._on_load_key_clicked()

    mock_info_popup.assert_called_once_with(decryption_page, "Private key loaded.")
    mock_result_popup.assert_not_called()
    assert "loaded" in decryption_page.status_label.text().lower()
    assert decryption_page._key_wrapper is not None


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


def test_wrong_passphrase_loads_a_decoy_key_instead_of_failing(tmp_path, decryption_page):
    from crypto import rsa_keypair

    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(pem)

    decryption_page.key_path_label.setText(str(key_path))
    decryption_page.passphrase_edit.setText("wrong-passphrase")
    decryption_page._on_load_key_clicked()

    assert decryption_page._key_wrapper is not None
    assert "loaded" in decryption_page.status_label.text().lower()


def test_view_click_does_not_force_deception_for_a_decoy_key_load_failure(tmp_path, decryption_page):
    """A wrong passphrase/key file (Phase D) no longer sets any flag that
    forces `force_deception`: the fabricated key is cryptographically
    unrelated to the real one, so it fails on its own -- either the
    portable-metadata HMAC check or the real decrypt attempt (see
    `test_wrong_passphrase_view_attempt_is_deceived_via_natural_hmac_failure`
    for that end-to-end path) -- exactly like a genuine denial, without
    ever touching `force_deception`. Only a decoy *session*
    (`test_view_click_forces_deception_for_a_decoy_session`) still short-
    circuits that way."""
    decryption_page._key_wrapper = object()  # stands in for a fabricated decoy key; no flag to set anymore
    mock_outcome = _stub_attempt_access_call(decryption_page, tmp_path)

    try:
        with patch("ui.pages.decryption_page.SecureAccessService") as mock_service_cls:
            mock_service_cls.return_value.attempt_access.return_value = mock_outcome
            decryption_page._on_view_clicked()

        _, kwargs = mock_service_cls.return_value.attempt_access.call_args
        assert kwargs["force_deception"] is False
    finally:
        if decryption_page._active_viewer is not None and not decryption_page._active_viewer.is_closed:
            decryption_page._active_viewer.close()


def test_wrong_passphrase_view_attempt_is_deceived_via_natural_hmac_failure(
    tmp_path, encryption_page, decryption_page
):
    """End-to-end (Phase D): with no `_key_is_decoy` flag left to force
    deception, a wrong-passphrase load must still never reveal the real
    file, relying entirely on the natural failure path -- the fabricated
    decoy key re-derives the wrong portable-metadata protection keys
    (see `metadata.protection.derive_protection_keys_from_key_material`),
    which fails `MetadataProtector.unprotect`'s own HMAC check exactly
    like tampered metadata would, denying access through the real
    `SecureAccessService` / `ValidationEngine` stack -- not a mock."""
    source = tmp_path / "findings.txt"
    plaintext = "the quarterly figures are confidential"
    source.write_text(plaintext, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)):
        encryption_page._on_write_clicked()
    from usb.storage_writer import SecureStorageWriter

    written = list(device_dir.glob("*.cusc"))
    assert len(written) == 1
    assert SecureStorageWriter().read_container(written[0]).portable_metadata is not None, (
        "the write must have embedded a portable metadata section"
    )

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()

    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("definitely-the-wrong-passphrase")
    decryption_page._on_load_key_clicked()
    assert decryption_page._key_wrapper is not None
    assert "loaded" in decryption_page.status_label.text().lower()

    decryption_page.container_table.selectRow(0)
    # The Deception Engine picks its fake content type at random; pin it
    # to text so the assertion below can inspect `_text_view` instead of
    # having to branch on whichever widget the viewer happened to show.
    decryption_page._deception_engine._rng = _FakeTextOnlyRandom()
    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    # Deceived, not denied: the viewer still opens and the status message
    # never distinguishes this from a real success.
    assert decryption_page._active_viewer._text_view.toPlainText() != plaintext
    assert "opened" in decryption_page.status_label.text().lower()
    decryption_page._active_viewer.close()


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
    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)):
        encryption_page_helper._on_write_clicked()
    written = list(device_dir.glob("*.cusc"))[0]

    # Write and export always prompt independently (no caching -- see
    # the module docstring); re-entering the same passphrase for both is
    # what keeps the exported PEM matched to this file's portable metadata.
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


# -- One-time access deletes the container after its single view ----------


def test_one_time_access_view_deletes_the_container_from_the_device(
    tmp_path, encryption_page, decryption_page
):
    source = tmp_path / "findings.txt"
    plaintext = "self-destructing message"
    source.write_text(plaintext, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    encryption_page.one_time_access_checkbox.setChecked(True)
    with patch.object(QInputDialog, "getText", return_value=("shared-passphrase", True)):
        encryption_page._on_write_clicked()

    cusc = list(device_dir.glob("*.cusc"))[0]
    assert cusc.exists()

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("shared-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()
    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("shared-passphrase")
    decryption_page._on_load_key_clicked()
    decryption_page.container_table.selectRow(0)
    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == plaintext
    decryption_page._active_viewer.close()

    assert not cusc.exists(), "the .cusc file must be deleted from the device after its one legitimate view"
    # The container table reflects this immediately, without waiting for
    # the next device-poll tick.
    assert decryption_page._containers == []
    assert list(device_dir.glob("*.cusc")) == []


def test_reusable_file_view_does_not_delete_the_container(tmp_path, encryption_page, decryption_page):
    """Only a one-time-access file's container is deleted after a view --
    a normal, reusable file must still be sitting on the device afterward,
    unlike the one-time-access case above."""
    source = tmp_path / "findings.txt"
    plaintext = "read me as many times as you like"
    source.write_text(plaintext, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    # one_time_access_checkbox left unchecked -- a reusable file.
    with patch.object(QInputDialog, "getText", return_value=("shared-passphrase", True)):
        encryption_page._on_write_clicked()

    cusc = list(device_dir.glob("*.cusc"))[0]

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("shared-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()
    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("shared-passphrase")
    decryption_page._on_load_key_clicked()
    decryption_page.container_table.selectRow(0)
    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == plaintext
    decryption_page._active_viewer.close()

    assert cusc.exists(), "a reusable file's container must not be deleted after a view"


# -- One-time access stays burned across both metadata copies (Phase E) ----


def test_one_time_access_burn_via_portable_metadata_also_invalidates_the_local_copy(
    tmp_path, encryption_page, decryption_page, metadata_repository, protection_keys
):
    """A file written on this machine gets both a local `metadata_repository`
    record and an embedded portable-metadata section in its `.cusc`
    file (see the module docstrings of `usb.secure_storage_service` and
    `ui.pages.decryption_page`). `decryption_page._on_view_clicked`
    prefers the embedded copy, so a one-time-access burn happens there
    first -- without mirroring, the
    local copy would be left looking untouched (`access_count` still 0,
    the real `wrapped_key` still intact), letting a second, independent
    access built directly against the local repository decrypt the file
    again despite its one-time-access policy. This is the exact gap
    `usb.secure_access_service.SecureAccessService`'s
    `mirror_repositories` (wired up in `_on_view_clicked`) closes."""
    source = tmp_path / "findings.txt"
    plaintext = "one-time-access secret"
    source.write_text(plaintext, encoding="utf-8")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    encryption_page._devices = [device]
    encryption_page._populate_table()
    encryption_page.table.selectRow(0)
    encryption_page._source_path = source
    encryption_page._update_write_button_state()
    encryption_page.one_time_access_checkbox.setChecked(True)
    with patch.object(QInputDialog, "getText", return_value=("shared-passphrase", True)):
        encryption_page._on_write_clicked()

    from usb.storage_writer import SecureStorageWriter

    cusc = list(device_dir.glob("*.cusc"))[0]
    assert SecureStorageWriter().read_container(cusc).portable_metadata is not None, (
        "both a local record and an embedded portable-metadata section must exist"
    )

    # Captured before the legitimate view below -- which, being a
    # one-time-access file, deletes `cusc` from disk once it succeeds
    # (see SecureAccessService.attempt_access's container_path). The
    # "second attempt" further down simulates someone who kept a copy of
    # the ciphertext from before that deletion.
    file_id, encrypted_bytes = encryption_page._service.read_encrypted_file_bytes(cusc)

    exported_key_path = tmp_path / "key.pem"
    with patch.object(QInputDialog, "getText", return_value=("shared-passphrase", True)), patch.object(
        QFileDialog, "getSaveFileName", return_value=(str(exported_key_path), "")
    ):
        encryption_page._on_export_key_clicked()

    decryption_page._devices = [device]
    decryption_page._selected_device = device
    decryption_page._refresh_containers()
    decryption_page.key_path_label.setText(str(exported_key_path))
    decryption_page.passphrase_edit.setText("shared-passphrase")
    decryption_page._on_load_key_clicked()
    decryption_page.container_table.selectRow(0)
    decryption_page._on_view_clicked()

    assert decryption_page._active_viewer is not None
    assert decryption_page._active_viewer._text_view.toPlainText() == plaintext
    decryption_page._active_viewer.close()

    # A second, independent access built directly against the LOCAL
    # repository -- as if the embedded portable section were unavailable
    # -- must be denied exactly like a repeat attempt through the same copy
    # would be, not silently granted because that copy was never burned.
    from crypto import rsa_keypair
    from crypto.key_wrapper import RSAOAEPKeyWrapper
    from usb.secure_access_service import SecureAccessService
    from validation.machine_fingerprint import compute_machine_fingerprint
    from validation.usb_identifier import compute_usb_identifier

    private_key = rsa_keypair.load_private_key(exported_key_path.read_bytes(), b"shared-passphrase")
    key_wrapper = RSAOAEPKeyWrapper(private_key.public_key(), private_key)

    captured = {}
    access_service = SecureAccessService(metadata_repository)
    outcome = access_service.attempt_access(
        file_id,
        encrypted_bytes,
        key_wrapper,
        protection_keys,
        lambda buf, meta: captured.__setitem__("content", bytes(buf)),
        current_device=device,
        current_usb_identifier=compute_usb_identifier(device),
        current_machine_fingerprint=compute_machine_fingerprint(),
        user="owner-1",
    )

    assert outcome.granted is False
    assert "content" not in captured
