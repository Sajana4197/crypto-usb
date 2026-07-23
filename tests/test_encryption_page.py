"""Tests for the Encrypt File UI page (device table, write panel, and the
containers-already-on-this-device table)."""

from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog

from ui.pages.encryption_page import EncryptionPage
from usb.device_detector import USBDevice
from usb.exceptions import ContainerOverwriteError, USBError
from usb.secure_storage_service import SecureWriteResult


@pytest.fixture(autouse=True)
def mock_result_popup(monkeypatch):
    """`important=True` status calls now pop up a real, blocking
    `QMessageBox` -- autouse so every test in this file is safe by
    default; tests that specifically assert on popup behavior can still
    take this fixture as a parameter to inspect the same mock."""
    mock = MagicMock()
    monkeypatch.setattr("ui.pages.encryption_page.show_result_popup", mock)
    return mock


@pytest.fixture(autouse=True)
def mock_passphrase_prompt(monkeypatch):
    """Deriving a file's portable metadata keys prompts for a passphrase
    via `QInputDialog.getText` (see `_prompt_passphrase`)
    -- autouse a valid default so existing write/export tests that don't
    care about this don't hang on a real dialog. Tests that specifically
    exercise passphrase behavior (cancel, too short) override this
    locally with their own `patch.object(QInputDialog, "getText", ...)`.
    """
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("a-valid-default-passphrase", True))


def _make_page():
    QApplication.instance() or QApplication([])
    return EncryptionPage()


def _device(mount_point, free_bytes=100_000_000):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="TESTUSB",
        filesystem="FAT32",
        total_bytes=free_bytes * 2,
        free_bytes=free_bytes,
        is_removable=True,
    )


class _StubDetector:
    def __init__(self, devices):
        self._devices = devices

    def detect_devices(self):
        return self._devices


# -- Device detection ---------------------------------------------------


def test_refresh_devices_populates_table(tmp_path):
    page = _make_page()
    device = _device(str(tmp_path))
    page._detector = _StubDetector([device])

    page._refresh_devices()

    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == str(tmp_path)


def test_no_devices_shows_zero_summary():
    page = _make_page()
    page._detector = _StubDetector([])

    page._refresh_devices()

    assert page.table.rowCount() == 0
    assert "No removable" in page.device_summary_label.text()


# -- Automatic device-list polling ------------------------------------------


def test_device_poll_timer_is_running_after_construction():
    page = _make_page()

    assert page._device_poll_timer.isActive() is True


def test_refresh_devices_is_a_noop_when_device_list_is_unchanged(tmp_path, monkeypatch):
    page = _make_page()
    device = _device(str(tmp_path))
    page._detector = _StubDetector([device])
    page._refresh_devices()

    rebuild_calls = []
    monkeypatch.setattr(page, "_populate_table", lambda: rebuild_calls.append(None))

    page._refresh_devices()  # same detector, same device list

    assert rebuild_calls == []


def test_refresh_devices_preserves_selection_when_a_new_device_appears(tmp_path):
    page = _make_page()
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


def test_refresh_devices_clears_selection_when_selected_device_disappears(tmp_path):
    page = _make_page()
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
    assert page.write_button.isEnabled() is False


# -- Write panel ----------------------------------------------------------


def test_write_button_disabled_until_device_and_file_chosen(tmp_path):
    page = _make_page()
    assert page.write_button.isEnabled() is False

    device = _device(str(tmp_path))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    assert page.write_button.isEnabled() is False  # no file chosen yet

    page._source_path = tmp_path / "does-not-matter.txt"
    page._update_write_button_state()
    assert page.write_button.isEnabled() is True


def test_write_container_end_to_end(tmp_path):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    written = list(device_dir.glob("*.cusc"))
    assert len(written) == 1
    assert b"top secret contents" not in written[0].read_bytes()
    assert "verified" in page.status_label.text().lower()


def test_write_success_pops_up_result(tmp_path, mock_result_popup):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    # The write-success message pops up; deep-verify's own success
    # message (called right after) is routine and does not.
    assert mock_result_popup.call_count == 1
    _, kwargs = mock_result_popup.call_args
    assert kwargs.get("ok", True) is True


def test_write_failure_pops_up_result(tmp_path, monkeypatch, mock_result_popup):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    def _raise(*args, **kwargs):
        raise USBError("disk full")

    monkeypatch.setattr(page._service, "store_file", _raise)

    page._on_write_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs["ok"] is False


def test_write_container_overwrite_declined_shows_cancel_message(tmp_path, monkeypatch):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    def _raise(*args, **kwargs):
        raise ContainerOverwriteError("exists")

    monkeypatch.setattr(page._service, "store_file", _raise)
    monkeypatch.setattr(page, "_confirm_overwrite", lambda: False)

    page._on_write_clicked()

    assert "cancelled" in page.status_label.text().lower()


def test_write_container_overwrite_confirmed_retries_write(tmp_path, monkeypatch):
    from metadata.protection import generate_protection_keys

    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    fake_destination = device_dir / "fixed-id.cusc"
    fake_result = SecureWriteResult(
        file_id="fixed-id",
        destination=fake_destination,
        container_size_bytes=4,
        protection_keys=generate_protection_keys(),
    )
    calls = {"count": 0}

    def _store(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ContainerOverwriteError("exists")
        fake_destination.write_bytes(b"stub")
        return fake_result

    monkeypatch.setattr(page._service, "store_file", _store)
    monkeypatch.setattr(page, "_confirm_overwrite", lambda: True)
    monkeypatch.setattr(page._service, "verify_stored_file", lambda *a, **kw: True)

    page._on_write_clicked()

    assert calls["count"] == 2
    assert "verified" in page.status_label.text().lower()


# -- One-time access checkbox (Phase 25) -------------------------------------


def _stub_store_file(monkeypatch, page, device_dir, captured):
    from metadata.protection import generate_protection_keys

    fake_destination = device_dir / "fixed-id.cusc"
    fake_result = SecureWriteResult(
        file_id="fixed-id",
        destination=fake_destination,
        container_size_bytes=4,
        protection_keys=generate_protection_keys(),
    )

    def _store(*args, **kwargs):
        captured.update(kwargs)
        fake_destination.write_bytes(b"stub")
        return fake_result

    monkeypatch.setattr(page._service, "store_file", _store)
    monkeypatch.setattr(page._service, "verify_stored_file", lambda *a, **kw: True)


def test_one_time_access_checkbox_defaults_unchecked():
    page = _make_page()
    assert page.one_time_access_checkbox.isChecked() is False


def test_write_container_with_checkbox_checked_passes_one_time_access_true(tmp_path, monkeypatch):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()
    page.one_time_access_checkbox.setChecked(True)

    captured = {}
    _stub_store_file(monkeypatch, page, device_dir, captured)

    page._on_write_clicked()

    assert captured["usage_policy"].one_time_access is True
    # Resets so the next write in this session defaults back to reusable.
    assert page.one_time_access_checkbox.isChecked() is False


def test_write_container_with_checkbox_unchecked_passes_one_time_access_false(tmp_path, monkeypatch):
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()
    assert page.one_time_access_checkbox.isChecked() is False

    captured = {}
    _stub_store_file(monkeypatch, page, device_dir, captured)

    page._on_write_clicked()

    assert captured["usage_policy"].one_time_access is False


# -- Exporting the file-wrapping private key --------------------------------


def test_export_key_writes_encrypted_private_key_file(tmp_path):
    page = _make_page()
    destination = tmp_path / "exported.pem"

    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), \
         patch.object(QFileDialog, "getSaveFileName", return_value=(str(destination), "")):
        page._on_export_key_clicked()

    assert destination.exists()
    assert b"ENCRYPTED" in destination.read_bytes() or b"PRIVATE KEY" in destination.read_bytes()
    assert "exported" in page.status_label.text().lower()


def test_export_key_success_pops_up_result_and_resets_source_file(tmp_path, mock_result_popup):
    page = _make_page()
    page._source_path = tmp_path / "secret.txt"
    page.source_file_label.setText(str(page._source_path))
    page._update_write_button_state()
    destination = tmp_path / "exported.pem"

    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), \
         patch.object(QFileDialog, "getSaveFileName", return_value=(str(destination), "")):
        page._on_export_key_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs.get("ok", True) is True

    # The write "session" ends at export -- a stale source file selection
    # must not silently carry over to a subsequent write.
    assert page._source_path is None
    assert page.source_file_label.text() == "No file selected."
    assert page.write_button.isEnabled() is False


def test_export_key_failure_pops_up_result(tmp_path, mock_result_popup):
    page = _make_page()
    destination = tmp_path / "a-directory"
    destination.mkdir()

    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), \
         patch.object(QFileDialog, "getSaveFileName", return_value=(str(destination), "")):
        page._on_export_key_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs["ok"] is False


def test_export_key_cancelled_passphrase_does_not_pop_up(tmp_path, mock_result_popup):
    """Routine/validation messages (short passphrase, cancelled dialog)
    are not a write/export pass-fail outcome -- inline-only."""
    page = _make_page()

    with patch.object(QInputDialog, "getText", return_value=("short", True)):
        page._on_export_key_clicked()

    mock_result_popup.assert_not_called()


def test_export_key_cancelled_passphrase_dialog_does_nothing(tmp_path):
    page = _make_page()

    with patch.object(QInputDialog, "getText", return_value=("", False)), \
         patch.object(QFileDialog, "getSaveFileName") as mock_save:
        page._on_export_key_clicked()

    mock_save.assert_not_called()


def test_export_key_rejects_short_passphrase(tmp_path):
    page = _make_page()

    with patch.object(QInputDialog, "getText", return_value=("short", True)):
        page._on_export_key_clicked()

    assert "passphrase" in page.status_label.text().lower()


def test_export_key_cancelled_save_dialog_does_not_write(tmp_path):
    page = _make_page()

    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), \
         patch.object(QFileDialog, "getSaveFileName", return_value=("", "")):
        page._on_export_key_clicked()

    assert list(tmp_path.glob("*.pem")) == []


def test_export_key_write_failure_shows_error_instead_of_crashing(tmp_path):
    page = _make_page()
    # A directory, not a file: writing to it raises OSError.
    destination = tmp_path / "a-directory"
    destination.mkdir()

    with patch.object(QInputDialog, "getText", return_value=("a-strong-passphrase", True)), \
         patch.object(QFileDialog, "getSaveFileName", return_value=(str(destination), "")):
        page._on_export_key_clicked()  # must not raise

    assert "failed to export" in page.status_label.text().lower()


# -- Embedded portable metadata section (Phase B) ----------------------------


def test_write_container_embeds_portable_metadata_section(tmp_path):
    from usb.storage_writer import SecureStorageWriter

    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    cusc_files = list(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 1
    # One file total on the device -- the portable metadata section is
    # embedded in the .cusc itself, not written as a second file.
    assert len(list(device_dir.iterdir())) == 1
    container = SecureStorageWriter().read_container(cusc_files[0])
    assert container.portable_metadata is not None


def test_portable_metadata_section_is_independently_loadable(tmp_path):
    from crypto.rsa_keypair import private_key_material
    from metadata.protection import MetadataProtector, derive_protection_keys_from_key_material
    from usb.storage_writer import SecureStorageWriter

    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    writer = SecureStorageWriter()
    cusc_path = next(device_dir.glob("*.cusc"))
    container = writer.read_container(cusc_path)
    envelope = container.portable_metadata

    # Simulates re-deriving on another machine: only the session private
    # key + the passphrase entered at write time (the autouse default)
    # plus the salt carried in the envelope itself are used.
    material = private_key_material(page._key_wrapper.private_key)
    rederived_keys = derive_protection_keys_from_key_material(
        material, b"a-valid-default-passphrase", envelope.salt
    )
    restored = MetadataProtector(rederived_keys).unprotect(envelope.protected)

    assert restored.file_id == container.file_id


def test_passphrase_prompted_fresh_for_every_write(tmp_path, monkeypatch):
    """Deliberately never cached (see the module docstring): two files
    written in the same page session each get their own independent
    passphrase prompt, so they can be protected by two different
    passphrases if the user chooses to."""
    from usb.storage_writer import SecureStorageWriter

    prompt = MagicMock(return_value=("a-valid-default-passphrase", True))
    monkeypatch.setattr(QInputDialog, "getText", prompt)

    page = _make_page()
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    source_a = tmp_path / "a.txt"
    source_a.write_bytes(b"content a")
    page._source_path = source_a
    page._update_write_button_state()
    page._on_write_clicked()

    source_b = tmp_path / "b.txt"
    source_b.write_bytes(b"content b")
    page._source_path = source_b
    page._update_write_button_state()
    page._on_write_clicked()

    assert prompt.call_count == 2
    cusc_files = sorted(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 2
    for path in cusc_files:
        assert SecureStorageWriter().read_container(path).portable_metadata is not None


def test_write_skips_portable_metadata_when_passphrase_prompt_cancelled(tmp_path, monkeypatch):
    from usb.storage_writer import SecureStorageWriter

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("", False))

    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    cusc_files = list(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 1
    assert SecureStorageWriter().read_container(cusc_files[0]).portable_metadata is None
    assert "verified" in page.status_label.text().lower()


def test_write_skips_portable_metadata_when_passphrase_too_short(tmp_path, monkeypatch):
    from usb.storage_writer import SecureStorageWriter

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("short", True))

    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    cusc_files = list(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 1
    assert SecureStorageWriter().read_container(cusc_files[0]).portable_metadata is None


def test_export_prompts_fresh_when_nothing_was_just_written(tmp_path, monkeypatch):
    """Export before any write this session has nothing to reuse, so it
    prompts on its own -- and that does not pre-fill or skip a later
    write's own (always-fresh) prompt either."""
    from usb.storage_writer import SecureStorageWriter

    page = _make_page()
    pem_destination = tmp_path / "exported.pem"

    with patch.object(QInputDialog, "getText", return_value=("export-passphrase-123", True)), \
         patch.object(QFileDialog, "getSaveFileName", return_value=(str(pem_destination), "")):
        page._on_export_key_clicked()

    # A write immediately after must still prompt fresh -- export never
    # caches anything for a later write to reuse.
    prompt = MagicMock(return_value=("a-different-passphrase", True))
    monkeypatch.setattr(QInputDialog, "getText", prompt)

    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    page._source_path = source
    page._update_write_button_state()

    page._on_write_clicked()

    prompt.assert_called_once()
    cusc_files = list(device_dir.glob("*.cusc"))
    assert len(cusc_files) == 1
    assert SecureStorageWriter().read_container(cusc_files[0]).portable_metadata is not None


def test_export_immediately_after_write_reuses_that_writes_passphrase(tmp_path, monkeypatch):
    """The normal first-time-encrypt flow: write, then export -- export
    must reuse the passphrase that write just prompted for, not ask a
    second time for the same file."""
    from crypto import rsa_keypair

    prompt = MagicMock(return_value=("write-time-passphrase", True))
    monkeypatch.setattr(QInputDialog, "getText", prompt)

    page = _make_page()
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    page._source_path = source
    page._update_write_button_state()
    page._on_write_clicked()

    assert prompt.call_count == 1

    pem_destination = tmp_path / "exported.pem"
    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(pem_destination), "")):
        page._on_export_key_clicked()

    # No second prompt, and the PEM was encrypted with the same
    # passphrase the write just used.
    prompt.assert_called_once()
    assert pem_destination.exists()
    rsa_keypair.load_private_key(pem_destination.read_bytes(), b"write-time-passphrase")


def test_export_after_a_second_write_reuses_the_second_writes_passphrase(tmp_path, monkeypatch):
    """Writing file B after file A must overwrite the one-write-deep
    memory export reuses -- exporting after B must never silently use
    A's (older, different) passphrase."""
    from crypto import rsa_keypair

    prompt = MagicMock(return_value=("passphrase-for-a", True))
    monkeypatch.setattr(QInputDialog, "getText", prompt)

    page = _make_page()
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    source_a = tmp_path / "a.txt"
    source_a.write_bytes(b"content a")
    page._source_path = source_a
    page._update_write_button_state()
    page._on_write_clicked()

    prompt.return_value = ("passphrase-for-b", True)
    source_b = tmp_path / "b.txt"
    source_b.write_bytes(b"content b")
    page._source_path = source_b
    page._update_write_button_state()
    page._on_write_clicked()

    assert prompt.call_count == 2

    pem_destination = tmp_path / "exported.pem"
    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(pem_destination), "")):
        page._on_export_key_clicked()

    assert prompt.call_count == 2  # still just the 2 write-time calls, no third
    rsa_keypair.load_private_key(pem_destination.read_bytes(), b"passphrase-for-b")


def test_export_prompts_fresh_after_a_cancelled_writes_passphrase(tmp_path, monkeypatch):
    """A write whose own passphrase prompt was cancelled leaves nothing
    for a following export to reuse -- export must not silently fall
    back to some earlier, unrelated file's passphrase."""
    page = _make_page()
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))
    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    # File A: written with a real passphrase, populating the memory.
    with patch.object(QInputDialog, "getText", return_value=("passphrase-for-a", True)):
        source_a = tmp_path / "a.txt"
        source_a.write_bytes(b"content a")
        page._source_path = source_a
        page._update_write_button_state()
        page._on_write_clicked()

    # File B: the portable-metadata prompt is cancelled this time.
    with patch.object(QInputDialog, "getText", return_value=("", False)):
        source_b = tmp_path / "b.txt"
        source_b.write_bytes(b"content b")
        page._source_path = source_b
        page._update_write_button_state()
        page._on_write_clicked()

    # Export must now prompt fresh -- not silently reuse A's passphrase.
    prompt = MagicMock(return_value=("export-time-passphrase", True))
    monkeypatch.setattr(QInputDialog, "getText", prompt)
    pem_destination = tmp_path / "exported.pem"
    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(pem_destination), "")):
        page._on_export_key_clicked()

    prompt.assert_called_once()


# -- Containers already on the selected device ------------------------------


def test_no_device_selected_shows_empty_container_table():
    page = _make_page()

    assert page.container_table.rowCount() == 0


def test_selecting_device_populates_container_table_with_existing_containers(tmp_path):
    page = _make_page()
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    (device_dir / "existing-file.cusc").write_bytes(b"stub container bytes")
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)

    assert page.container_table.rowCount() == 1
    assert page.container_table.item(0, 0).text() == "existing-file.cusc"


def test_switching_devices_refreshes_container_table(tmp_path):
    page = _make_page()
    device_a_dir = tmp_path / "usb-a"
    device_a_dir.mkdir()
    (device_a_dir / "a.cusc").write_bytes(b"stub")
    device_b_dir = tmp_path / "usb-b"
    device_b_dir.mkdir()

    device_a = _device(str(device_a_dir))
    device_b = _device(str(device_b_dir))
    page._devices = [device_a, device_b]
    page._populate_table()

    page.table.selectRow(0)
    assert page.container_table.rowCount() == 1

    page.table.selectRow(1)
    assert page.container_table.rowCount() == 0


def test_writing_a_container_makes_it_appear_in_the_container_table_immediately(tmp_path):
    """The concrete fix this phase delivers: no manual refresh needed."""
    page = _make_page()
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    device = _device(str(device_dir))

    page._devices = [device]
    page._populate_table()
    page.table.selectRow(0)
    assert page.container_table.rowCount() == 0

    page._source_path = source
    page._update_write_button_state()
    page._on_write_clicked()

    assert page.container_table.rowCount() == 1
    written = list(device_dir.glob("*.cusc"))
    assert page.container_table.item(0, 0).text() == written[0].name
