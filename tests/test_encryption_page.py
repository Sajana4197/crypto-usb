"""Tests for the Sender Module UI (EncryptionPage)."""

from PySide6.QtWidgets import QApplication

from ui.pages.encryption_page import EncryptionPage


def _make_page():
    QApplication.instance() or QApplication([])
    return EncryptionPage()


def _make_file(tmp_path, name, content=b"hello"):
    path = tmp_path / name
    path.write_bytes(content)
    return path


def test_handle_selected_paths_populates_table(tmp_path):
    page = _make_page()
    file_a = _make_file(tmp_path, "a.txt")

    page._handle_selected_paths([str(file_a)])

    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == "a.txt"
    assert "1 file(s) queued" in page.summary_label.text()


def test_remove_selected_removes_row(tmp_path):
    page = _make_page()
    file_a = _make_file(tmp_path, "a.txt")
    page._handle_selected_paths([str(file_a)])

    page.table.selectRow(0)
    page._on_remove_selected_clicked()

    assert page.table.rowCount() == 0
    assert page._queue.count == 0


def test_clear_empties_queue_and_table(tmp_path):
    page = _make_page()
    file_a = _make_file(tmp_path, "a.txt")
    file_b = _make_file(tmp_path, "b.txt")
    page._handle_selected_paths([str(file_a), str(file_b)])

    page._on_clear_clicked()

    assert page.table.rowCount() == 0
    assert page._queue.count == 0


def test_invalid_file_shown_with_invalid_status(tmp_path):
    page = _make_page()
    empty_file = _make_file(tmp_path, "empty.txt", b"")

    page._handle_selected_paths([str(empty_file)])

    assert page.table.item(0, 4).text() == "Invalid"


def test_encrypt_button_stays_disabled(tmp_path):
    page = _make_page()
    file_a = _make_file(tmp_path, "a.txt")
    page._handle_selected_paths([str(file_a)])

    assert page.encrypt_button.isEnabled() is False
