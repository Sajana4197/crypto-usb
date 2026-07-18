"""Tests for the Usage Tracking dashboard page."""

import sqlite3
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
from ui.pages.tracking_page import TrackingPage


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def mock_result_popup(monkeypatch):
    """`important=True` status calls now pop up a real, blocking
    `QMessageBox` -- autouse so every test in this file is safe by
    default; tests that specifically assert on popup behavior can still
    take this fixture as a parameter to inspect the same mock."""
    mock = MagicMock()
    monkeypatch.setattr("ui.pages.tracking_page.show_result_popup", mock)
    return mock


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def tracker(connection):
    return UsageTracker(generate_tracking_keys(), TrackingRepository(connection))


def _make_page(app, usage_tracker=None):
    return TrackingPage(usage_tracker=usage_tracker)


def test_page_with_no_tracker_shows_unavailable_message(app):
    page = _make_page(app)
    assert page.table.rowCount() == 0
    assert "no usage tracker" in page.summary_label.text().lower()


def test_page_with_empty_tracker_shows_zero_records(app, tracker):
    page = _make_page(app, tracker)
    assert page.table.rowCount() == 0
    assert "0 recorded" in page.summary_label.text()


def test_page_shows_recorded_sessions(app, tracker):
    record = tracker.start_session(user="alice", machine_id="machine-1", file_id="file-1", usb_id="usb-1")
    tracker.record_authentication_result(record, True)
    tracker.record_validation_result(record, True)
    tracker.record_open(record)
    tracker.record_close(record)

    page = _make_page(app, tracker)

    assert page.table.rowCount() == 1
    assert page.table.item(0, 1).text() == "alice"
    assert page.table.item(0, 2).text() == "file-1"
    assert page.table.item(0, 7).text() == "Yes"  # auth ok
    assert page.table.item(0, 8).text() == "Yes"  # validation ok


def test_page_shows_denied_attempts_with_no_for_validation(app, tracker):
    record = tracker.start_session(user="alice", machine_id="machine-1", file_id="file-2")
    tracker.record_authentication_result(record, True)
    tracker.record_validation_result(record, False)
    tracker.record_close(record)

    page = _make_page(app, tracker)

    assert page.table.item(0, 8).text() == "No"


def test_most_recent_session_shown_first(app, tracker):
    first = tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    tracker.record_close(first)
    second = tracker.start_session(user="bob", machine_id="m", file_id="file-2")
    tracker.record_close(second)

    page = _make_page(app, tracker)

    assert page.table.item(0, 1).text() == "bob"
    assert page.table.item(1, 1).text() == "alice"


def test_refresh_button_reflects_new_sessions(app, tracker):
    page = _make_page(app, tracker)
    assert page.table.rowCount() == 0

    record = tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    tracker.record_close(record)
    page.refresh()

    assert page.table.rowCount() == 1


def test_verify_integrity_reports_ok_for_clean_log(app, tracker):
    record = tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    tracker.record_close(record)
    page = _make_page(app, tracker)

    page._on_verify_clicked()

    assert "verified" in page.status_label.text().lower()


def test_verify_integrity_success_pops_up_result(app, tracker, mock_result_popup):
    record = tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    tracker.record_close(record)
    page = _make_page(app, tracker)

    page._on_verify_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs.get("ok", True) is True


def test_verify_integrity_failure_pops_up_result(app, tracker, connection, mock_result_popup):
    record = tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    tracker.record_close(record)
    # Constructed before the row is tampered with -- TrackingPage.__init__
    # calls refresh(), which decrypts every record and would itself raise
    # on a tampered row rather than reporting a pass/fail result.
    page = _make_page(app, tracker)

    cur = connection.execute("SELECT id, ciphertext FROM usage_log WHERE id = 1")
    row_id, ciphertext = cur.fetchone()
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    connection.execute("UPDATE usage_log SET ciphertext = ? WHERE id = ?", (bytes(tampered), row_id))
    connection.commit()

    page._on_verify_clicked()

    mock_result_popup.assert_called_once()
    _, kwargs = mock_result_popup.call_args
    assert kwargs["ok"] is False


def test_refresh_does_not_pop_up_result(app, tracker, mock_result_popup):
    """Refresh is routine/live-state, not a deliberate pass/fail action."""
    page = _make_page(app, tracker)

    record = tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    tracker.record_close(record)
    page.refresh()

    mock_result_popup.assert_not_called()


def test_verify_integrity_without_tracker_shows_error(app):
    page = _make_page(app)
    page._on_verify_clicked()
    assert "no usage tracker" in page.status_label.text().lower()


def test_verify_integrity_without_tracker_does_not_pop_up(app, mock_result_popup):
    """The 'no usage tracker' guard fires before any verification is
    attempted -- not a pass/fail verify result, inline-only."""
    page = _make_page(app)
    page._on_verify_clicked()
    mock_result_popup.assert_not_called()
