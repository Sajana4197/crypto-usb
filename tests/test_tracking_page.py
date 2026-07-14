"""Tests for the Usage Tracking dashboard page."""

import sqlite3

import pytest
from PySide6.QtWidgets import QApplication

from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
from ui.pages.tracking_page import TrackingPage


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


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


def test_verify_integrity_without_tracker_shows_error(app):
    page = _make_page(app)
    page._on_verify_clicked()
    assert "no usage tracker" in page.status_label.text().lower()
