"""Tests for `UsageTracker`: session lifecycle tracking and persistence."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
import tracking.tracking_service as tracking_service_module


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return TrackingRepository(connection)


@pytest.fixture
def tracker(repository):
    return UsageTracker(generate_tracking_keys(), repository)


@pytest.fixture
def tracker_without_repository():
    return UsageTracker(generate_tracking_keys())


# -- Session lifecycle: fields are tracked as required --------------------


def test_start_session_records_identity_and_login_time(tracker):
    record = tracker.start_session(user="alice", machine_id="machine-1", file_id="file-1", usb_id="usb-1")

    assert record.session_id
    assert record.user == "alice"
    assert record.machine_id == "machine-1"
    assert record.file_id == "file-1"
    assert record.usb_id == "usb-1"
    assert record.login_time is not None


def test_start_session_usb_id_defaults_to_none(tracker):
    record = tracker.start_session(user="alice", machine_id="machine-1", file_id="file-1")
    assert record.usb_id is None


def test_record_authentication_and_validation_results(tracker):
    record = tracker.start_session(user="alice", machine_id="m", file_id="f")

    tracker.record_authentication_result(record, True)
    tracker.record_validation_result(record, False)

    assert record.authentication_result is True
    assert record.validation_result is False


def test_record_open_sets_open_time(tracker):
    record = tracker.start_session(user="alice", machine_id="m", file_id="f")
    assert record.open_time is None

    tracker.record_open(record)

    assert record.open_time is not None


def test_screen_capture_attempts_accumulate(tracker):
    record = tracker.start_session(user="alice", machine_id="m", file_id="f")

    tracker.record_screen_capture_attempt(record)
    tracker.record_screen_capture_attempt(record)
    tracker.record_screen_capture_attempt(record)

    assert record.screen_capture_attempts == 3


def test_tampering_events_accumulate(tracker):
    record = tracker.start_session(user="alice", machine_id="m", file_id="f")

    tracker.record_tampering_event(record)
    tracker.record_tampering_event(record)

    assert record.tampering_events == 2


def test_record_close_sets_close_time_and_computes_duration(tracker, monkeypatch):
    times = iter(
        [
            datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),  # login
            datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc),  # open
            datetime(2026, 1, 1, 12, 5, 5, tzinfo=timezone.utc),  # close
        ]
    )
    monkeypatch.setattr(tracking_service_module, "_now", lambda: next(times))

    record = tracker.start_session(user="alice", machine_id="m", file_id="f")
    tracker.record_open(record)
    tracker.record_close(record)

    assert record.close_time == datetime(2026, 1, 1, 12, 5, 5, tzinfo=timezone.utc)
    assert record.duration_seconds == 300.0


def test_record_close_without_open_leaves_duration_unset(tracker):
    record = tracker.start_session(user="alice", machine_id="m", file_id="f")
    tracker.record_close(record)
    assert record.duration_seconds is None


# -- Persistence -----------------------------------------------------------


def test_record_close_persists_to_the_repository(tracker, repository):
    record = tracker.start_session(user="alice", machine_id="m", file_id="f")
    tracker.record_open(record)
    tracker.record_close(record)

    assert repository.count() == 1


def test_read_all_records_returns_the_full_session_after_close(tracker):
    record = tracker.start_session(user="alice", machine_id="machine-1", file_id="file-1", usb_id="usb-1")
    tracker.record_authentication_result(record, True)
    tracker.record_validation_result(record, True)
    tracker.record_open(record)
    tracker.record_screen_capture_attempt(record)
    tracker.record_tampering_event(record)
    tracker.record_close(record)

    [stored] = tracker.read_all_records()

    assert stored.session_id == record.session_id
    assert stored.user == "alice"
    assert stored.machine_id == "machine-1"
    assert stored.usb_id == "usb-1"
    assert stored.file_id == "file-1"
    assert stored.authentication_result is True
    assert stored.validation_result is True
    assert stored.screen_capture_attempts == 1
    assert stored.tampering_events == 1
    assert stored.duration_seconds is not None


def test_multiple_sessions_are_all_persisted_in_order(tracker):
    for i in range(3):
        record = tracker.start_session(user=f"user-{i}", machine_id="m", file_id="f")
        tracker.record_close(record)

    stored = tracker.read_all_records()

    assert [r.user for r in stored] == ["user-0", "user-1", "user-2"]


def test_tracker_without_repository_does_not_persist(tracker_without_repository):
    record = tracker_without_repository.start_session(user="alice", machine_id="m", file_id="f")
    tracker_without_repository.record_close(record)

    assert tracker_without_repository.read_all_records() == []


# -- Integrity verification, including end-to-end tamper detection ---------


def test_verify_log_integrity_ok_after_normal_use(tracker):
    for i in range(3):
        record = tracker.start_session(user=f"user-{i}", machine_id="m", file_id="f")
        tracker.record_close(record)

    result = tracker.verify_log_integrity()

    assert result.ok is True
    assert result.verified_count == 3


def test_verify_log_integrity_ok_for_an_empty_log(tracker):
    result = tracker.verify_log_integrity()
    assert result.ok is True
    assert result.verified_count == 0


def test_verify_log_integrity_detects_a_direct_database_edit(tracker, connection):
    """The realistic attack this module defends against: someone with
    filesystem/DB access edits a stored row directly, bypassing the
    application entirely."""
    for i in range(3):
        record = tracker.start_session(user=f"user-{i}", machine_id="m", file_id="f")
        tracker.record_close(record)

    cur = connection.execute("SELECT id, ciphertext FROM usage_log WHERE id = 2")
    row_id, ciphertext = cur.fetchone()
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    connection.execute("UPDATE usage_log SET ciphertext = ? WHERE id = ?", (bytes(tampered), row_id))
    connection.commit()

    result = tracker.verify_log_integrity()

    assert result.ok is False
    assert result.verified_count == 1


def test_verify_log_integrity_detects_a_direct_row_deletion(tracker, connection):
    for i in range(3):
        record = tracker.start_session(user=f"user-{i}", machine_id="m", file_id="f")
        tracker.record_close(record)

    connection.execute("DELETE FROM usage_log WHERE id = 2")
    connection.commit()

    result = tracker.verify_log_integrity()

    assert result.ok is False
    assert result.verified_count == 1
