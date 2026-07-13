"""Tests for the `UsageRecord` data model."""

from datetime import datetime, timezone

from tracking.models import UsageRecord


def _record(**overrides) -> UsageRecord:
    defaults = dict(
        session_id="session-1",
        user="alice",
        machine_id="machine-1",
        file_id="file-1",
        usb_id="usb-1",
        login_time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        open_time=datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
        close_time=datetime(2026, 1, 1, 12, 5, 5, tzinfo=timezone.utc),
        duration_seconds=300.0,
        authentication_result=True,
        validation_result=True,
        screen_capture_attempts=2,
        tampering_events=1,
    )
    defaults.update(overrides)
    return UsageRecord(**defaults)


def test_defaults_are_empty_and_unset():
    record = UsageRecord(session_id="s", user="u", machine_id="m", file_id="f")

    assert record.usb_id is None
    assert record.login_time is None
    assert record.open_time is None
    assert record.close_time is None
    assert record.duration_seconds is None
    assert record.authentication_result is None
    assert record.validation_result is None
    assert record.screen_capture_attempts == 0
    assert record.tampering_events == 0


def test_to_dict_serializes_every_tracked_field():
    record = _record()
    data = record.to_dict()

    for field in [
        "session_id",
        "user",
        "machine_id",
        "file_id",
        "usb_id",
        "login_time",
        "open_time",
        "close_time",
        "duration_seconds",
        "authentication_result",
        "validation_result",
        "screen_capture_attempts",
        "tampering_events",
    ]:
        assert field in data

    assert data["login_time"] == "2026-01-01T12:00:00+00:00"


def test_to_dict_from_dict_round_trip():
    record = _record()
    restored = UsageRecord.from_dict(record.to_dict())

    assert restored == record


def test_from_dict_handles_missing_optional_fields():
    restored = UsageRecord.from_dict(
        {"session_id": "s", "user": "u", "machine_id": "m", "file_id": "f"}
    )

    assert restored.usb_id is None
    assert restored.login_time is None
    assert restored.screen_capture_attempts == 0
    assert restored.tampering_events == 0
