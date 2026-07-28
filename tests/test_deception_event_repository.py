"""Tests for SQLite persistence of the deception-activation audit trail."""

import sqlite3
from datetime import datetime, timezone

import pytest

from deception.content_types import DeceptionContentType
from deception.event_repository import DeceptionEventRepository, PresentedDeviceInfo
from deception.triggers import DeceptionTrigger


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return DeceptionEventRepository(connection)


def test_new_repository_is_empty(repository):
    assert repository.count() == 0
    assert repository.list_events() == []


def test_record_and_list_round_trip(repository):
    now = datetime.now(timezone.utc)
    repository.record(DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "file-1", now)

    events = repository.list_events()

    assert len(events) == 1
    assert events[0].trigger == DeceptionTrigger.WRONG_CREDENTIALS
    assert events[0].content_type == DeceptionContentType.FAKE_TEXT
    assert events[0].file_id == "file-1"
    assert events[0].generated_at == now


def test_file_id_can_be_none(repository):
    repository.record(DeceptionTrigger.INTEGRITY_FAILURE, DeceptionContentType.CORRUPTED_DATA, None, datetime.now(timezone.utc))

    events = repository.list_events()
    assert events[0].file_id is None


def test_count_reflects_number_of_records(repository):
    for i in range(3):
        repository.record(DeceptionTrigger.DEVICE_MISMATCH, DeceptionContentType.FAKE_IMAGE, f"file-{i}", datetime.now(timezone.utc))
    assert repository.count() == 3


def test_list_events_returns_most_recent_first(repository):
    repository.record(DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "file-1", datetime.now(timezone.utc))
    repository.record(DeceptionTrigger.ACCESS_ALREADY_USED, DeceptionContentType.FAKE_PDF, "file-2", datetime.now(timezone.utc))
    repository.record(DeceptionTrigger.METADATA_TAMPERING, DeceptionContentType.FAKE_METADATA, "file-3", datetime.now(timezone.utc))

    events = repository.list_events()

    assert [e.file_id for e in events] == ["file-3", "file-2", "file-1"]


def test_every_trigger_and_content_type_round_trips(repository):
    for trigger in DeceptionTrigger:
        for content_type in DeceptionContentType:
            repository.record(trigger, content_type, "file-x", datetime.now(timezone.utc))

    events = repository.list_events()
    assert len(events) == len(list(DeceptionTrigger)) * len(list(DeceptionContentType))
    assert all(isinstance(e.trigger, DeceptionTrigger) for e in events)
    assert all(isinstance(e.content_type, DeceptionContentType) for e in events)


def test_repository_exposes_no_update_or_delete_method(repository):
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")


def test_clear_removes_every_event(repository):
    repository.record(DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "file-1", datetime.now(timezone.utc))
    repository.record(DeceptionTrigger.ACCESS_ALREADY_USED, DeceptionContentType.FAKE_PDF, "file-2", datetime.now(timezone.utc))

    assert repository.clear() == 2

    assert repository.count() == 0
    assert repository.list_events() == []


def test_clear_on_empty_repository_returns_zero(repository):
    assert repository.clear() == 0


# -- Presented device info (Phase 5) -----------------------------------------


def test_record_and_list_round_trip_with_device_info(repository):
    info = PresentedDeviceInfo(
        usb_serial="ABCD1234:FAT32:1000000",
        vendor_id="SANDISK",
        product_id="CRUZER_BLADE",
        hardware_serial="4C530001A2B3C4D5",
        mount_point="E:\\",
        label="MYUSB",
    )
    repository.record(
        DeceptionTrigger.DEVICE_MISMATCH,
        DeceptionContentType.FAKE_IMAGE,
        "file-1",
        datetime.now(timezone.utc),
        device_info=info,
    )

    events = repository.list_events()

    assert len(events) == 1
    assert events[0].device_info == info


def test_record_without_device_info_defaults_to_empty():
    conn = sqlite3.connect(":memory:")
    repo = DeceptionEventRepository(conn)
    repo.record(DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "file-1", datetime.now(timezone.utc))

    events = repo.list_events()

    assert events[0].device_info == PresentedDeviceInfo()
    assert events[0].device_info.is_empty is True


def test_presented_device_info_is_empty_detects_any_field_set():
    assert PresentedDeviceInfo().is_empty is True
    assert PresentedDeviceInfo(usb_serial="ABCD").is_empty is False
    assert PresentedDeviceInfo(label="MYUSB").is_empty is False


def test_schema_migration_adds_device_columns_to_a_pre_phase_5_table():
    """Simulates a database created before Phase 5 (only the original five
    columns exist) -- opening it with the current `DeceptionEventRepository`
    must add the missing columns instead of failing, and any row already
    there must still read back fine, with every new field `None`."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE deception_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trigger TEXT NOT NULL,
            content_type TEXT NOT NULL,
            file_id TEXT,
            generated_at TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
        """
    )
    now = datetime.now(timezone.utc)
    conn.execute(
        "INSERT INTO deception_events (trigger, content_type, file_id, generated_at, recorded_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (DeceptionTrigger.WRONG_CREDENTIALS.value, DeceptionContentType.FAKE_TEXT.value, "legacy-file", now.isoformat(), now.isoformat()),
    )
    conn.commit()

    repo = DeceptionEventRepository(conn)  # must not raise

    events = repo.list_events()
    assert len(events) == 1
    assert events[0].file_id == "legacy-file"
    assert events[0].device_info == PresentedDeviceInfo()

    # New writes on the migrated table work exactly as on a fresh one.
    repo.record(
        DeceptionTrigger.DEVICE_MISMATCH,
        DeceptionContentType.CORRUPTED_DATA,
        "new-file",
        now,
        device_info=PresentedDeviceInfo(usb_serial="NEW-SERIAL"),
    )
    events = repo.list_events()
    assert len(events) == 2
    assert events[0].device_info.usb_serial == "NEW-SERIAL"
