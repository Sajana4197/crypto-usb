"""Tests for SQLite persistence of the deception-activation audit trail."""

import sqlite3
from datetime import datetime, timezone

import pytest

from deception.content_types import DeceptionContentType
from deception.event_repository import DeceptionEventRepository
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
