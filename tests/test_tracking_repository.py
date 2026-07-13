"""Tests for SQLite persistence of the tamper-evident usage log."""

import sqlite3

import pytest

from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import GENESIS_HMAC, TamperEvidentLog, generate_tracking_keys
from tracking.models import UsageRecord


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return TrackingRepository(connection)


@pytest.fixture
def log():
    return TamperEvidentLog(generate_tracking_keys())


def _record(session_id="session-1") -> UsageRecord:
    return UsageRecord(session_id=session_id, user="alice", machine_id="machine-1", file_id="file-1")


def test_new_repository_is_empty(repository):
    assert repository.count() == 0
    assert repository.list_entries() == []


def test_last_entry_hmac_is_genesis_when_empty(repository):
    assert repository.last_entry_hmac() == GENESIS_HMAC


def test_append_and_list_round_trip(repository, log):
    entry = log.seal(_record())
    repository.append("session-1", entry)

    stored = repository.list_entries()

    assert len(stored) == 1
    assert stored[0].nonce == entry.nonce
    assert stored[0].ciphertext == entry.ciphertext
    assert stored[0].prev_hmac == entry.prev_hmac
    assert stored[0].entry_hmac == entry.entry_hmac


def test_last_entry_hmac_reflects_the_most_recent_append(repository, log):
    first = log.seal(_record("session-1"))
    repository.append("session-1", first)
    assert repository.last_entry_hmac() == first.entry_hmac

    second = log.seal(_record("session-2"), prev_hmac=first.entry_hmac)
    repository.append("session-2", second)
    assert repository.last_entry_hmac() == second.entry_hmac


def test_entries_are_returned_in_append_order(repository, log):
    prev = GENESIS_HMAC
    sealed = []
    for i in range(5):
        entry = log.seal(_record(f"session-{i}"), prev_hmac=prev)
        repository.append(f"session-{i}", entry)
        sealed.append(entry)
        prev = entry.entry_hmac

    stored = repository.list_entries()

    assert [e.entry_hmac for e in stored] == [e.entry_hmac for e in sealed]


def test_count_reflects_number_of_appends(repository, log):
    for i in range(3):
        repository.append(f"session-{i}", log.seal(_record(f"session-{i}")))
    assert repository.count() == 3


def test_repository_exposes_no_update_or_delete_method(repository):
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")
