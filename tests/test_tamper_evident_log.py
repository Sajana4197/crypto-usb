"""Tests for the hash-chained, encrypted usage log envelope."""

import copy
from datetime import datetime, timezone

import pytest

from tracking.exceptions import TrackingTamperError
from tracking.models import UsageRecord
from tracking.tamper_evident_log import (
    GENESIS_HMAC,
    ChainedLogEntry,
    TamperEvidentLog,
    generate_tracking_keys,
)


def _record(session_id="session-1", **overrides) -> UsageRecord:
    defaults = dict(
        session_id=session_id,
        user="alice",
        machine_id="machine-1",
        file_id="file-1",
        usb_id="usb-1",
        login_time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        close_time=datetime(2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc),
        duration_seconds=300.0,
        authentication_result=True,
        validation_result=True,
        screen_capture_attempts=0,
        tampering_events=0,
    )
    defaults.update(overrides)
    return UsageRecord(**defaults)


@pytest.fixture
def log():
    return TamperEvidentLog(generate_tracking_keys())


# -- seal / open round trip -----------------------------------------------


def test_seal_open_round_trip(log):
    record = _record()
    entry = log.seal(record)

    opened = log.open(entry)

    assert opened == record


def test_first_entry_chains_from_genesis(log):
    entry = log.seal(_record())
    assert entry.prev_hmac == GENESIS_HMAC


def test_second_entry_chains_from_first_entrys_hmac(log):
    first = log.seal(_record(session_id="s1"))
    second = log.seal(_record(session_id="s2"), prev_hmac=first.entry_hmac)

    assert second.prev_hmac == first.entry_hmac


def test_ciphertext_never_contains_plaintext_identifiers(log):
    record = _record(user="UNMISTAKABLE_USER_MARKER")
    entry = log.seal(record)

    assert b"UNMISTAKABLE_USER_MARKER" not in entry.ciphertext


# -- single-entry tamper detection -----------------------------------------


def test_open_detects_tampered_ciphertext(log):
    entry = log.seal(_record())
    tampered = bytearray(entry.ciphertext)
    tampered[0] ^= 0xFF
    entry.ciphertext = bytes(tampered)

    with pytest.raises(TrackingTamperError):
        log.open(entry)


def test_open_detects_tampered_entry_hmac(log):
    entry = log.seal(_record())
    tampered = bytearray(entry.entry_hmac)
    tampered[0] ^= 0xFF
    entry.entry_hmac = bytes(tampered)

    with pytest.raises(TrackingTamperError):
        log.open(entry)


def test_open_fails_with_the_wrong_keys():
    record = _record()
    entry = TamperEvidentLog(generate_tracking_keys()).seal(record)

    wrong_log = TamperEvidentLog(generate_tracking_keys())
    with pytest.raises(TrackingTamperError):
        wrong_log.open(entry)


def test_verify_entry_true_for_untouched_entry(log):
    entry = log.seal(_record())
    assert log.verify_entry(entry) is True


def test_verify_entry_false_for_tampered_entry(log):
    entry = log.seal(_record())
    tampered = bytearray(entry.ciphertext)
    tampered[-1] ^= 0xFF
    entry.ciphertext = bytes(tampered)

    assert log.verify_entry(entry) is False


# -- chain verification: modification, deletion, reordering ----------------


def _seal_chain(log, count: int) -> list[ChainedLogEntry]:
    entries = []
    prev = GENESIS_HMAC
    for i in range(count):
        entry = log.seal(_record(session_id=f"session-{i}"), prev_hmac=prev)
        entries.append(entry)
        prev = entry.entry_hmac
    return entries


def test_verify_chain_ok_for_an_untouched_chain(log):
    entries = _seal_chain(log, 5)

    result = log.verify_chain(entries)

    assert result.ok is True
    assert result.verified_count == 5
    assert result.reason is None


def test_verify_chain_empty_log_is_ok(log):
    result = log.verify_chain([])
    assert result.ok is True
    assert result.verified_count == 0


def test_verify_chain_detects_a_modified_middle_entry(log):
    entries = _seal_chain(log, 5)
    entries = copy.deepcopy(entries)
    tampered = bytearray(entries[2].ciphertext)
    tampered[0] ^= 0xFF
    entries[2].ciphertext = bytes(tampered)

    result = log.verify_chain(entries)

    assert result.ok is False
    assert result.verified_count == 2
    assert "entry 2" in result.reason


def test_verify_chain_detects_a_deleted_middle_entry(log):
    entries = _seal_chain(log, 5)
    del entries[2]  # remove one entry entirely; the chain link now skips it

    result = log.verify_chain(entries)

    assert result.ok is False
    assert result.verified_count == 2  # entries 0 and 1 still verify; entry at index 2 (was #3) breaks


def test_verify_chain_detects_reordered_entries(log):
    entries = _seal_chain(log, 4)
    entries[1], entries[2] = entries[2], entries[1]

    result = log.verify_chain(entries)

    assert result.ok is False
    assert result.verified_count == 1


def test_verify_chain_detects_an_appended_forged_entry_without_the_real_key(log):
    entries = _seal_chain(log, 3)

    forger_log = TamperEvidentLog(generate_tracking_keys())
    forged = forger_log.seal(_record(session_id="forged"), prev_hmac=entries[-1].entry_hmac)
    entries.append(forged)

    result = log.verify_chain(entries)

    assert result.ok is False
    assert result.verified_count == 3
