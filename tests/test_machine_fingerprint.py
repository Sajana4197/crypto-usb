"""Tests for stable machine fingerprint computation."""

from validation.machine_fingerprint import compute_machine_fingerprint


def test_same_guid_produces_same_fingerprint():
    a = compute_machine_fingerprint(machine_guid_fn=lambda: "11111111-1111-1111-1111-111111111111")
    b = compute_machine_fingerprint(machine_guid_fn=lambda: "11111111-1111-1111-1111-111111111111")
    assert a == b


def test_different_guids_produce_different_fingerprints():
    a = compute_machine_fingerprint(machine_guid_fn=lambda: "11111111-1111-1111-1111-111111111111")
    b = compute_machine_fingerprint(machine_guid_fn=lambda: "22222222-2222-2222-2222-222222222222")
    assert a != b


def test_fingerprint_is_sha256_hex():
    fingerprint = compute_machine_fingerprint(machine_guid_fn=lambda: "some-guid")
    assert len(fingerprint) == 64
    int(fingerprint, 16)  # must be valid hex, raises otherwise


def test_falls_back_when_guid_unavailable():
    fingerprint = compute_machine_fingerprint(machine_guid_fn=lambda: None)
    assert len(fingerprint) == 64
    int(fingerprint, 16)


def test_fallback_is_deterministic_within_the_same_process():
    a = compute_machine_fingerprint(machine_guid_fn=lambda: None)
    b = compute_machine_fingerprint(machine_guid_fn=lambda: None)
    assert a == b


def test_fingerprint_never_holds_the_raw_guid():
    guid = "UNMISTAKABLE-GUID-MARKER-998877"
    fingerprint = compute_machine_fingerprint(machine_guid_fn=lambda: guid)
    assert guid not in fingerprint
