"""Tests for SHA-256 integrity hashing."""

from metadata.hashing import compute_integrity_hash, verify_integrity_hash


def test_compute_integrity_hash_is_64_hex_chars():
    digest = compute_integrity_hash(b"some encrypted file bytes")
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_compute_integrity_hash_is_deterministic():
    data = b"same content"
    assert compute_integrity_hash(data) == compute_integrity_hash(data)


def test_compute_integrity_hash_differs_for_different_data():
    assert compute_integrity_hash(b"content A") != compute_integrity_hash(b"content B")


def test_verify_integrity_hash_true_for_matching_data():
    data = b"container bytes"
    digest = compute_integrity_hash(data)
    assert verify_integrity_hash(data, digest) is True


def test_verify_integrity_hash_false_for_tampered_data():
    data = b"container bytes"
    digest = compute_integrity_hash(data)
    assert verify_integrity_hash(b"tampered bytes!!", digest) is False


def test_verify_integrity_hash_is_case_insensitive():
    data = b"container bytes"
    digest = compute_integrity_hash(data)
    assert verify_integrity_hash(data, digest.upper()) is True
