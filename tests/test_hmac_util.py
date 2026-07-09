"""Tests for HMAC-SHA256 generation and verification."""

from crypto.hmac_util import compute_hmac, generate_hmac_key, verify_hmac


def test_generate_hmac_key_is_32_bytes():
    assert len(generate_hmac_key()) == 32


def test_generate_hmac_key_is_random():
    assert generate_hmac_key() != generate_hmac_key()


def test_compute_and_verify_round_trip():
    key = generate_hmac_key()
    tag = compute_hmac(key, b"important data")
    assert verify_hmac(key, b"important data", tag) is True


def test_verify_fails_on_tampered_data():
    key = generate_hmac_key()
    tag = compute_hmac(key, b"important data")
    assert verify_hmac(key, b"tampered data!!", tag) is False


def test_verify_fails_on_wrong_key():
    key_a = generate_hmac_key()
    key_b = generate_hmac_key()
    tag = compute_hmac(key_a, b"important data")
    assert verify_hmac(key_b, b"important data", tag) is False


def test_verify_fails_on_tampered_tag():
    key = generate_hmac_key()
    tag = bytearray(compute_hmac(key, b"important data"))
    tag[0] ^= 0xFF
    assert verify_hmac(key, b"important data", bytes(tag)) is False
