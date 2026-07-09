"""Tests for AES-256-GCM encryption/decryption."""

import pytest

from crypto import aes_cipher
from crypto.exceptions import DecryptionError, EncryptionError


def test_generate_fek_is_32_bytes():
    key = aes_cipher.generate_fek()
    assert len(key) == 32


def test_generate_fek_is_random():
    assert aes_cipher.generate_fek() != aes_cipher.generate_fek()


def test_encrypt_decrypt_round_trip():
    key = aes_cipher.generate_fek()
    plaintext = b"the quick brown fox jumps over the lazy dog"

    nonce, ciphertext = aes_cipher.encrypt(plaintext, key)
    recovered = aes_cipher.decrypt(nonce, ciphertext, key)

    assert recovered == plaintext


def test_nonce_is_unique_per_call():
    key = aes_cipher.generate_fek()
    nonce1, _ = aes_cipher.encrypt(b"data", key)
    nonce2, _ = aes_cipher.encrypt(b"data", key)
    assert nonce1 != nonce2


def test_ciphertext_differs_from_plaintext():
    key = aes_cipher.generate_fek()
    plaintext = b"not secret at all until encrypted"
    _, ciphertext = aes_cipher.encrypt(plaintext, key)
    assert plaintext not in ciphertext


def test_decrypt_with_wrong_key_fails():
    key_a = aes_cipher.generate_fek()
    key_b = aes_cipher.generate_fek()
    nonce, ciphertext = aes_cipher.encrypt(b"secret data", key_a)

    with pytest.raises(DecryptionError):
        aes_cipher.decrypt(nonce, ciphertext, key_b)


def test_decrypt_with_tampered_ciphertext_fails():
    key = aes_cipher.generate_fek()
    nonce, ciphertext = aes_cipher.encrypt(b"secret data", key)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF

    with pytest.raises(DecryptionError):
        aes_cipher.decrypt(nonce, bytes(tampered), key)


def test_encrypt_rejects_wrong_key_size():
    with pytest.raises(EncryptionError):
        aes_cipher.encrypt(b"data", b"too-short-key")


def test_decrypt_rejects_wrong_key_size():
    key = aes_cipher.generate_fek()
    nonce, ciphertext = aes_cipher.encrypt(b"data", key)
    with pytest.raises(DecryptionError):
        aes_cipher.decrypt(nonce, ciphertext, b"too-short-key")


def test_associated_data_must_match_to_decrypt():
    key = aes_cipher.generate_fek()
    nonce, ciphertext = aes_cipher.encrypt(b"data", key, associated_data=b"file-id-1")

    with pytest.raises(DecryptionError):
        aes_cipher.decrypt(nonce, ciphertext, key, associated_data=b"file-id-2")

    assert aes_cipher.decrypt(nonce, ciphertext, key, associated_data=b"file-id-1") == b"data"


def test_encrypt_decrypt_empty_plaintext():
    key = aes_cipher.generate_fek()
    nonce, ciphertext = aes_cipher.encrypt(b"", key)
    assert aes_cipher.decrypt(nonce, ciphertext, key) == b""
