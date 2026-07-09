"""Tests for RSA-4096 key pair generation, serialization, and loading."""

import pytest

from crypto import rsa_keypair
from crypto.exceptions import CryptoError


def test_generate_rsa_keypair_is_4096_bits():
    keypair = rsa_keypair.generate_rsa_keypair()
    assert keypair.private_key.key_size == 4096
    assert keypair.public_key.key_size == 4096
    assert keypair.algorithm == "RSA-4096"


def test_serialize_private_key_requires_passphrase():
    keypair = rsa_keypair.generate_rsa_keypair()
    with pytest.raises(CryptoError):
        rsa_keypair.serialize_private_key(keypair.private_key, b"")


def test_private_key_pem_is_encrypted_not_plaintext():
    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")
    assert b"ENCRYPTED PRIVATE KEY" in pem
    assert b"-----BEGIN PRIVATE KEY-----" not in pem  # would indicate unencrypted PKCS8


def test_private_key_round_trip_with_correct_passphrase():
    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")

    loaded = rsa_keypair.load_private_key(pem, b"correct-passphrase")
    assert loaded.private_numbers() == keypair.private_key.private_numbers()


def test_private_key_load_fails_with_wrong_passphrase():
    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, b"correct-passphrase")

    with pytest.raises(CryptoError):
        rsa_keypair.load_private_key(pem, b"wrong-passphrase")


def test_public_key_round_trip():
    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_public_key(keypair.public_key)

    loaded = rsa_keypair.load_public_key(pem)
    assert loaded.public_numbers() == keypair.public_key.public_numbers()


def test_public_key_pem_is_plaintext():
    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_public_key(keypair.public_key)
    assert b"-----BEGIN PUBLIC KEY-----" in pem


def test_load_public_key_rejects_garbage():
    with pytest.raises(CryptoError):
        rsa_keypair.load_public_key(b"not a real PEM")
