"""Tests for RAM-only decryption via `SecureDecryptor`."""

from pathlib import Path
from unittest.mock import patch

import pytest

from crypto.exceptions import DecryptionError, KeyDestroyedError, KeyUnwrappingError
from crypto.file_encryptor import FileEncryptor
from crypto.key_wrapper import RSAOAEPKeyWrapper
from crypto.secure_decryptor import SecureDecryptor

PLAINTEXT = b"top secret in-memory-only research payload"


@pytest.fixture
def wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


@pytest.fixture
def other_wrapper(other_rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(
        other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key
    )


@pytest.fixture
def container(wrapper):
    return FileEncryptor().encrypt_bytes(PLAINTEXT, wrapper)


@pytest.fixture
def decryptor():
    return SecureDecryptor()


# -- Decryption correctness -------------------------------------------------


def test_open_decrypted_yields_correct_plaintext(decryptor, container, wrapper):
    with decryptor.open_decrypted(container, wrapper) as buffer:
        assert bytes(buffer) == PLAINTEXT


def test_open_decrypted_with_wrong_key_raises(decryptor, container, other_wrapper):
    with pytest.raises(KeyUnwrappingError):
        with decryptor.open_decrypted(container, other_wrapper):
            pass


def test_open_decrypted_with_tampered_ciphertext_raises(decryptor, container, wrapper):
    tampered = bytearray(container.ciphertext)
    tampered[-1] ^= 0xFF
    container.ciphertext = bytes(tampered)

    with pytest.raises(DecryptionError):
        with decryptor.open_decrypted(container, wrapper):
            pass


def test_can_decrypt_the_same_container_multiple_times(decryptor, container, wrapper):
    with decryptor.open_decrypted(container, wrapper) as first:
        assert bytes(first) == PLAINTEXT
    with decryptor.open_decrypted(container, wrapper) as second:
        assert bytes(second) == PLAINTEXT


# -- Buffer lifecycle: destroyed immediately after use -----------------------


def test_buffer_is_destroyed_after_the_with_block_exits(decryptor, container, wrapper):
    with decryptor.open_decrypted(container, wrapper) as buffer:
        leaked = buffer

    assert leaked.is_destroyed is True
    with pytest.raises(KeyDestroyedError):
        bytes(leaked)


def test_buffer_is_destroyed_even_if_the_caller_raises(decryptor, container, wrapper):
    leaked = None
    with pytest.raises(RuntimeError):
        with decryptor.open_decrypted(container, wrapper) as buffer:
            leaked = buffer
            raise RuntimeError("caller-side failure while viewing")

    assert leaked is not None
    assert leaked.is_destroyed is True


def test_open_decrypted_destroys_the_unwrapped_fek(decryptor, container, wrapper):
    with patch("crypto.key_manager.ManagedKey.destroy", autospec=True) as mock_destroy:
        with decryptor.open_decrypted(container, wrapper) as buffer:
            assert bytes(buffer) == PLAINTEXT

    assert mock_destroy.called


# -- Never touches disk -------------------------------------------------


def test_open_decrypted_never_writes_to_disk(decryptor, container, wrapper, monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("Unexpected disk write during RAM-only decryption")

    monkeypatch.setattr(Path, "write_bytes", _forbidden)
    monkeypatch.setattr(Path, "write_text", _forbidden)

    with decryptor.open_decrypted(container, wrapper) as buffer:
        assert bytes(buffer) == PLAINTEXT


def test_secure_decryptor_module_exposes_no_path_based_api():
    import inspect

    signature = inspect.signature(SecureDecryptor.open_decrypted)
    for param in signature.parameters.values():
        assert param.annotation not in (Path, "Path"), (
            "SecureDecryptor must never accept a filesystem path"
        )
