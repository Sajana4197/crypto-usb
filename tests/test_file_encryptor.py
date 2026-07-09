"""Tests for hybrid AES-256-GCM + RSA-OAEP file encryption."""

import pytest

from crypto.exceptions import DecryptionError, KeyUnwrappingError
from crypto.file_encryptor import EncryptedContainer, FileEncryptor
from crypto.key_wrapper import RSAOAEPKeyWrapper


@pytest.fixture
def wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


@pytest.fixture
def encryptor():
    return FileEncryptor()


# -- in-memory (disk-free) API ---------------------------------------------


def test_encrypt_decrypt_bytes_round_trip(encryptor, wrapper):
    plaintext = b"confidential research data"

    container = encryptor.encrypt_bytes(plaintext, wrapper)
    recovered = encryptor.decrypt_bytes(container, wrapper)

    assert recovered == plaintext


def test_encrypted_container_never_holds_plaintext(encryptor, wrapper):
    plaintext = b"the secret payload marker XYZ123"
    container = encryptor.encrypt_bytes(plaintext, wrapper)

    assert plaintext not in container.ciphertext
    assert plaintext not in container.wrapped_key
    assert plaintext not in container.serialize()


def test_wrapped_key_is_not_plaintext_fek(encryptor, wrapper):
    container = encryptor.encrypt_bytes(b"data", wrapper)
    assert len(container.wrapped_key) == 512  # RSA-4096 OAEP ciphertext size


# -- container serialization -------------------------------------------------


def test_container_serialize_deserialize_round_trip():
    container = EncryptedContainer(
        wrap_algorithm="RSA-OAEP",
        wrapped_key=b"\x01" * 512,
        nonce=b"\x02" * 12,
        ciphertext=b"\x03" * 64,
    )
    restored = EncryptedContainer.deserialize(container.serialize())

    assert restored == container


def test_deserialize_rejects_bad_magic():
    with pytest.raises(DecryptionError):
        EncryptedContainer.deserialize(b"NOTCUSB" + b"\x00" * 20)


# -- file-based API -----------------------------------------------------


def test_encrypt_decrypt_file_round_trip(encryptor, wrapper, tmp_path):
    original = tmp_path / "secret.txt"
    original.write_bytes(b"top secret file contents")
    encrypted_path = tmp_path / "secret.txt.cusb"
    decrypted_path = tmp_path / "secret.decrypted.txt"

    encryptor.encrypt_file(original, encrypted_path, wrapper)
    encryptor.decrypt_file(encrypted_path, decrypted_path, wrapper)

    assert decrypted_path.read_bytes() == original.read_bytes()


def test_encrypted_file_on_disk_has_no_plaintext(encryptor, wrapper, tmp_path):
    original = tmp_path / "secret.txt"
    marker = b"UNMISTAKABLE_PLAINTEXT_MARKER_998877"
    original.write_bytes(marker)
    encrypted_path = tmp_path / "secret.txt.cusb"

    encryptor.encrypt_file(original, encrypted_path, wrapper)

    assert marker not in encrypted_path.read_bytes()


def test_decrypt_file_with_wrong_private_key_fails(
    encryptor, wrapper, other_rsa_keypair_fixture, tmp_path
):
    original = tmp_path / "secret.txt"
    original.write_bytes(b"secret content")
    encrypted_path = tmp_path / "secret.txt.cusb"
    decrypted_path = tmp_path / "secret.decrypted.txt"

    encryptor.encrypt_file(original, encrypted_path, wrapper)

    wrong_wrapper = RSAOAEPKeyWrapper(
        other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key
    )
    with pytest.raises(KeyUnwrappingError):
        encryptor.decrypt_file(encrypted_path, decrypted_path, wrong_wrapper)


def test_decrypt_file_with_tampered_ciphertext_fails(encryptor, wrapper, tmp_path):
    original = tmp_path / "secret.txt"
    original.write_bytes(b"secret content that is long enough to tamper with")
    encrypted_path = tmp_path / "secret.txt.cusb"
    decrypted_path = tmp_path / "secret.decrypted.txt"

    encryptor.encrypt_file(original, encrypted_path, wrapper)

    tampered = bytearray(encrypted_path.read_bytes())
    tampered[-1] ^= 0xFF  # flip a byte inside the ciphertext/tag
    encrypted_path.write_bytes(bytes(tampered))

    with pytest.raises(DecryptionError):
        encryptor.decrypt_file(encrypted_path, decrypted_path, wrapper)


def test_each_file_gets_a_unique_fek(encryptor, wrapper, tmp_path):
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_bytes(b"same content")
    file_b.write_bytes(b"same content")

    container_a = encryptor.encrypt_file(file_a, tmp_path / "a.cusb", wrapper)
    container_b = encryptor.encrypt_file(file_b, tmp_path / "b.cusb", wrapper)

    # Same plaintext, independently generated FEKs/nonces -> different wrapped
    # keys and different ciphertext even though the source content is identical.
    assert container_a.wrapped_key != container_b.wrapped_key
    assert container_a.ciphertext != container_b.ciphertext
