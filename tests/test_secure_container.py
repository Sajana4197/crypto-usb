"""Tests for the .cusc secure container format."""

import hashlib
from datetime import datetime, timezone

import pytest

from crypto.file_encryptor import FileEncryptor
from crypto.key_manager import KeyManager
from crypto.key_wrapper import RSAOAEPKeyWrapper
from metadata.hashing import compute_integrity_hash
from metadata.models import FileMetadata
from metadata.protection import MetadataProtector, generate_protection_keys
from usb.exceptions import ContainerVerificationError
from usb.secure_container import SecureContainer, verify_container_deep


@pytest.fixture
def wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


def _build_container(wrapper, plaintext=b"top secret research data", file_id="file-123"):
    file_container = FileEncryptor().encrypt_bytes(plaintext, wrapper)

    metadata = FileMetadata(
        file_id=file_id,
        owner_id="owner-1",
        wrapped_key=file_container.wrapped_key,
        wrap_algorithm=file_container.wrap_algorithm,
        integrity_hash=compute_integrity_hash(file_container.serialize()),
        created_at=datetime.now(timezone.utc),
    )
    keys = generate_protection_keys()
    protected = MetadataProtector(keys).protect(metadata)

    container = SecureContainer(file_id=file_id, file_container=file_container, protected_metadata=protected)
    return container, keys


def test_serialize_deserialize_round_trip(wrapper):
    container, _ = _build_container(wrapper)
    restored = SecureContainer.deserialize(container.serialize())

    assert restored.file_id == container.file_id
    assert restored.file_container == container.file_container
    assert restored.protected_metadata == container.protected_metadata


def test_serialized_container_has_no_plaintext(wrapper):
    marker = b"UNMISTAKABLE_PLAINTEXT_MARKER_5551234"
    container, _ = _build_container(wrapper, plaintext=marker)

    assert marker not in container.serialize()


def test_deserialize_rejects_bad_magic():
    body = b"NOTC" + bytes([1]) + bytes([0]) + (0).to_bytes(8, "big") + (0).to_bytes(8, "big")
    payload = body + hashlib.sha256(body).digest()

    with pytest.raises(ContainerVerificationError):
        SecureContainer.deserialize(payload)


def test_deserialize_rejects_tampered_outer_hash(wrapper):
    container, _ = _build_container(wrapper)
    data = bytearray(container.serialize())
    data[10] ^= 0xFF

    with pytest.raises(ContainerVerificationError):
        SecureContainer.deserialize(bytes(data))


def test_deserialize_rejects_truncated_data(wrapper):
    container, _ = _build_container(wrapper)
    data = container.serialize()[:-5]

    with pytest.raises(ContainerVerificationError):
        SecureContainer.deserialize(data)


def test_deserialize_rejects_too_short_data():
    with pytest.raises(ContainerVerificationError):
        SecureContainer.deserialize(b"short")


def test_verify_container_deep_success(wrapper):
    container, keys = _build_container(wrapper)
    protector = MetadataProtector(keys)

    assert verify_container_deep(container, KeyManager(), wrapper, protector) is True


def test_verify_container_deep_fails_with_wrong_key_wrapper(wrapper, other_rsa_keypair_fixture):
    container, keys = _build_container(wrapper)
    wrong_wrapper = RSAOAEPKeyWrapper(
        other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key
    )
    protector = MetadataProtector(keys)

    with pytest.raises(ContainerVerificationError):
        verify_container_deep(container, KeyManager(), wrong_wrapper, protector)


def test_verify_container_deep_fails_on_tampered_metadata(wrapper):
    container, keys = _build_container(wrapper)
    tampered_tag = bytearray(container.protected_metadata.hmac_tag)
    tampered_tag[0] ^= 0xFF
    container.protected_metadata.hmac_tag = bytes(tampered_tag)
    protector = MetadataProtector(keys)

    with pytest.raises(ContainerVerificationError):
        verify_container_deep(container, KeyManager(), wrapper, protector)


def test_verify_container_deep_fails_on_tampered_ciphertext(wrapper):
    container, keys = _build_container(wrapper)
    tampered = bytearray(container.file_container.ciphertext)
    tampered[0] ^= 0xFF
    container.file_container.ciphertext = bytes(tampered)
    protector = MetadataProtector(keys)

    with pytest.raises(ContainerVerificationError):
        verify_container_deep(container, KeyManager(), wrapper, protector)
