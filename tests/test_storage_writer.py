"""Tests for atomic, overwrite-protected, self-verifying secure container writes."""

from datetime import datetime, timezone

import pytest

from crypto.file_encryptor import FileEncryptor
from crypto.key_wrapper import RSAOAEPKeyWrapper
from metadata.hashing import compute_integrity_hash
from metadata.models import FileMetadata
from metadata.protection import MetadataProtector, generate_protection_keys
from usb.device_detector import USBDevice
from usb.exceptions import (
    ContainerOverwriteError,
    ContainerVerificationError,
    ContainerWriteError,
    DeviceValidationError,
)
from usb.secure_container import SecureContainer
from usb.storage_writer import SecureStorageWriter


@pytest.fixture
def wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


def _device(mount_point, free_bytes=100_000_000):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label="TEST",
        filesystem="FAT32",
        total_bytes=free_bytes * 2,
        free_bytes=free_bytes,
        is_removable=True,
    )


def _container(wrapper, file_id="file-1", plaintext=b"secret data"):
    file_container = FileEncryptor().encrypt_bytes(plaintext, wrapper)
    metadata = FileMetadata(
        file_id=file_id,
        owner_id="owner-1",
        wrapped_key=file_container.wrapped_key,
        wrap_algorithm=file_container.wrap_algorithm,
        integrity_hash=compute_integrity_hash(file_container.serialize()),
        created_at=datetime.now(timezone.utc),
    )
    protected = MetadataProtector(generate_protection_keys()).protect(metadata)
    return SecureContainer(file_id=file_id, file_container=file_container, protected_metadata=protected)


def test_write_container_creates_file(tmp_path, wrapper):
    device = _device(str(tmp_path))
    destination = SecureStorageWriter().write_container(_container(wrapper), device)

    assert destination.exists()
    assert destination.suffix == ".cusc"


def test_written_container_has_no_plaintext(tmp_path, wrapper):
    marker = b"UNMISTAKABLE_PLAINTEXT_MARKER_998877"
    device = _device(str(tmp_path))
    destination = SecureStorageWriter().write_container(_container(wrapper, plaintext=marker), device)

    assert marker not in destination.read_bytes()


def test_write_container_refuses_overwrite_by_default(tmp_path, wrapper):
    device = _device(str(tmp_path))
    writer = SecureStorageWriter()

    writer.write_container(_container(wrapper), device, filename="dup.cusc")
    with pytest.raises(ContainerOverwriteError):
        writer.write_container(_container(wrapper), device, filename="dup.cusc")


@pytest.mark.parametrize(
    "malicious_name",
    ["../escaped.cusc", "../../escaped.cusc", "sub/escaped.cusc", "C:\\escaped.cusc", ".."],
)
def test_write_container_rejects_filenames_with_a_path_component(tmp_path, wrapper, malicious_name):
    device = _device(str(tmp_path))

    with pytest.raises(ContainerWriteError):
        SecureStorageWriter().write_container(_container(wrapper), device, filename=malicious_name)

    # Nothing should have been written anywhere outside (or inside) the device dir.
    assert list(tmp_path.rglob("*.cusc")) == []


def test_write_container_overwrite_true_replaces_file(tmp_path, wrapper):
    device = _device(str(tmp_path))
    writer = SecureStorageWriter()
    container_a = _container(wrapper, file_id="a", plaintext=b"first")
    container_b = _container(wrapper, file_id="a", plaintext=b"second")

    path_a = writer.write_container(container_a, device, filename="dup.cusc")
    path_b = writer.write_container(container_b, device, filename="dup.cusc", overwrite=True)

    assert path_a == path_b
    restored = writer.read_container(path_b)
    assert restored.file_container.ciphertext == container_b.file_container.ciphertext


def test_write_container_leaves_no_leftover_temp_files(tmp_path, wrapper):
    device = _device(str(tmp_path))
    SecureStorageWriter().write_container(_container(wrapper), device)

    assert list(tmp_path.glob("*.tmp")) == []


def test_write_container_raises_on_insufficient_space(tmp_path, wrapper):
    device = _device(str(tmp_path), free_bytes=10)

    with pytest.raises(DeviceValidationError):
        SecureStorageWriter().write_container(_container(wrapper), device)


def test_verify_container_detects_tampering(tmp_path, wrapper):
    device = _device(str(tmp_path))
    writer = SecureStorageWriter()
    destination = writer.write_container(_container(wrapper), device)

    data = bytearray(destination.read_bytes())
    data[20] ^= 0xFF
    destination.write_bytes(bytes(data))

    with pytest.raises(ContainerVerificationError):
        writer.verify_container(destination)


def test_verify_container_missing_file_raises(tmp_path):
    with pytest.raises(ContainerVerificationError):
        SecureStorageWriter().verify_container(tmp_path / "missing.cusc")


def test_read_container_round_trip(tmp_path, wrapper):
    device = _device(str(tmp_path))
    writer = SecureStorageWriter()
    container = _container(wrapper)
    destination = writer.write_container(container, device)

    restored = writer.read_container(destination)
    assert restored.file_id == container.file_id
