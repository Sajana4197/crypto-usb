"""Integration tests for the Secure Storage Layer orchestration service."""

import pytest

from crypto.key_wrapper import RSAOAEPKeyWrapper
from usb.device_detector import USBDevice
from usb.exceptions import ContainerOverwriteError, ContainerVerificationError
from usb.secure_storage_service import SecureStorageService


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


def _usb_dir(tmp_path):
    device_dir = tmp_path / "usb"
    device_dir.mkdir()
    return device_dir


def test_store_file_writes_container_and_verifies(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"confidential research findings")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1")

    assert result.destination.exists()
    assert service.verify_stored_file(result.destination, wrapper, result.protection_keys) is True


def test_store_file_never_writes_plaintext(tmp_path, wrapper):
    marker = b"UNMISTAKABLE_PLAINTEXT_MARKER_112233"
    source = tmp_path / "secret.txt"
    source.write_bytes(marker)
    device = _device(str(_usb_dir(tmp_path)))

    result = SecureStorageService().store_file(source, device, wrapper, owner_id="researcher-1")

    assert marker not in result.destination.read_bytes()


def test_store_file_refuses_overwrite(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1")
    container = service._storage_writer.read_container(result.destination)

    with pytest.raises(ContainerOverwriteError):
        service._storage_writer.write_container(container, device, filename=result.destination.name)


def test_verify_stored_file_fails_with_wrong_key(tmp_path, wrapper, other_rsa_keypair_fixture):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1")

    wrong_wrapper = RSAOAEPKeyWrapper(
        other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key
    )
    with pytest.raises(ContainerVerificationError):
        service.verify_stored_file(result.destination, wrong_wrapper, result.protection_keys)


def test_each_stored_file_gets_unique_file_id(tmp_path, wrapper):
    source_a = tmp_path / "a.txt"
    source_b = tmp_path / "b.txt"
    source_a.write_bytes(b"same content")
    source_b.write_bytes(b"same content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result_a = service.store_file(source_a, device, wrapper, owner_id="researcher-1")
    result_b = service.store_file(source_b, device, wrapper, owner_id="researcher-1")

    assert result_a.file_id != result_b.file_id
    assert result_a.destination != result_b.destination


def test_stored_metadata_integrity_hash_matches_file_container(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content to hash")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1")

    from metadata.hashing import verify_integrity_hash
    from metadata.protection import MetadataProtector

    container = service._storage_writer.read_container(result.destination)
    protector = MetadataProtector(result.protection_keys)
    metadata = protector.unprotect(container.protected_metadata)

    assert verify_integrity_hash(container.file_container.serialize(), metadata.integrity_hash)
