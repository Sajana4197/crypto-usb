"""Integration tests for the Secure Storage Layer orchestration service."""

import pytest

from crypto.key_wrapper import RSAOAEPKeyWrapper
from crypto.rsa_keypair import private_key_material
from metadata.protection import MetadataProtector, derive_protection_keys_from_key_material
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


# -- Embedded portable metadata section (Phase B) ----------------------------


def test_store_file_without_portable_keys_embeds_no_portable_section(tmp_path, wrapper):
    from usb.storage_writer import SecureStorageWriter

    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = _usb_dir(tmp_path)
    device = _device(str(device_dir))

    result = SecureStorageService().store_file(source, device, wrapper, owner_id="researcher-1")

    assert result.portable_metadata_embedded is False
    container = SecureStorageWriter().read_container(result.destination)
    assert container.portable_metadata is None
    # Still exactly one file on the device -- no second file of any kind.
    assert len(list(device_dir.iterdir())) == 1


def test_store_file_with_portable_keys_embeds_portable_section_in_the_container(
    tmp_path, wrapper, rsa_keypair_fixture
):
    from usb.storage_writer import SecureStorageWriter

    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device_dir = _usb_dir(tmp_path)
    device = _device(str(device_dir))

    material = private_key_material(rsa_keypair_fixture.private_key)
    salt = b"\x11" * 16
    portable_keys = derive_protection_keys_from_key_material(material, b"a-strong-passphrase", salt)

    result = SecureStorageService().store_file(
        source,
        device,
        wrapper,
        owner_id="researcher-1",
        portable_metadata_keys=portable_keys,
        portable_metadata_salt=salt,
    )

    assert result.portable_metadata_embedded is True
    container = SecureStorageWriter().read_container(result.destination)
    assert container.portable_metadata is not None
    assert container.portable_metadata.salt == salt
    # Still exactly one file on the device -- the portable copy lives
    # inside the same .cusc file, not a second one.
    assert len(list(device_dir.iterdir())) == 1


def test_embedded_portable_metadata_is_independently_loadable_and_re_derivable(
    tmp_path, wrapper, rsa_keypair_fixture
):
    from usb.storage_writer import SecureStorageWriter

    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    material = private_key_material(rsa_keypair_fixture.private_key)
    passphrase = b"a-strong-passphrase"
    salt = b"\x22" * 16
    portable_keys = derive_protection_keys_from_key_material(material, passphrase, salt)

    result = SecureStorageService().store_file(
        source,
        device,
        wrapper,
        owner_id="researcher-1",
        portable_metadata_keys=portable_keys,
        portable_metadata_salt=salt,
    )

    writer = SecureStorageWriter()
    container = writer.read_container(result.destination)
    envelope = container.portable_metadata
    assert envelope.salt == salt

    # Re-derive independently from scratch -- as if on a different
    # machine with only the private key + passphrase + this envelope's
    # stored salt -- and confirm it unlocks the same metadata.
    rederived_keys = derive_protection_keys_from_key_material(material, passphrase, envelope.salt)
    restored = MetadataProtector(rederived_keys).unprotect(envelope.protected)

    embedded_metadata = MetadataProtector(result.protection_keys).unprotect(container.protected_metadata)
    assert restored == embedded_metadata


def test_portable_metadata_wrong_passphrase_fails_to_unprotect(tmp_path, wrapper, rsa_keypair_fixture):
    from metadata.exceptions import MetadataTamperError
    from usb.storage_writer import SecureStorageWriter

    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    material = private_key_material(rsa_keypair_fixture.private_key)
    salt = b"\x33" * 16
    portable_keys = derive_protection_keys_from_key_material(material, b"right-passphrase", salt)

    result = SecureStorageService().store_file(
        source,
        device,
        wrapper,
        owner_id="researcher-1",
        portable_metadata_keys=portable_keys,
        portable_metadata_salt=salt,
    )

    envelope = SecureStorageWriter().read_container(result.destination).portable_metadata
    wrong_keys = derive_protection_keys_from_key_material(material, b"wrong-passphrase", envelope.salt)

    with pytest.raises(MetadataTamperError):
        MetadataProtector(wrong_keys).unprotect(envelope.protected)


def test_store_file_requires_both_portable_metadata_params_together(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    with pytest.raises(ValueError):
        SecureStorageService().store_file(
            source, device, wrapper, owner_id="researcher-1", portable_metadata_keys=None, portable_metadata_salt=b"\x00" * 16
        )
