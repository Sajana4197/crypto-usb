"""Integration tests for the Secure Storage Layer orchestration service."""

import pytest

from crypto.key_wrapper import RSAOAEPKeyWrapper
from crypto.rsa_keypair import private_key_material
from metadata.models import MachineBindingMode
from metadata.protection import MetadataProtector, derive_protection_keys_from_key_material
from usb.device_detector import USBDevice
from usb.exceptions import ContainerOverwriteError, ContainerVerificationError
from usb.secure_storage_service import SecureStorageService
from validation.usb_identifier import HardwareDescriptor


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


# -- Device binding modes (Phase 1) ------------------------------------------


def _stored_device_binding(result, service):
    container = service._storage_writer.read_container(result.destination)
    protector = MetadataProtector(result.protection_keys)
    metadata = protector.unprotect(container.protected_metadata)
    return metadata.device_binding


def test_default_binding_mode_is_portable_and_unbound(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1")

    binding = _stored_device_binding(result, service)
    assert binding.bound is False
    assert binding.usb_serial is None
    assert binding.machine_fingerprint is None


# -- Rich hardware descriptor: vendor/product/serial (Phase 2) --------------


def test_bound_write_populates_hardware_descriptor_fields(tmp_path, wrapper, monkeypatch):
    monkeypatch.setattr(
        "usb.secure_storage_service.compute_hardware_descriptor",
        lambda device: HardwareDescriptor(
            vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="4C530001A2B3C4D5"
        ),
    )
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1", bind_device=True)

    binding = _stored_device_binding(result, service)
    assert binding.vendor_id == "SANDISK"
    assert binding.product_id == "CRUZER_BLADE"
    assert binding.hardware_serial == "4C530001A2B3C4D5"


def test_bound_write_with_unresolvable_hardware_descriptor_leaves_fields_none(tmp_path, wrapper, monkeypatch):
    monkeypatch.setattr("usb.secure_storage_service.compute_hardware_descriptor", lambda device: None)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(
        source, device, wrapper, owner_id="researcher-1", bind_device=True, machine_binding=MachineBindingMode.CURRENT
    )

    binding = _stored_device_binding(result, service)
    assert binding.vendor_id is None
    assert binding.product_id is None
    assert binding.hardware_serial is None


def test_portable_write_never_computes_hardware_descriptor(tmp_path, wrapper, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "usb.secure_storage_service.compute_hardware_descriptor",
        lambda device: calls.append(device) or None,
    )
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    service.store_file(source, device, wrapper, owner_id="researcher-1")

    assert calls == []


def test_device_only_binding_sets_usb_serial_but_not_machine_fingerprint(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1", bind_device=True)

    binding = _stored_device_binding(result, service)
    assert binding.bound is True
    assert binding.usb_serial is not None
    assert binding.machine_fingerprint is None


def test_device_and_machine_binding_sets_both_identifiers(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(
        source, device, wrapper, owner_id="researcher-1", bind_device=True, machine_binding=MachineBindingMode.CURRENT
    )

    binding = _stored_device_binding(result, service)
    assert binding.bound is True
    assert binding.usb_serial is not None
    assert binding.machine_fingerprint is not None


def test_machine_only_binding_sets_machine_fingerprint_but_not_usb_serial():
    """Phase 7: the two axes are independent -- a file can be bound to a
    machine without being bound to any USB device at all."""
    service = SecureStorageService()
    device_binding, _ = service._device_binding_and_wrapper(
        key_wrapper=None, device=None, bind_device=False, machine_binding=MachineBindingMode.CURRENT
    )

    assert device_binding.bound is False
    assert device_binding.usb_serial is None
    assert device_binding.machine_fingerprint is not None


def test_specific_machine_binding_uses_the_supplied_fingerprint(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(
        source,
        device,
        wrapper,
        owner_id="researcher-1",
        bind_device=True,
        machine_binding=MachineBindingMode.SPECIFIC,
        target_machine_fingerprint="pre-enrolled-fingerprint",
    )

    binding = _stored_device_binding(result, service)
    assert binding.machine_fingerprint == "pre-enrolled-fingerprint"


def test_specific_machine_binding_without_a_fingerprint_raises(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    with pytest.raises(ValueError):
        service.store_file(
            source, device, wrapper, owner_id="researcher-1", machine_binding=MachineBindingMode.SPECIFIC
        )


def test_portable_binding_explicitly_matches_default(tmp_path, wrapper):
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(
        source, device, wrapper, owner_id="researcher-1", bind_device=False, machine_binding=MachineBindingMode.NONE
    )

    binding = _stored_device_binding(result, service)
    assert binding.bound is False
    assert binding.usb_serial is None
    assert binding.machine_fingerprint is None


# -- Cryptographic USB binding via HKDF (Phase 3) ----------------------------


def _mock_device_identity(monkeypatch, usb_serial: str, descriptor: HardwareDescriptor) -> None:
    monkeypatch.setattr("usb.secure_storage_service.compute_usb_identifier", lambda device: usb_serial)
    monkeypatch.setattr("usb.secure_storage_service.compute_hardware_descriptor", lambda device: descriptor)


_DEVICE_A_SERIAL = "SERIAL-A:FAT32:1000000"
_DEVICE_A_DESCRIPTOR = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER_BLADE", hardware_serial="AAA111")
_DEVICE_B_SERIAL = "SERIAL-B:FAT32:1000000"
_DEVICE_B_DESCRIPTOR = HardwareDescriptor(vendor_id="KINGSTON", product_id="DATATRAVELER", hardware_serial="BBB222")


def test_device_only_file_round_trips_when_verified_with_the_same_device(tmp_path, wrapper, monkeypatch):
    _mock_device_identity(monkeypatch, _DEVICE_A_SERIAL, _DEVICE_A_DESCRIPTOR)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1", bind_device=True)

    assert (
        service.verify_stored_file(
            result.destination, wrapper, result.protection_keys, device=device, bind_device=True
        )
        is True
    )


def test_device_only_file_fails_verification_with_a_different_device(tmp_path, wrapper, monkeypatch):
    from usb.exceptions import ContainerVerificationError

    _mock_device_identity(monkeypatch, _DEVICE_A_SERIAL, _DEVICE_A_DESCRIPTOR)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1", bind_device=True)

    _mock_device_identity(monkeypatch, _DEVICE_B_SERIAL, _DEVICE_B_DESCRIPTOR)
    with pytest.raises(ContainerVerificationError):
        service.verify_stored_file(
            result.destination, wrapper, result.protection_keys, device=device, bind_device=True
        )


def test_device_only_file_genuinely_fails_to_decrypt_with_a_different_device_fingerprint_not_just_validation(
    tmp_path, wrapper, monkeypatch
):
    """The core Phase 3 proof, entirely at the crypto layer: no
    `validation.device_binding_validator`/`ValidationEngine` is used
    anywhere in this test. A DEVICE_ONLY file's wrapped key is
    reconstructed with a different device's fingerprint and shown to
    fail cryptographic unwrapping outright -- not a policy check."""
    from crypto.exceptions import KeyUnwrappingError
    from crypto.key_manager import derive_device_binding_key
    from crypto.key_wrapper import DeviceBoundKeyWrapper
    from validation.usb_identifier import device_fingerprint_material

    _mock_device_identity(monkeypatch, _DEVICE_A_SERIAL, _DEVICE_A_DESCRIPTOR)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"top secret contents")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1", bind_device=True)
    container = service._storage_writer.read_container(result.destination)

    # The correct device unwraps fine.
    correct_key = derive_device_binding_key(device_fingerprint_material(_DEVICE_A_SERIAL, _DEVICE_A_DESCRIPTOR))
    assert DeviceBoundKeyWrapper(wrapper, correct_key).unwrap(container.file_container.wrapped_key) is not None

    # A different device's fingerprint derives a different key and fails
    # to unwrap -- a real cryptographic failure, not a validation denial.
    wrong_key = derive_device_binding_key(device_fingerprint_material(_DEVICE_B_SERIAL, _DEVICE_B_DESCRIPTOR))
    with pytest.raises(KeyUnwrappingError):
        DeviceBoundKeyWrapper(wrapper, wrong_key).unwrap(container.file_container.wrapped_key)


def test_device_only_wrapped_key_is_not_unwrappable_by_the_plain_inner_wrapper_alone(tmp_path, wrapper, monkeypatch):
    """Proves the outer device-bound layer is actually present: even the
    correct RSA private key alone (no device-bound unwrap) can't unwrap
    a DEVICE_ONLY file's stored wrapped key."""
    from crypto.exceptions import KeyUnwrappingError

    _mock_device_identity(monkeypatch, _DEVICE_A_SERIAL, _DEVICE_A_DESCRIPTOR)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(source, device, wrapper, owner_id="researcher-1", bind_device=True)
    container = service._storage_writer.read_container(result.destination)

    with pytest.raises(KeyUnwrappingError):
        wrapper.unwrap(container.file_container.wrapped_key)


@pytest.mark.parametrize(
    "bind_device,machine_binding",
    [
        (True, MachineBindingMode.CURRENT),
        (False, MachineBindingMode.CURRENT),
        (False, MachineBindingMode.NONE),
    ],
)
def test_non_device_only_combinations_are_never_cryptographically_device_bound(
    tmp_path, wrapper, monkeypatch, bind_device, machine_binding
):
    """Any machine binding, or no device binding at all, must be entirely
    unaffected by Phase 3 -- the plain (inner) wrapper alone must unwrap
    the stored key directly, with no outer device-bound layer at all."""
    _mock_device_identity(monkeypatch, _DEVICE_A_SERIAL, _DEVICE_A_DESCRIPTOR)
    source = tmp_path / "secret.txt"
    source.write_bytes(b"content")
    device = _device(str(_usb_dir(tmp_path)))

    service = SecureStorageService()
    result = service.store_file(
        source, device, wrapper, owner_id="researcher-1", bind_device=bind_device, machine_binding=machine_binding
    )
    container = service._storage_writer.read_container(result.destination)

    # No outer layer to strip -- unwraps directly, and matches the plain
    # RSA-OAEP algorithm name (no "+DEVICE-BOUND-AES-GCM" suffix).
    assert container.file_container.wrap_algorithm == "RSA-OAEP"
    assert wrapper.unwrap(container.file_container.wrapped_key) is not None
