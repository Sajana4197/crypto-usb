"""Tests for `DeviceRebindService.rebind` — Phase 6's explicit device
re-binding workflow, extended for Phase 7's independent device/machine
binding axes."""

import sqlite3

import pytest

from crypto import rsa_keypair
from crypto.exceptions import CryptoError, KeyUnwrappingError
from crypto.file_encryptor import FileEncryptor
from crypto.key_manager import derive_device_binding_key
from crypto.key_wrapper import DeviceBoundKeyWrapper, RSAOAEPKeyWrapper
from metadata.controller import MetadataController
from metadata.device_rebind import DeviceRebindService
from metadata.hashing import compute_integrity_hash
from metadata.models import DeviceBinding
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from usb.device_detector import USBDevice
from validation.device_binding_validator import DeviceBindingValidator
from validation.usb_identifier import HardwareDescriptor, compute_usb_identifier, device_fingerprint_material

PLAINTEXT = b"the confidential research findings"
PASSPHRASE = b"correct-horse-battery-staple"


@pytest.fixture
def keypair_pem():
    keypair = rsa_keypair.generate_rsa_keypair()
    pem = rsa_keypair.serialize_private_key(keypair.private_key, PASSPHRASE)
    return keypair, pem


@pytest.fixture
def wrapper(keypair_pem):
    keypair, _ = keypair_pem
    return RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return MetadataRepository(connection)


@pytest.fixture
def session_keys():
    return generate_protection_keys()


@pytest.fixture
def controller(repository, session_keys):
    return MetadataController(repository, MetadataProtector(session_keys))


@pytest.fixture
def service(repository):
    return DeviceRebindService(repository)


def _device(mount_point, label="OLDUSB"):
    return USBDevice(
        device_id=mount_point,
        mount_point=mount_point,
        label=label,
        filesystem="FAT32",
        total_bytes=1_000_000,
        free_bytes=500_000,
        is_removable=True,
    )


OLD_DEVICE = _device("E:\\", label="OLDUSB")
NEW_DEVICE = _device("F:\\", label="NEWUSB")


def _device_and_machine_metadata(controller, wrapper, machine_fingerprint="machine-a"):
    container = FileEncryptor().encrypt_bytes(PLAINTEXT, wrapper)
    integrity_hash = compute_integrity_hash(container.serialize())
    return controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
        device_binding=DeviceBinding(
            device_id=OLD_DEVICE.device_id,
            label=OLD_DEVICE.label,
            bound=True,
            usb_serial=compute_usb_identifier(OLD_DEVICE, volume_serial_fn=lambda mp: 0xAAAA),
            machine_fingerprint=machine_fingerprint,
        ),
    )


def _device_only_metadata(controller, wrapper, old_device_key):
    device_bound_wrapper = DeviceBoundKeyWrapper(wrapper, old_device_key)
    container = FileEncryptor().encrypt_bytes(PLAINTEXT, device_bound_wrapper)
    integrity_hash = compute_integrity_hash(container.serialize())
    old_usb_serial = compute_usb_identifier(OLD_DEVICE, volume_serial_fn=lambda mp: 0xAAAA)
    return controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
        device_binding=DeviceBinding(
            device_id=OLD_DEVICE.device_id,
            label=OLD_DEVICE.label,
            bound=True,
            usb_serial=old_usb_serial,
        ),
    )


# -- Machine-bound (any MachineBindingMode != NONE): pure metadata rebind,
# no crypto re-wrap needed; machine_fingerprint carries forward unchanged --


def test_rebind_updates_device_binding_to_the_new_device(controller, service, wrapper, keypair_pem, monkeypatch):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper)
    monkeypatch.setattr(
        "metadata.device_rebind.compute_hardware_descriptor",
        lambda device: HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="NEW111")
        if device is NEW_DEVICE
        else None,
    )

    service.rebind(metadata, pem, PASSPHRASE, generate_protection_keys(), new_device=NEW_DEVICE)

    assert metadata.device_binding.device_id == NEW_DEVICE.device_id
    assert metadata.device_binding.label == NEW_DEVICE.label
    assert metadata.device_binding.bound is True
    # Machine binding is untouched by a rebind -- only the device moves.
    assert metadata.device_binding.machine_fingerprint == "machine-a"
    assert metadata.device_binding.vendor_id == "SANDISK"
    assert metadata.device_binding.hardware_serial == "NEW111"


def test_rebind_persists_the_updated_binding_to_the_repository(controller, repository, service, wrapper, keypair_pem):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper)
    keys = generate_protection_keys()
    # Re-protect under `keys` first so the repository copy actually uses
    # them (the metadata was created under `session_keys`, a separate
    # fixture) -- mirrors how a real caller would already hold whatever
    # protection_keys apply to this session.
    repository.save(MetadataProtector(keys).protect(metadata))

    service.rebind(metadata, pem, PASSPHRASE, keys, new_device=NEW_DEVICE)

    stored = repository.load("file-1")
    reopened = MetadataProtector(keys).unprotect(stored)
    assert reopened.device_binding.device_id == NEW_DEVICE.device_id
    assert reopened.device_binding.bound is True


def test_rebound_file_validates_against_the_new_device(controller, service, wrapper, keypair_pem, monkeypatch):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper, machine_fingerprint="machine-a")
    new_usb_serial = "NEW-SERIAL:FAT32:2000000"
    monkeypatch.setattr("metadata.device_rebind.compute_usb_identifier", lambda device: new_usb_serial)
    monkeypatch.setattr("metadata.device_rebind.compute_hardware_descriptor", lambda device: None)

    service.rebind(metadata, pem, PASSPHRASE, generate_protection_keys(), new_device=NEW_DEVICE)

    assert metadata.device_binding.usb_serial == new_usb_serial
    result = DeviceBindingValidator().validate(metadata.device_binding, NEW_DEVICE, new_usb_serial, "machine-a")
    assert result.ok is True


def test_rebound_file_no_longer_matches_the_old_device(controller, service, wrapper, keypair_pem, monkeypatch):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper, machine_fingerprint="machine-a")
    old_usb_serial = metadata.device_binding.usb_serial
    monkeypatch.setattr("metadata.device_rebind.compute_hardware_descriptor", lambda device: None)

    service.rebind(metadata, pem, PASSPHRASE, generate_protection_keys(), new_device=NEW_DEVICE)

    result = DeviceBindingValidator().validate(metadata.device_binding, OLD_DEVICE, old_usb_serial, "machine-a")
    assert result.ok is False


# -- Wrong passphrase: must not silently succeed -----------------------------


def test_wrong_passphrase_raises_and_does_not_mutate_binding(controller, service, wrapper, keypair_pem):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper)
    original_binding = metadata.device_binding
    original_wrapped_key = metadata.wrapped_key

    with pytest.raises(CryptoError):
        service.rebind(
            metadata,
            pem,
            b"definitely-the-wrong-passphrase",
            generate_protection_keys(),
            new_device=NEW_DEVICE,
        )

    assert metadata.device_binding == original_binding
    assert metadata.wrapped_key == original_wrapped_key


def test_wrong_passphrase_does_not_persist_anything(controller, repository, service, wrapper, keypair_pem):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper)
    keys = generate_protection_keys()
    repository.save(MetadataProtector(keys).protect(metadata))
    original_stored = repository.load("file-1")

    with pytest.raises(CryptoError):
        service.rebind(metadata, pem, b"wrong-passphrase", keys, new_device=NEW_DEVICE)

    still_stored = repository.load("file-1")
    assert still_stored.hmac_tag == original_stored.hmac_tag
    assert still_stored.ciphertext == original_stored.ciphertext


# -- No machine binding (cryptographic device binding): requires the
# matching old device to unwrap --------------------------------------------


def test_device_only_rebind_succeeds_with_the_matching_old_device(controller, service, wrapper, keypair_pem, monkeypatch):
    _, pem = keypair_pem
    old_descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="OLD111")
    old_usb_serial = "OLD-SERIAL:FAT32:1000000"
    old_key = derive_device_binding_key(device_fingerprint_material(old_usb_serial, old_descriptor))
    metadata = _device_only_metadata(controller, wrapper, old_key)

    new_descriptor = HardwareDescriptor(vendor_id="KINGSTON", product_id="DATATRAVELER", hardware_serial="NEW222")
    new_usb_serial = "NEW-SERIAL:FAT32:2000000"

    monkeypatch.setattr(
        "metadata.device_rebind.compute_usb_identifier",
        lambda device: old_usb_serial if device is OLD_DEVICE else new_usb_serial,
    )
    monkeypatch.setattr(
        "metadata.device_rebind.compute_hardware_descriptor",
        lambda device: old_descriptor if device is OLD_DEVICE else new_descriptor,
    )

    service.rebind(
        metadata,
        pem,
        PASSPHRASE,
        generate_protection_keys(),
        new_device=NEW_DEVICE,
        old_device=OLD_DEVICE,
    )

    assert metadata.device_binding.usb_serial == new_usb_serial
    assert metadata.device_binding.vendor_id == "KINGSTON"
    assert metadata.device_binding.machine_fingerprint is None  # stays unbound to any machine

    # The re-wrapped key genuinely unwraps under the NEW device's key, not the old one.
    new_key = derive_device_binding_key(device_fingerprint_material(new_usb_serial, new_descriptor))
    fek = DeviceBoundKeyWrapper(wrapper, new_key).unwrap(metadata.wrapped_key)
    assert fek is not None
    with pytest.raises(KeyUnwrappingError):
        DeviceBoundKeyWrapper(wrapper, old_key).unwrap(metadata.wrapped_key)


def test_device_only_rebind_fails_with_a_non_matching_old_device(controller, service, wrapper, keypair_pem, monkeypatch):
    _, pem = keypair_pem
    old_descriptor = HardwareDescriptor(vendor_id="SANDISK", product_id="CRUZER", hardware_serial="OLD111")
    old_key = derive_device_binding_key(device_fingerprint_material("OLD-SERIAL:FAT32:1000000", old_descriptor))
    metadata = _device_only_metadata(controller, wrapper, old_key)
    original_wrapped_key = metadata.wrapped_key

    monkeypatch.setattr("metadata.device_rebind.compute_usb_identifier", lambda device: "WRONG-SERIAL:FAT32:9999999")
    monkeypatch.setattr("metadata.device_rebind.compute_hardware_descriptor", lambda device: None)

    with pytest.raises(KeyUnwrappingError):
        service.rebind(
            metadata,
            pem,
            PASSPHRASE,
            generate_protection_keys(),
            new_device=NEW_DEVICE,
            old_device=OLD_DEVICE,  # wrong -- doesn't match the recorded fingerprint
        )

    assert metadata.wrapped_key == original_wrapped_key


def test_device_only_rebind_without_old_device_raises(controller, service, wrapper, keypair_pem):
    _, pem = keypair_pem
    old_key = derive_device_binding_key(device_fingerprint_material("OLD-SERIAL", HardwareDescriptor()))
    metadata = _device_only_metadata(controller, wrapper, old_key)

    with pytest.raises(ValueError):
        service.rebind(metadata, pem, PASSPHRASE, generate_protection_keys(), new_device=NEW_DEVICE)


# -- Portable / unbound: nothing to rebind -----------------------------------


def test_rebind_refuses_an_unbound_file(controller, service, wrapper, keypair_pem):
    _, pem = keypair_pem
    container = FileEncryptor().encrypt_bytes(PLAINTEXT, wrapper)
    integrity_hash = compute_integrity_hash(container.serialize())
    metadata = controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
    )

    with pytest.raises(ValueError):
        service.rebind(metadata, pem, PASSPHRASE, generate_protection_keys(), new_device=NEW_DEVICE)


# -- Mirror repositories -----------------------------------------------------


@pytest.fixture
def mirror_connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def mirror_repository(mirror_connection):
    return MetadataRepository(mirror_connection)


def test_rebind_mirrors_the_updated_record(controller, repository, mirror_repository, wrapper, keypair_pem, monkeypatch):
    _, pem = keypair_pem
    metadata = _device_and_machine_metadata(controller, wrapper)
    keys = generate_protection_keys()
    repository.save(MetadataProtector(keys).protect(metadata))
    mirror_repository.save(MetadataProtector(keys).protect(metadata))
    monkeypatch.setattr("metadata.device_rebind.compute_hardware_descriptor", lambda device: None)
    service = DeviceRebindService(repository, mirror_repositories=[mirror_repository])

    service.rebind(metadata, pem, PASSPHRASE, keys, new_device=NEW_DEVICE)

    primary_stored = repository.load("file-1")
    mirror_stored = mirror_repository.load("file-1")
    assert mirror_stored.ciphertext == primary_stored.ciphertext
    assert mirror_stored.hmac_tag == primary_stored.hmac_tag
    reopened = MetadataProtector(keys).unprotect(mirror_stored)
    assert reopened.device_binding.device_id == NEW_DEVICE.device_id
