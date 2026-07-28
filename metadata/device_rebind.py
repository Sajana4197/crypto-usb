"""Explicit device re-binding: deliberately moving a device-bound file's
authorization to a newly presented USB device (e.g. the originally
enrolled stick died or was replaced).

This is a separate, explicitly invoked action — never an automatic
fallback. The normal read path (`usb.secure_access_service
.SecureAccessService.attempt_access`) is completely unmodified by this
module: a device mismatch during an ordinary view attempt still fails
`validation.device_binding_validator`'s policy check and still activates
`deception.DeceptionEngine` exactly as before. `DeviceRebindService.rebind`
is only ever reached when the authenticated user explicitly requests it
(see `ui.pages.decryption_page.DecryptionPage`'s "Rebind to Selected
Device" action).

Re-authentication ("requires re-entering the private-key passphrase")
is not a side check bolted on afterward — it *is* how this module
obtains a usable `KeyWrapper` at all: `rebind` loads the private key
itself from `private_key_pem` + `passphrase` and raises
`crypto.exceptions.CryptoError` if that fails, exactly like any other
wrong-passphrase key load. Unlike loading a key to *view* a file (see
`ui.pages.decryption_page.DecryptionPage._on_load_key_clicked`'s
Deceptive Protection Mechanism — a wrong passphrase there silently
loads a decoy key instead of failing), a rebind is a deliberate
re-confirmation of an already-authenticated session, the same category
as `security.auth_controller.AuthController.change_password`/
`delete_account` — so a wrong passphrase here is reported honestly
(the caller sees the raised error), not deceptively.

Whether "whatever the binding depends on" includes the cryptographic
layer Phase 3 added (`crypto.key_wrapper.DeviceBoundKeyWrapper`) is read
straight off `metadata.device_binding` itself — `bound=True` with no
`machine_fingerprint` recorded (`metadata.models.MachineBindingMode.NONE`,
mirroring the exact same detection `usb.secure_storage_service`/
`usb.secure_access_service` already use) rather than a separately passed
mode, so this can never drift from what the file was actually written
with. For such a file, the currently stored `wrapped_key` can only be
unwrapped with a key derived from the *presently enrolled* device's own
fingerprint. `old_device` supplies that — genuinely, physically
presented and freshly probed, never read back from the metadata record
itself (which would let anyone holding just the private key and
protection keys rebind the file to any device of their choosing,
without ever proving they possess the enrolled hardware — exactly the
bypass Phase 3 exists to prevent). If the enrolled device is truly gone,
this correctly fails: such a file's content is unrecoverable without it,
by design, and no rebind feature should be able to circumvent that. A
file with any machine binding has no such cryptographic dependency
(Phase 3 only ever applies with no machine binding at all), so rebinding
one is a pure metadata update — `old_device` is unused for it. Either
way, `machine_fingerprint` is carried forward unchanged into the
rebound record — a rebind moves the USB device only, never silently
changes which machine(s) the file is also bound to.

Mirrors `metadata.one_time_access.OneTimeAccessEnforcer.burn`'s shape:
mutate `metadata` in place, re-protect it under the same
`MetadataProtectionKeys`, save to the primary repository and every
mirror.
"""

from __future__ import annotations

from typing import Optional, Sequence

from core.logger import get_logger
from crypto import rsa_keypair
from crypto.key_manager import KeyManager, derive_device_binding_key
from crypto.key_wrapper import DeviceBoundKeyWrapper, RSAOAEPKeyWrapper
from metadata.models import DeviceBinding, FileMetadata
from metadata.protection import MetadataProtectionKeys, MetadataProtector
from metadata.repository import MetadataRepository
from usb.device_detector import USBDevice
from validation.usb_identifier import compute_hardware_descriptor, compute_usb_identifier, device_fingerprint_material

logger = get_logger(__name__)


class DeviceRebindService:
    """Moves a bound file's `DeviceBinding` — and, when it has no machine
    binding, its device-bound key wrapping — to a newly presented device."""

    def __init__(
        self,
        repository: MetadataRepository,
        key_manager: Optional[KeyManager] = None,
        mirror_repositories: Sequence[MetadataRepository] = (),
    ) -> None:
        """`mirror_repositories` — see `metadata.one_time_access
        .OneTimeAccessEnforcer` — are any other repositories holding
        their own protected copy of the same file's metadata; the
        rebound record is saved to all of them so none is left looking
        untouched (still pointing at the old device)."""
        self._repository = repository
        self._key_manager = key_manager or KeyManager()
        self._mirror_repositories = tuple(mirror_repositories)

    def rebind(
        self,
        metadata: FileMetadata,
        private_key_pem: bytes,
        passphrase: bytes,
        protection_keys: MetadataProtectionKeys,
        new_device: USBDevice,
        old_device: Optional[USBDevice] = None,
    ) -> None:
        """Rebind `metadata` to `new_device`. Mutates `metadata` in place
        and persists the result; raises instead of ever partially
        succeeding.

        Raises `crypto.exceptions.CryptoError` if `passphrase` does not
        match `private_key_pem` — this is the re-authentication check;
        nothing about `metadata` is touched before it passes.

        Raises `ValueError` if `metadata` isn't bound to any device at
        all (fully portable, or machine-bound only) — there is nothing
        to rebind. Raises `crypto.exceptions.KeyUnwrappingError` if this
        is a no-machine-binding file and `old_device` is missing or its
        fingerprint doesn't actually match what `metadata` is currently
        bound to (see the module docstring for why this is not read from
        the metadata record itself).
        """
        if not metadata.device_binding.bound:
            raise ValueError(f"file_id={metadata.file_id} is not bound to any device; nothing to rebind")

        cryptographically_device_bound = metadata.device_binding.machine_fingerprint is None

        private_key = rsa_keypair.load_private_key(private_key_pem, passphrase)
        key_wrapper = RSAOAEPKeyWrapper(private_key.public_key(), private_key)

        effective_wrapper = key_wrapper
        if cryptographically_device_bound:
            if old_device is None:
                raise ValueError("old_device is required to rebind a device-only-bound file")
            old_key = derive_device_binding_key(
                device_fingerprint_material(compute_usb_identifier(old_device), compute_hardware_descriptor(old_device))
            )
            effective_wrapper = DeviceBoundKeyWrapper(key_wrapper, old_key)

        fek = self._key_manager.unwrap_key(metadata.wrapped_key, effective_wrapper)
        try:
            new_usb_serial = compute_usb_identifier(new_device)
            new_hardware_descriptor = compute_hardware_descriptor(new_device)

            new_wrapper = key_wrapper
            if cryptographically_device_bound:
                new_key = derive_device_binding_key(
                    device_fingerprint_material(new_usb_serial, new_hardware_descriptor)
                )
                new_wrapper = DeviceBoundKeyWrapper(key_wrapper, new_key)

            metadata.wrapped_key = self._key_manager.wrap_key(fek, new_wrapper)
        finally:
            fek.destroy()

        metadata.device_binding = DeviceBinding(
            device_id=new_device.device_id,
            label=new_device.label,
            bound=True,
            usb_serial=new_usb_serial,
            machine_fingerprint=metadata.device_binding.machine_fingerprint,
            vendor_id=new_hardware_descriptor.vendor_id if new_hardware_descriptor else None,
            product_id=new_hardware_descriptor.product_id if new_hardware_descriptor else None,
            hardware_serial=new_hardware_descriptor.hardware_serial if new_hardware_descriptor else None,
        )

        protected = MetadataProtector(protection_keys).protect(metadata)
        self._repository.save(protected)
        for mirror in self._mirror_repositories:
            mirror.save(protected)

        logger.warning(
            "Rebound file_id=%s to device_id=%s (usb_serial=%s)",
            metadata.file_id,
            new_device.device_id,
            new_usb_serial,
        )
