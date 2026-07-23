"""One-Time Access Enforcement: crypto-shredding a file the instant its
single permitted viewing ends.

`usb.secure_access_service.SecureAccessService` calls
`OneTimeAccessEnforcer.burn` immediately after a successful decrypt for
any file whose `usage_policy.one_time_access` is set. Enforcement is
cryptographic, not just a policy flag: the metadata's `wrapped_key` is
replaced with a freshly generated, unrelated key wrapped under the same
`KeyWrapper` — structurally identical to a real record, but unable to
ever decrypt the file's actual ciphertext again, since AES-GCM
authentication fails deterministically against the wrong key.

Burning alone never touches the file's ciphertext — deliberately.
Nothing needs to be deleted for the file to become permanently
unreadable, and `access_count` is reset to 0 rather than incremented,
so a party who only ever sees the metadata record cannot tell a
burned file from one that was never accessed. That indistinguishability
is what lets `usb.secure_access_service` route every future decrypt
failure against a still-present burned file to the Deception Engine on
the same footing as any other failure — neither the metadata nor the
failure mode gives away *why* access was refused. `SecureAccessService`
can optionally delete the container after burning it too (see its
`container_path` parameter) — that deletion is layered on top of, and
entirely separate from, what this module does; burning by itself never
deletes anything.

The AES File Encryption Key used to decrypt the file during this
viewing session is not destroyed here — it already is, unconditionally,
by `crypto.secure_decryptor.SecureDecryptor.open_decrypted`'s context
manager, which every caller of this module is expected to have used to
view the file in the first place.
"""

from __future__ import annotations

from typing import Optional, Sequence

from core.logger import get_logger
from crypto.key_manager import KeyManager
from crypto.key_wrapper import KeyWrapper
from crypto.secure_bytes import SecureBytes
from metadata.models import FileMetadata
from metadata.protection import MetadataProtectionKeys, MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository

logger = get_logger(__name__)


class OneTimeAccessEnforcer:
    """Burns a one-time-access file's key material immediately after viewing."""

    def __init__(
        self,
        repository: MetadataRepository,
        key_manager: Optional[KeyManager] = None,
        mirror_repositories: Sequence[MetadataRepository] = (),
    ) -> None:
        """`mirror_repositories` are any other stores holding their own
        protected copy of the same file's metadata (e.g. a file's local
        SQLite record when the just-validated copy came from its
        USB-resident portable-metadata section instead, or vice versa — see
        `ui.pages.decryption_page._on_view_clicked`). Without this, a
        one-time-access burn made through one copy would leave any other
        copy looking untouched (`access_count` still 0, the real
        `wrapped_key` still intact), letting the file be legitimately
        decrypted again through whichever copy wasn't burned. `burn`
        writes the identical post-burn record to every mirror, so all
        copies become equally, permanently unreadable no matter which
        one a future caller happens to validate against.
        """
        self._repository = repository
        self._key_manager = key_manager or KeyManager()
        self._mirror_repositories = tuple(mirror_repositories)

    def burn(
        self,
        metadata: FileMetadata,
        key_wrapper: KeyWrapper,
        session_keys: MetadataProtectionKeys,
    ) -> MetadataProtectionKeys:
        """Consume `metadata`'s one-time access.

        Mutates `metadata` in place (`access_count` reset to 0,
        `wrapped_key` replaced with a decoy) and returns the fresh
        `MetadataProtectionKeys` that must be used for any future
        legitimate read of this metadata record — `session_keys` (this
        session's now-destroyed metadata key, the "Session Key") no
        longer works, and is wiped as part of this call ("Securely wipe
        memory" / "Destroy Session Key").

        Raises `ValueError` if `metadata` is not marked for one-time
        access — burning a reusable file would be a caller bug, not a
        normal outcome to silently ignore.
        """
        if not metadata.usage_policy.one_time_access:
            raise ValueError(
                f"file_id={metadata.file_id} is not marked for one-time access; refusing to burn it"
            )

        # Decoy key: same wrap algorithm and shape as a real wrapped FEK,
        # generated and destroyed here, never the key that encrypted this
        # file's actual content.
        decoy_fek = self._key_manager.generate_fek()
        try:
            metadata.wrapped_key = self._key_manager.wrap_key(decoy_fek, key_wrapper)
        finally:
            decoy_fek.destroy()

        metadata.access_count = 0

        new_keys = generate_protection_keys()
        SecureBytes(session_keys.encryption_key).destroy()
        SecureBytes(session_keys.hmac_key).destroy()

        protected = MetadataProtector(new_keys).protect(metadata)
        self._repository.save(protected)
        for mirror in self._mirror_repositories:
            mirror.save(protected)

        logger.warning(
            "One-time access consumed for file_id=%s; the file can no longer be legitimately decrypted",
            metadata.file_id,
        )
        return new_keys
