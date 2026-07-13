"""Secure in-memory decryption: RAM only, never touches disk.

`SecureDecryptor` is the only place a caller unwraps a File Encryption
Key and decrypts a file's ciphertext for viewing. Both the unwrapped
FEK (via `crypto.key_manager.ManagedKey`, already destroyed by
`FileEncryptor.decrypt_bytes`) and the decrypted plaintext (held in a
`SecureBytes` buffer here) are destroyed as soon as the caller's `with`
block exits.

Nothing in this module accepts or produces a filesystem path — unlike
`FileEncryptor.decrypt_file`, which exists for other, disk-based flows —
so there is no code path by which decrypted content could land on
disk, a USB device, a temp folder, a cache, or anywhere under the user
profile. As with `SecureBytes` itself, this closes the most direct
window (an explicit, immediate zero-and-discard) rather than claiming
Python can guarantee memory is unrecoverable.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from core.logger import get_logger
from crypto.file_encryptor import EncryptedContainer, FileEncryptor
from crypto.key_manager import KeyManager
from crypto.key_wrapper import KeyWrapper
from crypto.secure_bytes import SecureBytes

logger = get_logger(__name__)


class SecureDecryptor:
    """Decrypts an `EncryptedContainer` entirely in memory."""

    def __init__(
        self,
        file_encryptor: Optional[FileEncryptor] = None,
        key_manager: Optional[KeyManager] = None,
    ) -> None:
        self._key_manager = key_manager or KeyManager()
        self._file_encryptor = file_encryptor or FileEncryptor(self._key_manager)

    @contextmanager
    def open_decrypted(
        self, container: EncryptedContainer, wrapper: KeyWrapper
    ) -> Iterator[SecureBytes]:
        """Decrypt `container` and yield a `SecureBytes` buffer of the plaintext.

        Unwraps the FEK and decrypts with it exactly as `FileEncryptor`
        does (which already destroys the FEK before returning), then
        copies the resulting plaintext into a `SecureBytes` buffer.

        The buffer is destroyed unconditionally when the `with` block
        exits, whether it exits normally or via an exception — the
        caller never has to remember to clean up, and the plaintext is
        never valid to read once the block ends.
        """
        plaintext = self._file_encryptor.decrypt_bytes(container, wrapper)
        buffer = SecureBytes(plaintext)
        logger.info("Decrypted %d byte(s) into a RAM-only secure buffer", len(buffer))
        try:
            yield buffer
        finally:
            buffer.destroy()
            logger.info("RAM-only secure buffer destroyed")
