"""The SQLCipher file-encryption key: a random, machine-resident secret,
deliberately independent of any user credential.

This is a separate, outer layer from `security.password_hasher`'s
credential-derived vault key (Phase 21), which wraps the
metadata/tracking protection keys *inside* the database. This key
instead protects the *entire SQLite file at rest* — including the
`accounts` table itself, which the vault key deliberately never
touches, since `security.account_repository.AccountRepository` must be
readable *before* login succeeds in order to check a password against
it in the first place. There is no way to derive a file-level key from
credentials not yet verified without deadlocking login, so this key
cannot reuse or be derived from the vault key either.

Generated once per installation and stored in its own file next to the
database (see `utils.paths.get_vault_key_path`) rather than in the
database itself, for the obvious reason that a key cannot unlock the
same file it lives inside.
"""

from __future__ import annotations

import os

from utils.paths import get_vault_key_path

FILE_KEY_SIZE_BYTES = 32


def load_or_create_file_key() -> bytes:
    """Return this installation's SQLCipher file key, generating and
    persisting it on first use. Restricting this file's permissions to
    the current user is best-effort only: Windows has no reliable
    `chmod`-equivalent enforced at the filesystem level the way POSIX
    does, so this is a deterrent against casual inspection, not a proof
    that no other local account or process can read it.
    """
    path = get_vault_key_path()
    if path.exists():
        return path.read_bytes()

    key = os.urandom(FILE_KEY_SIZE_BYTES)
    path.write_bytes(key)
    return key
