"""Secure Cleanup: the single place that names *when* sensitive
in-memory material is guaranteed to be erased, and gives every call
site that hasn't already wrapped its secrets in `SecureBytes` /
`ManagedKey` the same duck-typed destroy-or-zero handling.

Individual objects already know how to destroy themselves
(`crypto.secure_bytes.SecureBytes.destroy`,
`crypto.key_manager.ManagedKey.destroy`), and several call sites
already invoke that directly (`crypto.secure_decryptor.SecureDecryptor`,
`viewer.secure_viewer_widget.SecureViewerWidget._teardown`,
`metadata.one_time_access.OneTimeAccessEnforcer.burn`). This module
does not replace any of that — it adds:

- `wipe`/`wipe_bytearray` for temporary credential buffers (a
  passphrase or private-key PEM read for one authentication attempt)
  that never get wrapped in `SecureBytes`, so they can still be zeroed
  in place before the reference is dropped.
- `cleanup`, a thin logging wrapper naming which of the four moments
  this application guarantees a cleanup pass — `CleanupReason` — so an
  audit of the logs shows cleanup ran after every successful view,
  every failed authentication, every validation failure, and
  application exit, even on the calls where nothing was left to wipe.

As with `SecureBytes`, this closes the most direct window (an
explicit, immediate overwrite-with-zeros before the last reference is
dropped) rather than claiming Python can guarantee freed memory is
unrecoverable — see `crypto.secure_bytes` for the fuller explanation of
that limitation.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any

from core.logger import get_logger

logger = get_logger(__name__)


class CleanupReason(Enum):
    """The four moments secure cleanup is guaranteed to run."""

    SUCCESSFUL_VIEW = auto()
    FAILED_AUTHENTICATION = auto()
    VALIDATION_FAILURE = auto()
    APPLICATION_EXIT = auto()


def wipe_bytearray(buffer: bytearray) -> None:
    """Overwrite every byte of a mutable buffer with zero, in place."""
    for i in range(len(buffer)):
        buffer[i] = 0


def wipe(obj: Any) -> bool:
    """Best-effort secure erasure of one sensitive object.

    Duck-typed rather than an `isinstance` check against a fixed list
    of classes (the same reasoning `viewer.secure_viewer_widget`
    documents for `ViewerBackend`): anything exposing a no-argument
    `destroy()` — `SecureBytes`, `ManagedKey`, or a future
    sensitive-object type — is destroyed (idempotent: both existing
    `destroy()` implementations are safe to call on an
    already-destroyed object). A `bytearray` — the shape a temporary
    credential buffer takes before/instead of being wrapped in
    `SecureBytes` — is zeroed in place. Anything else (an immutable
    `bytes`/`str`, or `None`) cannot be wiped from Python and is left
    alone; returns False in that case.
    """
    if obj is None:
        return False
    if isinstance(obj, bytearray):
        wipe_bytearray(obj)
        return True
    destroy = getattr(obj, "destroy", None)
    if callable(destroy):
        destroy()
        return True
    return False


def cleanup(reason: CleanupReason, *sensitive: Any) -> int:
    """Wipe every object in `sensitive` and log one summary line naming
    `reason` — never the wiped content itself. Returns the count of
    objects actually wiped.

    Safe to call with nothing sensitive on hand (e.g. a validation
    failure before any key material was ever unwrapped) — this still
    records that a cleanup pass ran for `reason`, which is the point:
    every one of the four guaranteed moments gets a log entry whether
    or not there was anything left to erase.
    """
    wiped_count = sum(1 for obj in sensitive if wipe(obj))
    logger.info("Secure cleanup performed (reason=%s, objects_wiped=%d)", reason.name, wiped_count)
    return wiped_count
