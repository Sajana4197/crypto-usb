"""Interfaces the controlled, RAM-only viewer (a later phase) will implement.

Phase 9 only prepares the contract between decryption and viewing: how
decrypted content reaches a viewer, and how its session guarantees the
content is released from memory when the session ends — regardless of
whether the actual rendering UI closes cleanly, raises, or is never
implemented at all yet. No rendering/UI code lives here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Type

from crypto.exceptions import KeyDestroyedError
from crypto.secure_bytes import SecureBytes


class ViewerBackend(ABC):
    """Renders already-decrypted content to the user.

    Implemented by a later phase (e.g. a PySide6 widget). A conforming
    implementation must never write `content` to disk, a cache, or any
    other persistent location, and must not retain a reference to it
    after `close()`.
    """

    @abstractmethod
    def display(self, content: bytes, content_type: str) -> None:
        """Render `content` (already decrypted, in RAM) for the user."""

    @abstractmethod
    def close(self) -> None:
        """Release any UI-side resources. Must not retain `content`."""


class SecureViewSession:
    """Owns one decrypted `SecureBytes` buffer for the lifetime of a view.

    Typically constructed around the buffer yielded by
    `crypto.secure_decryptor.SecureDecryptor.open_decrypted`. Guarantees
    that buffer is destroyed exactly once — on `close()`, on normal
    `with`-block exit, or when an exception propagates out of the
    `with` block — so a viewer implementation never has to remember to
    clean up decrypted content itself.
    """

    def __init__(
        self,
        buffer: SecureBytes,
        content_type: str,
        backend: Optional[ViewerBackend] = None,
    ) -> None:
        self._buffer = buffer
        self._content_type = content_type
        self._backend = backend
        self._closed = False

    @property
    def content_type(self) -> str:
        return self._content_type

    @property
    def is_closed(self) -> bool:
        return self._closed

    def read(self) -> bytes:
        """Return the decrypted content. Only valid while the session is open."""
        if self._closed:
            raise KeyDestroyedError("Cannot read from a closed SecureViewSession")
        return bytes(self._buffer)

    def display(self) -> None:
        """Hand the decrypted content to the attached viewer backend, if any.

        A no-op when no backend is attached yet — Phase 9 prepares this
        interface before the real viewer backend exists.
        """
        if self._backend is not None:
            self._backend.display(self.read(), self._content_type)

    def close(self) -> None:
        """Destroy the decrypted buffer and close the backend. Idempotent."""
        if self._closed:
            return
        try:
            if self._backend is not None:
                self._backend.close()
        finally:
            self._buffer.destroy()
            self._closed = True

    def __enter__(self) -> "SecureViewSession":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()
