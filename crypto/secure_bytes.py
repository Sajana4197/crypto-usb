"""In-memory secure handling of key material.

Python cannot guarantee that freed memory is unrecoverable (garbage
collection timing, copies, swap), but `SecureBytes` closes the most
direct window: the buffer is explicitly overwritten with zeros as
soon as the key is destroyed, rather than left for the garbage
collector. It also refuses to reveal its contents through `repr`/`str`
so key material never lands in a log line or traceback by accident.
"""

from __future__ import annotations

from crypto.exceptions import KeyDestroyedError


class SecureBytes:
    """A byte buffer for key material that can be explicitly zeroed after use."""

    __slots__ = ("_buffer", "_destroyed")

    def __init__(self, data: bytes) -> None:
        self._buffer = bytearray(data)
        self._destroyed = False

    def __enter__(self) -> "SecureBytes":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()

    def __len__(self) -> int:
        return len(self._buffer)

    def __bytes__(self) -> bytes:
        self._check_alive()
        return bytes(self._buffer)

    def __repr__(self) -> str:
        return f"SecureBytes({'destroyed' if self._destroyed else '<redacted>'})"

    __str__ = __repr__

    @property
    def is_destroyed(self) -> bool:
        return self._destroyed

    def _check_alive(self) -> None:
        if self._destroyed:
            raise KeyDestroyedError("Key material has already been destroyed")

    def destroy(self) -> None:
        """Overwrite the buffer with zeros and mark it unusable."""
        if not self._destroyed:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            self._destroyed = True
