"""Tests for the RAM-only viewer's prepared interfaces."""

import pytest

from crypto.exceptions import KeyDestroyedError
from crypto.secure_bytes import SecureBytes
from viewer.interfaces import SecureViewSession, ViewerBackend

PLAINTEXT = b"decrypted content ready for viewing"


class RecordingViewerBackend(ViewerBackend):
    """A fake `ViewerBackend` that records what it was asked to render."""

    def __init__(self) -> None:
        self.displayed: list[tuple[bytes, str]] = []
        self.closed = False

    def display(self, content: bytes, content_type: str) -> None:
        self.displayed.append((content, content_type))

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def buffer():
    return SecureBytes(PLAINTEXT)


# -- ViewerBackend is a real interface ---------------------------------------


def test_viewer_backend_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ViewerBackend()  # type: ignore[abstract]


# -- Reading content ----------------------------------------------------


def test_read_returns_the_decrypted_content(buffer):
    session = SecureViewSession(buffer, content_type="text/plain")
    assert session.read() == PLAINTEXT
    session.close()


def test_read_after_close_raises(buffer):
    session = SecureViewSession(buffer, content_type="text/plain")
    session.close()

    with pytest.raises(KeyDestroyedError):
        session.read()


# -- Backend wiring -----------------------------------------------------


def test_display_forwards_content_and_type_to_backend(buffer):
    backend = RecordingViewerBackend()
    session = SecureViewSession(buffer, content_type="application/pdf", backend=backend)

    session.display()

    assert backend.displayed == [(PLAINTEXT, "application/pdf")]
    session.close()


def test_display_without_a_backend_is_a_safe_no_op(buffer):
    session = SecureViewSession(buffer, content_type="text/plain", backend=None)
    session.display()  # must not raise
    session.close()


def test_close_closes_the_backend(buffer):
    backend = RecordingViewerBackend()
    session = SecureViewSession(buffer, content_type="text/plain", backend=backend)

    session.close()

    assert backend.closed is True


# -- Buffer lifecycle: destroyed exactly once ----------------------------


def test_close_destroys_the_underlying_buffer(buffer):
    session = SecureViewSession(buffer, content_type="text/plain")
    session.close()

    assert buffer.is_destroyed is True


def test_close_is_idempotent(buffer):
    backend = RecordingViewerBackend()
    session = SecureViewSession(buffer, content_type="text/plain", backend=backend)

    session.close()
    session.close()  # must not raise or double-close the backend

    assert session.is_closed is True


def test_context_manager_closes_on_normal_exit(buffer):
    with SecureViewSession(buffer, content_type="text/plain") as session:
        assert session.read() == PLAINTEXT

    assert buffer.is_destroyed is True


def test_context_manager_closes_on_exception(buffer):
    with pytest.raises(RuntimeError):
        with SecureViewSession(buffer, content_type="text/plain") as session:
            session.read()
            raise RuntimeError("viewer-side failure")

    assert buffer.is_destroyed is True


def test_content_type_is_exposed(buffer):
    session = SecureViewSession(buffer, content_type="image/png")
    assert session.content_type == "image/png"
    session.close()
