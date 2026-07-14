"""Lightweight "this will take a moment" feedback for the handful of
synchronous operations slow enough for a user to notice: RSA-4096
keypair generation, and encrypting/writing or validating/decrypting a
file.

This application has no background-thread/worker-queue architecture
(that would be a change to the approved research architecture, not a
demonstration-readiness polish), so these operations still block the
Qt event loop for their duration — typically well under a second, but
enough to make an unresponsive-looking cursor confusing during a live
demo. `busy_cursor` swaps in a wait cursor and forces a repaint before
the blocking call runs, so the user sees immediate feedback that
something is happening, and the normal cursor is always restored
afterward (even if the operation raises). `progress_dialog` is the
heavier-weight counterpart for the two operations worth a labeled,
modal "what's happening" box — writing a secure container and
validating/decrypting one — rather than just a cursor change.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QProgressDialog, QWidget


@contextmanager
def busy_cursor() -> Iterator[None]:
    """Show a wait cursor for the duration of the `with` block."""
    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    QApplication.processEvents()
    try:
        yield
    finally:
        QApplication.restoreOverrideCursor()


@contextmanager
def progress_dialog(parent: Optional[QWidget], message: str) -> Iterator[QProgressDialog]:
    """Show an indeterminate, non-cancellable modal progress dialog with
    `message` for the duration of the `with` block. There is no
    determinate progress to report (a single synchronous cryptographic
    call, not a multi-step or chunked operation), so this is a busy
    indicator with a label, not a percentage — and it is not
    cancel-able, since half-finished writes/decrypts are exactly what
    the atomic-write and RAM-only designs elsewhere exist to avoid.
    """
    dialog = QProgressDialog(message, None, 0, 0, parent)
    dialog.setWindowTitle("Please Wait")
    dialog.setWindowModality(Qt.WindowModality.WindowModal)
    dialog.setMinimumDuration(0)
    dialog.setCancelButton(None)
    dialog.show()
    QApplication.processEvents()
    try:
        yield dialog
    finally:
        dialog.close()
