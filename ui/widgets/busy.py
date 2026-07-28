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

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

_SPINNER_DIAMETER = 36
_SPINNER_STEP_DEGREES = 8
_SPINNER_INTERVAL_MS = 20
_SPINNER_ARC_SPAN_DEGREES = 100
_SPINNER_ACCENT = QColor("#00b8d4")
_SPINNER_TRACK = QColor(128, 140, 148, 90)


class _SpinnerWidget(QWidget):
    """A small, continuously rotating arc, self-painted so a single
    indeterminate-progress cue doesn't need an external GIF/PNG asset."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(_SPINNER_DIAMETER, _SPINNER_DIAMETER)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(_SPINNER_INTERVAL_MS)
        self._timer.timeout.connect(self._advance)

    def start(self) -> None:
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def _advance(self) -> None:
        self._angle = (self._angle + _SPINNER_STEP_DEGREES) % 360
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ARG002 -- Qt event-handler signature
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(4, 4, self.width() - 8, self.height() - 8)

        track_pen = QPen(_SPINNER_TRACK, 3.5)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawEllipse(rect)

        arc_pen = QPen(_SPINNER_ACCENT, 3.5)
        arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc_pen)
        # Qt angles are in 1/16ths of a degree, measured counterclockwise
        # from the 3 o'clock position.
        painter.drawArc(rect, -self._angle * 16, -_SPINNER_ARC_SPAN_DEGREES * 16)
        painter.end()


class _BusyDialog(QDialog):
    """The modal "please wait" box `progress_dialog` shows: a spinner next
    to a message, styled to match whatever app theme is currently active
    rather than falling back to an unstyled native dialog background."""

    def __init__(self, parent: Optional[QWidget], message: str) -> None:
        super().__init__(parent)
        self.setWindowTitle("Please Wait")
        self.setWindowModality(Qt.WindowModality.WindowModal)
        # No close ("X") button: this box reflects a synchronous operation
        # already under way by the time it's shown, so there is nothing a
        # close action could actually cancel (see the module docstring).
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint)
        self.setFixedSize(380, 104)

        # Native (Windows-vista-style) top-level dialogs ignore the
        # app-wide QSS `background-color` for their own backdrop even
        # though it applies fine to every *child* widget -- setting the
        # exact same stylesheet directly on this instance forces Qt's
        # styled paint path for this dialog too, so it always matches
        # whichever theme (dark/light) is currently active.
        app = QApplication.instance()
        if app is not None:
            self.setStyleSheet(app.styleSheet())

        self._spinner = _SpinnerWidget(self)

        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_label.setStyleSheet("font-weight: 600;")

        hint_label = QLabel("Please do not remove the device or close the application.")
        hint_label.setWordWrap(True)
        hint_label.setObjectName("pageSubtitle")

        text_layout = QVBoxLayout()
        text_layout.setSpacing(4)
        text_layout.addWidget(message_label)
        text_layout.addWidget(hint_label)
        text_layout.addStretch(1)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(18)
        layout.addWidget(self._spinner)
        layout.addLayout(text_layout, 1)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._spinner.start()

    def closeEvent(self, event) -> None:
        self._spinner.stop()
        super().closeEvent(event)


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
def progress_dialog(parent: Optional[QWidget], message: str) -> Iterator[QDialog]:
    """Show a non-cancellable modal "please wait" box with `message` and a
    spinner for the duration of the `with` block. There is no determinate
    progress to report (a single synchronous cryptographic call, not a
    multi-step or chunked operation), so this is a busy indicator, not a
    percentage — and it is not cancel-able, since half-finished
    writes/decrypts are exactly what the atomic-write and RAM-only
    designs elsewhere exist to avoid.
    """
    dialog = _BusyDialog(parent, message)
    dialog.show()
    # `processEvents()` alone only guarantees the *request* to paint is
    # queued -- on Windows the window can still be blocking-call-frozen
    # (see `_disable_windows_ghosting`) before that queued paint ever
    # actually reaches the screen, leaving the last real frame blank.
    # `repaint()` forces the paint to happen synchronously, right now, so
    # the dialog has genuinely drawn its spinner/message at least once
    # before the caller's blocking cryptographic/USB-I/O call begins.
    for _ in range(3):
        QApplication.processEvents()
    dialog.repaint()
    QApplication.processEvents()
    try:
        yield dialog
    finally:
        dialog.close()


def show_result_popup(parent: Optional[QWidget], message: str, ok: bool = True) -> None:
    """Surface a deliberate action's pass/fail result as a modal popup, in
    addition to whatever inline status label already shows it — a page
    taller than the visible window can scroll that label out of view,
    silently hiding the result. Only for outcomes of a deliberate action
    (a write, an export, a verification); routine/informational status
    text should stay inline-only, not call this for every update.
    """
    if ok:
        QMessageBox.information(parent, "Success", message)
    else:
        QMessageBox.warning(parent, "Error", message)


def show_info_popup(parent: Optional[QWidget], message: str) -> None:
    """Surface a neutral popup that carries no pass/fail framing.

    Used where a "Success"/"Error" title would itself be a signal an
    attacker could read (e.g. loading a private key: a wrong key or
    passphrase must produce a popup indistinguishable from a correct
    one — see `ui.pages.decryption_page.DecryptionPage._on_load_key_clicked`).
    """
    QMessageBox.information(parent, "Notice", message)
