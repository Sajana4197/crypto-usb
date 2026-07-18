"""The Secure Controlled Viewer: renders decrypted PDF/image/text content
entirely in memory, with every in-app copy/export/print/edit path
disabled and the strongest reasonably available Windows screen-capture
mitigation applied.

Implements `viewer.interfaces.ViewerBackend`'s method signatures
(`display`/`close`) by duck typing rather than formal inheritance:
PySide6 widget classes use Shiboken's metaclass, which conflicts with
`abc.ABCMeta`, so a `QWidget` subclass cannot literally inherit from
`ViewerBackend` (attempting it raises `TypeError: metaclass conflict`
at class-definition time). `SecureViewSession` never does an
`isinstance` check against `ViewerBackend` — it only calls
`display(...)`/`close()` — so this is a distinction without a runtime
difference.

Scope of protection:
- In-app copy/cut/paste/select/edit/print/save/export/drag-drop/context
  menu are all disabled below, at the Qt level. This closes every path
  *this application* offers for extracting content.
- Screen capture mitigation (`viewer.screen_capture_protection`) is
  best-effort and Windows-version-dependent — see that module's
  docstring for exactly what is and is not covered. Nothing here can
  stop a photograph of the screen, a hardware capture device, or a
  remote viewer on the far end of a screen-sharing session the user is
  legitimately running.
- Qt's own internal, C++-side copies of rendered content (a QImage's
  pixel buffer, a QPdfDocument's parsed representation, a text
  widget's internal document) are not zeroed when the viewer closes —
  Qt provides no API to do that. This is the same limitation
  `crypto.secure_bytes.SecureBytes` documents for Python's own memory:
  the most direct window is closed (every reference is dropped so the
  content becomes unreachable and eligible for normal deallocation),
  not an unrecoverable-memory guarantee.
"""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt, Signal
from PySide6.QtGui import (
    QCloseEvent,
    QContextMenuEvent,
    QDragEnterEvent,
    QDropEvent,
    QImage,
    QKeyEvent,
    QKeySequence,
    QPixmap,
    QShowEvent,
)
from PySide6.QtPdf import QPdfDocument
from PySide6.QtPdfWidgets import QPdfView
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from viewer.screen_capture_protection import (
    CaptureProtectionLevel,
    CaptureProtectionResult,
    PrintScreenWatcher,
    apply_capture_protection,
    remove_capture_protection,
)

logger = get_logger(__name__)

CONTENT_TYPE_TXT = "text/plain"
CONTENT_TYPE_PDF = "application/pdf"
_IMAGE_PREFIX = "image/"

# Zoom step/bounds shared by the PDF and image zoom controls (text zoom is
# governed by QPlainTextEdit's own zoomIn/zoomOut instead).
_ZOOM_STEP = 1.25
_ZOOM_MIN = 0.25
_ZOOM_MAX = 4.0

# Every shortcut this viewer must never act on. `Save`/`SaveAs`/`Print`
# have no button or menu action wired up anywhere in this widget either
# — this interception is defense in depth, not the only thing standing
# between a keypress and one of those actions.
_BLOCKED_KEY_SEQUENCES = (
    QKeySequence.StandardKey.Copy,
    QKeySequence.StandardKey.Cut,
    QKeySequence.StandardKey.Paste,
    QKeySequence.StandardKey.SelectAll,
    QKeySequence.StandardKey.Print,
    QKeySequence.StandardKey.Save,
    QKeySequence.StandardKey.SaveAs,
)


def _is_blocked_shortcut(event: QKeyEvent) -> bool:
    return any(event.matches(sequence) for sequence in _BLOCKED_KEY_SEQUENCES)


class _NoCopyMixin:
    """Shared lockdown: no context menu, no drag/drop, no copy shortcuts.

    Mixed into a `QWidget` subclass (first in MRO) so its overrides run
    before the Qt base class's own event handling.
    """

    def _lockdown(self) -> None:
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.setAcceptDrops(False)

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        event.ignore()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        event.ignore()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if _is_blocked_shortcut(event):
            event.accept()
            return
        super().keyPressEvent(event)  # type: ignore[misc]


class _SecureTextView(_NoCopyMixin, QPlainTextEdit):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self._lockdown()


class _SecureLabelView(_NoCopyMixin, QLabel):
    """Used both for rendered images and for plain-text notices
    (e.g. an unsupported-content-type message)."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self._lockdown()


class _SecurePdfView(_NoCopyMixin, QPdfView):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._lockdown()
        self.setPageMode(QPdfView.PageMode.MultiPage)


class SecureViewerWidget(QWidget):
    """A `ViewerBackend`-shaped widget: `display(content, content_type)`
    and `close()`. Renders TXT, images, and PDF entirely from in-memory
    bytes; nothing here ever reads or writes a file."""

    # Emitted exactly once, at the end of `_teardown()`, regardless of
    # whether the window was closed by the user or by capture detection —
    # the signal callers (see `ui.pages.decryption_page`) rely on to know
    # when the user has actually finished viewing.
    closed = Signal()

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        on_screen_capture_detected: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Secure Viewer")
        # Established before any `display()` call (which can run before
        # `show()` — see `ui.pages.decryption_page`), so the "fit to
        # window" computations below have a real size to fit against
        # instead of Qt's default not-yet-shown widget size.
        self.resize(900, 700)
        self._on_screen_capture_detected = on_screen_capture_detected

        self._text_view = _SecureTextView()
        self._label_view = _SecureLabelView()
        self._pdf_view = _SecurePdfView()
        self._pdf_document = QPdfDocument(self)
        self._pdf_view.setDocument(self._pdf_document)
        self._pdf_buffer: Optional[QBuffer] = None

        # Original, unscaled pixmap for the currently displayed image —
        # `_label_view.pixmap()` only ever holds the current *scaled*
        # render, so zooming needs a separate source to re-scale from
        # rather than repeatedly downsampling an already-downsampled copy.
        self._original_image_pixmap: Optional[QPixmap] = None
        self._image_zoom_factor: float = 1.0
        # Captured lazily, the first time text is actually shown (see
        # `_show_text`), as the baseline "Fit to Window" resets zoom back
        # to — not here at construction, since Qt's QSS-driven font can
        # still change between a freshly-constructed widget and its first
        # real display (the widget is not necessarily shown/polished
        # yet), which would make an eagerly-captured baseline wrong.
        self._default_text_point_size: Optional[float] = None

        self._stack = QStackedWidget()
        self._stack.addWidget(self._text_view)
        self._stack.addWidget(self._label_view)
        self._stack.addWidget(self._pdf_view)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self._build_zoom_toolbar())
        layout.addWidget(self._stack)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.setAcceptDrops(False)

        self._printscreen_watcher = PrintScreenWatcher(parent=self)
        self._printscreen_watcher.printscreen_detected.connect(self._on_printscreen_detected)

        self._capture_protection: Optional[CaptureProtectionResult] = None
        self._closed = False

    def _build_zoom_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        self.zoom_out_button = QPushButton("Zoom Out")
        self.zoom_out_button.clicked.connect(self._zoom_out)
        toolbar.addWidget(self.zoom_out_button)

        self.zoom_in_button = QPushButton("Zoom In")
        self.zoom_in_button.clicked.connect(self._zoom_in)
        toolbar.addWidget(self.zoom_in_button)

        self.fit_button = QPushButton("Fit to Window")
        self.fit_button.clicked.connect(self._zoom_fit)
        toolbar.addWidget(self.fit_button)

        self._zoom_label = QLabel("100%")
        toolbar.addWidget(self._zoom_label)
        toolbar.addStretch(1)
        return toolbar

    # -- ViewerBackend contract ----------------------------------------

    def display(self, content: bytes, content_type: str) -> None:
        if self._closed:
            raise RuntimeError("Cannot display content on a closed SecureViewerWidget")

        if content_type == CONTENT_TYPE_TXT:
            self._show_text(content)
        elif content_type == CONTENT_TYPE_PDF:
            self._show_pdf(content)
        elif content_type.startswith(_IMAGE_PREFIX):
            self._show_image(content)
        else:
            self._show_unsupported(content_type)

    # `close()` itself is not overridden: `QWidget.close()` already
    # matches `ViewerBackend.close()`'s signature and, via the
    # `closeEvent` override below, already guarantees teardown runs —
    # whether `close()` is called directly (as `SecureViewSession` does)
    # or the user closes the window.

    # -- Rendering (RAM-only: no path is ever read or written) -----------

    def _show_text(self, content: bytes) -> None:
        if self._default_text_point_size is None:
            self._default_text_point_size = self._text_view.font().pointSizeF()
        self._text_view.setPlainText(content.decode("utf-8", errors="replace"))
        self._stack.setCurrentWidget(self._text_view)
        self._update_zoom_label()

    def _show_image(self, content: bytes) -> None:
        image = QImage.fromData(content)
        if image.isNull():
            self._show_unsupported("image (unrecognized or corrupt format)")
            return
        self._original_image_pixmap = QPixmap.fromImage(image)
        # Switched to the current widget *before* `_render_image()` below
        # (which updates the zoom-percentage label): `_update_zoom_label`
        # reads `self._stack.currentWidget()` to decide which content
        # type's zoom to report, so it must already see `_label_view` as
        # current, not whatever was current beforehand.
        self._stack.setCurrentWidget(self._label_view)
        # A large image opening at native pixel size can be too big to
        # read comfortably (or even fit on screen) — start fit-to-window
        # instead, same as the PDF view now defaults to FitToWidth.
        self._image_zoom_factor = self._compute_image_fit_factor(self._original_image_pixmap)
        self._render_image()

    def _show_pdf(self, content: bytes) -> None:
        buffer = QBuffer(self)
        buffer.setData(QByteArray(content))
        buffer.open(QIODevice.OpenModeFlag.ReadOnly)

        self._pdf_document.close()
        if self._pdf_buffer is not None:
            self._pdf_buffer.close()
        self._pdf_buffer = buffer

        self._pdf_document.load(buffer)
        # Default to fit-to-width rather than QPdfView's native/unscaled
        # default zoom, which can open a high-resolution PDF too large to
        # read without immediately having to zoom out manually.
        self._pdf_view.setZoomMode(QPdfView.ZoomMode.FitToWidth)
        self._stack.setCurrentWidget(self._pdf_view)
        self._update_zoom_label()

    def _show_unsupported(self, content_type: str) -> None:
        self._original_image_pixmap = None
        self._label_view.setPixmap(QPixmap())
        self._label_view.setText(f"Unsupported content type: {content_type}")
        self._stack.setCurrentWidget(self._label_view)
        self._update_zoom_label()

    # -- Zoom (PDF / image / text) ---------------------------------------

    def _compute_image_fit_factor(self, pixmap: QPixmap) -> float:
        available = self.size()
        if available.width() < 100 or available.height() < 100:
            # Not yet given real on-screen geometry (display() can run
            # before show(), see __init__) — the explicit default size
            # set at construction covers this in practice, but fall back
            # to it explicitly too rather than fitting against a
            # degenerate size.
            available = self.sizeHint()
        if pixmap.width() <= 0 or pixmap.height() <= 0:
            return 1.0
        factor = min(1.0, available.width() / pixmap.width(), available.height() / pixmap.height())
        return max(_ZOOM_MIN, factor)

    def _render_image(self) -> None:
        if self._original_image_pixmap is None:
            return
        width = max(1, round(self._original_image_pixmap.width() * self._image_zoom_factor))
        height = max(1, round(self._original_image_pixmap.height() * self._image_zoom_factor))
        scaled = self._original_image_pixmap.scaled(
            width, height, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        )
        self._label_view.setPixmap(scaled)
        self._update_zoom_label()

    def _zoom_in(self) -> None:
        current = self._stack.currentWidget()
        if current is self._pdf_view:
            self._set_pdf_zoom_factor(self._pdf_view.zoomFactor() * _ZOOM_STEP)
        elif current is self._label_view and self._original_image_pixmap is not None:
            self._image_zoom_factor = min(_ZOOM_MAX, self._image_zoom_factor * _ZOOM_STEP)
            self._render_image()
        elif current is self._text_view:
            self._text_view.zoomIn(2)
            self._update_zoom_label()

    def _zoom_out(self) -> None:
        current = self._stack.currentWidget()
        if current is self._pdf_view:
            self._set_pdf_zoom_factor(self._pdf_view.zoomFactor() / _ZOOM_STEP)
        elif current is self._label_view and self._original_image_pixmap is not None:
            self._image_zoom_factor = max(_ZOOM_MIN, self._image_zoom_factor / _ZOOM_STEP)
            self._render_image()
        elif current is self._text_view:
            self._text_view.zoomOut(2)
            self._update_zoom_label()

    def _zoom_fit(self) -> None:
        current = self._stack.currentWidget()
        if current is self._pdf_view:
            self._pdf_view.setZoomMode(QPdfView.ZoomMode.FitToWidth)
            self._update_zoom_label()
        elif current is self._label_view and self._original_image_pixmap is not None:
            self._image_zoom_factor = self._compute_image_fit_factor(self._original_image_pixmap)
            self._render_image()
        elif current is self._text_view and self._default_text_point_size is not None:
            font = self._text_view.font()
            font.setPointSizeF(self._default_text_point_size)
            self._text_view.setFont(font)
            self._update_zoom_label()

    def _set_pdf_zoom_factor(self, factor: float) -> None:
        clamped = max(_ZOOM_MIN, min(_ZOOM_MAX, factor))
        self._pdf_view.setZoomMode(QPdfView.ZoomMode.Custom)
        self._pdf_view.setZoomFactor(clamped)
        self._update_zoom_label()

    def _update_zoom_label(self) -> None:
        current = self._stack.currentWidget()
        if current is self._pdf_view:
            if self._pdf_view.zoomMode() == QPdfView.ZoomMode.FitToWidth:
                self._zoom_label.setText("Fit")
            else:
                self._zoom_label.setText(f"{round(self._pdf_view.zoomFactor() * 100)}%")
        elif current is self._label_view and self._original_image_pixmap is not None:
            self._zoom_label.setText(f"{round(self._image_zoom_factor * 100)}%")
        elif current is self._text_view and self._default_text_point_size:
            percent = round(self._text_view.font().pointSizeF() / self._default_text_point_size * 100)
            self._zoom_label.setText(f"{percent}%")
        else:
            self._zoom_label.setText("100%")

    # -- Lifecycle: capture protection + guaranteed teardown --------------

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self._capture_protection = apply_capture_protection(int(self.winId()))
        logger.info(
            "Screen capture protection: level=%s detail=%s",
            self._capture_protection.level.name,
            self._capture_protection.detail,
        )
        self._printscreen_watcher.start()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._teardown()
        super().closeEvent(event)

    @property
    def capture_protection_level(self) -> CaptureProtectionLevel:
        if self._capture_protection is None:
            return CaptureProtectionLevel.NONE
        return self._capture_protection.level

    @property
    def is_closed(self) -> bool:
        return self._closed

    def set_screen_capture_handler(self, handler: Optional[Callable[[], None]]) -> None:
        """Set (or clear) the callback invoked when a screen-capture
        attempt is detected while this viewer is open — see
        `usb.secure_access_service.AccessOutcome.on_screen_capture_detected`."""
        self._on_screen_capture_detected = handler

    def _teardown(self) -> None:
        """Clear rendered content and stop background watchers. Idempotent."""
        if self._closed:
            return
        self._closed = True

        self._text_view.clear()
        self._label_view.clear()
        self._original_image_pixmap = None
        self._pdf_document.close()
        if self._pdf_buffer is not None:
            self._pdf_buffer.close()
            self._pdf_buffer = None

        self._printscreen_watcher.stop()
        if self._capture_protection is not None:
            remove_capture_protection(int(self.winId()))
            self._capture_protection = None

        logger.info("Secure viewer closed; decrypted content cleared from view")
        self.closed.emit()

    def _on_printscreen_detected(self) -> None:
        # Detection only — see viewer.screen_capture_protection for why
        # this cannot also guarantee prevention. Per project decision, the
        # viewer reacts by closing immediately rather than merely logging:
        # the capture event is recorded first (before teardown clears the
        # record reference), then any lingering rendered content is
        # blanked right away, then the window closes (which runs the same
        # blanking again via `_teardown`, but that moment is not
        # guaranteed to be instantaneous, so this avoids a visible lag).
        logger.warning("Print Screen detected while the secure viewer was open")
        if self._on_screen_capture_detected is not None:
            self._on_screen_capture_detected()
        self._text_view.clear()
        self._label_view.clear()
        self._original_image_pixmap = None
        self._pdf_document.close()
        if self._pdf_buffer is not None:
            self._pdf_buffer.close()
            self._pdf_buffer = None
        self.close()
