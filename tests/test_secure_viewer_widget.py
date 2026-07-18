"""Tests for the Secure Controlled Viewer widget."""

import random

import pytest
from PySide6.QtCore import QEvent, QMimeData, Qt
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QKeyEvent, QKeySequence
from PySide6.QtWidgets import QApplication

import viewer.secure_viewer_widget as svw
from crypto.secure_bytes import SecureBytes
from deception.content_generators import generate_fake_image, generate_fake_pdf
from viewer.interfaces import SecureViewSession
from viewer.screen_capture_protection import CaptureProtectionLevel
from viewer.secure_viewer_widget import CONTENT_TYPE_PDF, CONTENT_TYPE_TXT, SecureViewerWidget

TEXT_CONTENT = b"the quarterly figures are strictly confidential"


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def widget(app):
    w = SecureViewerWidget()
    yield w
    if not w.is_closed:
        w.close()


def _key_event(key, modifier=Qt.KeyboardModifier.NoModifier, text=""):
    return QKeyEvent(QEvent.Type.KeyPress, key, modifier, text)


# -- Rendering: PDF / image / TXT --------------------------------------


def test_displays_plain_text(widget):
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    assert widget._text_view.toPlainText() == TEXT_CONTENT.decode("utf-8")
    assert widget._stack.currentWidget() is widget._text_view


def test_displays_image(widget, app):
    png = generate_fake_image(random.Random(1))

    widget.display(png, "image/png")
    app.processEvents()

    assert widget._label_view.pixmap() is not None
    assert not widget._label_view.pixmap().isNull()
    assert widget._stack.currentWidget() is widget._label_view


def test_displays_pdf(widget, app):
    pdf = generate_fake_pdf(random.Random(1))

    widget.display(pdf, CONTENT_TYPE_PDF)
    app.processEvents()

    assert widget._pdf_document.pageCount() == 1
    assert widget._stack.currentWidget() is widget._pdf_view


def test_pdf_view_uses_multi_page_mode_so_all_pages_are_reachable(widget):
    """`QPdfView` defaults to `SinglePage` mode, which stranded multi-page
    PDFs on page 1 with no navigation control anywhere in the UI to
    reach later pages; `MultiPage` renders the whole document as one
    continuous scrollable view instead."""
    from PySide6.QtPdfWidgets import QPdfView

    assert widget._pdf_view.pageMode() == QPdfView.PageMode.MultiPage


def test_unsupported_content_type_shows_a_notice_instead_of_raising(widget):
    widget.display(b"PK\x03\x04 pretend zip bytes", "application/zip")

    assert "Unsupported" in widget._label_view.text()
    assert widget._stack.currentWidget() is widget._label_view


def test_corrupt_image_bytes_show_a_notice_instead_of_crashing(widget):
    widget.display(b"not actually a png", "image/png")

    assert "Unsupported" in widget._label_view.text()


def test_display_after_close_raises(widget):
    widget.close()

    with pytest.raises(RuntimeError):
        widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)


# -- Restrictions: context menu, drag & drop -----------------------------


@pytest.mark.parametrize(
    "attr", ["_text_view", "_label_view", "_pdf_view"]
)
def test_context_menu_is_disabled_on_every_sub_view(widget, attr):
    sub_widget = getattr(widget, attr)
    assert sub_widget.contextMenuPolicy() == Qt.ContextMenuPolicy.NoContextMenu


def test_widget_itself_disables_context_menu(widget):
    assert widget.contextMenuPolicy() == Qt.ContextMenuPolicy.NoContextMenu


@pytest.mark.parametrize("attr", ["_text_view", "_label_view", "_pdf_view"])
def test_drag_and_drop_is_disabled_on_every_sub_view(widget, attr):
    sub_widget = getattr(widget, attr)
    assert sub_widget.acceptDrops() is False


def test_drop_event_is_ignored_by_the_text_view(widget):
    mime = QMimeData()
    mime.setText("smuggled content")
    event = QDropEvent(
        widget._text_view.rect().center().toPointF(),
        Qt.DropAction.CopyAction,
        mime,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )

    widget._text_view.dropEvent(event)

    assert event.isAccepted() is False


def test_drag_enter_event_is_ignored_by_the_text_view(widget):
    mime = QMimeData()
    mime.setText("smuggled content")
    event = QDragEnterEvent(
        widget._text_view.rect().center(),
        Qt.DropAction.CopyAction,
        mime,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )

    widget._text_view.dragEnterEvent(event)

    assert event.isAccepted() is False


# -- Restrictions: editing / selection -----------------------------------


def test_text_view_is_read_only_and_non_interactive(widget):
    assert widget._text_view.isReadOnly() is True
    assert widget._text_view.textInteractionFlags() == Qt.TextInteractionFlag.NoTextInteraction


def test_label_view_is_non_interactive(widget):
    assert widget._label_view.textInteractionFlags() == Qt.TextInteractionFlag.NoTextInteraction


# -- Restrictions: copy/cut/paste/select-all/print/save shortcuts --------


@pytest.mark.parametrize(
    "key,modifier",
    [
        (Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier),
        (Qt.Key.Key_X, Qt.KeyboardModifier.ControlModifier),
        (Qt.Key.Key_V, Qt.KeyboardModifier.ControlModifier),
        (Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier),
        (Qt.Key.Key_P, Qt.KeyboardModifier.ControlModifier),
        (Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier),
    ],
)
def test_copy_paste_print_save_shortcuts_are_swallowed(widget, key, modifier):
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)
    event = _key_event(key, modifier)

    widget._text_view.keyPressEvent(event)

    assert event.isAccepted() is True


def test_clipboard_is_untouched_after_a_blocked_copy_shortcut(widget, app):
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)
    clipboard = QApplication.clipboard()
    clipboard.setText("sentinel-before-copy-attempt")

    event = _key_event(Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    widget._text_view.keyPressEvent(event)

    assert clipboard.text() == "sentinel-before-copy-attempt"


def test_navigation_keys_are_forwarded_to_the_base_widget(widget, monkeypatch):
    from PySide6.QtWidgets import QPlainTextEdit

    calls = []
    original = QPlainTextEdit.keyPressEvent

    def _spy(self, event):
        calls.append(event.key())
        return original(self, event)

    monkeypatch.setattr(QPlainTextEdit, "keyPressEvent", _spy)
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    widget._text_view.keyPressEvent(_key_event(Qt.Key.Key_Down))

    # Not one of the blocked standard-key sequences, so it must reach
    # the base QPlainTextEdit's own handling rather than being swallowed.
    assert calls == [Qt.Key.Key_Down]


def test_copy_shortcut_never_reaches_the_base_widget(widget, monkeypatch):
    from PySide6.QtWidgets import QPlainTextEdit

    calls = []
    monkeypatch.setattr(
        QPlainTextEdit, "keyPressEvent", lambda self, event: calls.append(event.key())
    )
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    widget._text_view.keyPressEvent(_key_event(Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier))

    assert calls == []


def test_is_blocked_shortcut_matches_every_required_standard_key():
    required = [
        QKeySequence.StandardKey.Copy,
        QKeySequence.StandardKey.Cut,
        QKeySequence.StandardKey.Paste,
        QKeySequence.StandardKey.SelectAll,
        QKeySequence.StandardKey.Print,
        QKeySequence.StandardKey.Save,
        QKeySequence.StandardKey.SaveAs,
    ]
    assert set(required) <= set(svw._BLOCKED_KEY_SEQUENCES)


# -- Lifecycle: RAM only, destroyed on close -----------------------------


def test_close_clears_text_content(widget):
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    widget.close()

    assert widget._text_view.toPlainText() == ""
    assert widget.is_closed is True


def test_close_clears_image_content(widget, app):
    widget.display(generate_fake_image(random.Random(1)), "image/png")

    widget.close()

    assert widget._label_view.pixmap() is None or widget._label_view.pixmap().isNull()


def test_close_clears_pdf_document(widget, app):
    widget.display(generate_fake_pdf(random.Random(1)), CONTENT_TYPE_PDF)
    app.processEvents()
    assert widget._pdf_document.pageCount() == 1

    widget.close()

    assert widget._pdf_document.pageCount() == 0


def test_close_is_idempotent(widget):
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    widget.close()
    widget.close()  # must not raise

    assert widget.is_closed is True


def test_close_stops_the_printscreen_watcher(widget):
    widget._printscreen_watcher.start()
    assert widget._printscreen_watcher.is_active is True

    widget.close()

    assert widget._printscreen_watcher.is_active is False


# -- Lifecycle: screen capture protection wiring -------------------------


def test_show_applies_capture_protection_and_starts_the_watcher(widget, app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        svw,
        "apply_capture_protection",
        lambda hwnd: calls.append(hwnd) or svw.CaptureProtectionResult(
            svw.CaptureProtectionLevel.EXCLUDED_FROM_CAPTURE, "test"
        ),
    )

    widget.show()
    app.processEvents()

    assert len(calls) == 1
    assert widget.capture_protection_level is CaptureProtectionLevel.EXCLUDED_FROM_CAPTURE
    assert widget._printscreen_watcher.is_active is True


def test_close_removes_capture_protection(widget, app, monkeypatch):
    monkeypatch.setattr(
        svw,
        "apply_capture_protection",
        lambda hwnd: svw.CaptureProtectionResult(svw.CaptureProtectionLevel.MONITOR_BLACKOUT, "test"),
    )
    removed = []
    monkeypatch.setattr(svw, "remove_capture_protection", lambda hwnd: removed.append(hwnd))

    widget.show()
    app.processEvents()
    widget.close()

    assert len(removed) == 1
    assert widget.capture_protection_level is CaptureProtectionLevel.NONE


def test_capture_protection_level_defaults_to_none_before_show(widget):
    assert widget.capture_protection_level is CaptureProtectionLevel.NONE


# -- `closed` signal ------------------------------------------------------


def test_closed_signal_fires_exactly_once_on_close(widget):
    calls = []
    widget.closed.connect(lambda: calls.append(None))

    widget.close()
    widget.close()  # idempotent teardown must not fire the signal again

    assert len(calls) == 1


def test_closed_signal_fires_on_printscreen_triggered_close(widget):
    calls = []
    widget.closed.connect(lambda: calls.append(None))

    widget._on_printscreen_detected()

    assert len(calls) == 1
    assert widget.is_closed is True


# -- Screen-capture detection reacts by closing immediately ----------------


def test_set_screen_capture_handler_stores_the_handler(widget):
    handler = lambda: None  # noqa: E731
    widget.set_screen_capture_handler(handler)

    assert widget._on_screen_capture_detected is handler


def test_printscreen_detected_calls_the_configured_handler(widget):
    calls = []
    widget.set_screen_capture_handler(lambda: calls.append("detected"))

    widget._on_printscreen_detected()

    assert calls == ["detected"]


def test_printscreen_detected_without_a_handler_does_not_raise(widget):
    widget._on_printscreen_detected()  # must not raise

    assert widget.is_closed is True


def test_printscreen_detected_blanks_text_content(widget):
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    widget._on_printscreen_detected()

    assert widget._text_view.toPlainText() == ""


def test_printscreen_detected_blanks_image_content(widget, app):
    widget.display(generate_fake_image(random.Random(1)), "image/png")

    widget._on_printscreen_detected()

    assert widget._label_view.pixmap() is None or widget._label_view.pixmap().isNull()


def test_printscreen_detected_blanks_pdf_content(widget, app):
    widget.display(generate_fake_pdf(random.Random(1)), CONTENT_TYPE_PDF)
    app.processEvents()
    assert widget._pdf_document.pageCount() == 1

    widget._on_printscreen_detected()

    assert widget._pdf_document.pageCount() == 0


def test_printscreen_detected_closes_the_viewer(widget):
    assert widget.is_closed is False

    widget._on_printscreen_detected()

    assert widget.is_closed is True


def test_printscreen_detected_calls_handler_before_teardown_clears_content(widget):
    """The tracking callback must see the widget still "open" (i.e. it
    must run before `close()`/`_teardown()`), so a caller closing over a
    live UsageRecord can still record the event before anything is torn
    down."""
    order = []
    widget.set_screen_capture_handler(lambda: order.append("handler"))
    original_close = widget.close

    def _spy_close():
        order.append("close")
        original_close()

    widget.close = _spy_close
    widget.display(TEXT_CONTENT, CONTENT_TYPE_TXT)

    widget._on_printscreen_detected()

    assert order == ["handler", "close"]


# -- Integration with Phase 9's SecureViewSession -------------------------


def test_used_as_a_viewer_backend_via_secure_view_session(app):
    plaintext = b"decrypted-in-ram-only content for the controlled viewer"
    buffer = SecureBytes(plaintext)
    backend = SecureViewerWidget()

    with SecureViewSession(buffer, content_type=CONTENT_TYPE_TXT, backend=backend) as session:
        session.display()
        assert backend._text_view.toPlainText() == plaintext.decode("utf-8")

    assert buffer.is_destroyed is True
    assert backend.is_closed is True
    assert backend._text_view.toPlainText() == ""
