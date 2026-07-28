"""Tests for the `busy_cursor` and `progress_dialog` UI feedback helpers."""

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel

from ui.widgets.busy import busy_cursor, progress_dialog


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_busy_cursor_sets_and_restores_wait_cursor(app):
    assert QApplication.overrideCursor() is None

    with busy_cursor():
        assert QApplication.overrideCursor() is not None
        assert QApplication.overrideCursor().shape() == Qt.CursorShape.WaitCursor

    assert QApplication.overrideCursor() is None


def test_busy_cursor_restores_even_if_the_block_raises(app):
    with pytest.raises(RuntimeError):
        with busy_cursor():
            raise RuntimeError("boom")

    assert QApplication.overrideCursor() is None


# -- progress_dialog -------------------------------------------------------


def test_progress_dialog_shows_the_given_message(app):
    message = "Encrypting and writing secure container..."
    with progress_dialog(None, message) as dialog:
        assert dialog.isVisible() is True
        labels = [label.text() for label in dialog.findChildren(QLabel)]
        assert message in labels


def test_progress_dialog_forces_a_synchronous_repaint_before_yielding(app, monkeypatch):
    """A single `processEvents()` only queues the paint request -- on
    Windows, a long blocking call started right after `show()` can freeze
    the window before that queued paint ever reaches the screen, leaving
    the last real frame blank (see `progress_dialog`'s docstring). An
    explicit `repaint()` forces it to happen before the caller's blocking
    work can start."""
    from ui.widgets import busy as busy_module

    calls = []
    original_repaint = busy_module._BusyDialog.repaint

    def _spy_repaint(self):
        calls.append("repaint")
        return original_repaint(self)

    monkeypatch.setattr(busy_module._BusyDialog, "repaint", _spy_repaint)

    with progress_dialog(None, "Working..."):
        pass

    assert calls == ["repaint"]


def test_progress_dialog_starts_and_stops_the_spinner(app):
    with progress_dialog(None, "Working...") as dialog:
        assert dialog._spinner._timer.isActive() is True

    assert dialog._spinner._timer.isActive() is False


def test_progress_dialog_has_no_close_button(app):
    with progress_dialog(None, "Working...") as dialog:
        assert not (dialog.windowFlags() & Qt.WindowType.WindowCloseButtonHint)


def test_progress_dialog_closes_after_the_with_block(app):
    with progress_dialog(None, "Working...") as dialog:
        pass

    assert dialog.isVisible() is False


def test_progress_dialog_closes_even_if_the_block_raises(app):
    captured = {}
    with pytest.raises(RuntimeError):
        with progress_dialog(None, "Working...") as dialog:
            captured["dialog"] = dialog
            raise RuntimeError("boom")

    assert captured["dialog"].isVisible() is False
    assert captured["dialog"]._spinner._timer.isActive() is False
