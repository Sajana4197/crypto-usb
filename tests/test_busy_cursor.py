"""Tests for the `busy_cursor` UI feedback helper."""

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from ui.widgets.busy import busy_cursor


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
