"""Tests for the global, last-resort exception hook."""

import sys
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QApplication

import app.error_handling as error_handling
from app.error_handling import install_excepthook


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _restore_excepthook():
    # An earlier test (e.g. one that calls `app.main.bootstrap`) may have
    # already installed the real hook this session; force a clean,
    # not-yet-installed state so each test here observes `install_excepthook`
    # actually taking effect, then restore whatever was in place before.
    original = sys.excepthook
    original_installed = error_handling._installed
    error_handling._installed = False
    yield
    sys.excepthook = original
    error_handling._installed = original_installed


def test_install_excepthook_replaces_sys_excepthook():
    default = sys.excepthook
    install_excepthook()
    assert sys.excepthook is not default


def test_install_excepthook_is_idempotent():
    install_excepthook()
    first = sys.excepthook
    install_excepthook()
    assert sys.excepthook is first


def test_handler_logs_and_shows_dialog_without_raising(app, monkeypatch, caplog):
    import logging

    from PySide6.QtWidgets import QMessageBox

    shown = {}

    def _fake_critical(*args, **kwargs):
        shown["called"] = True
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "critical", _fake_critical)
    install_excepthook()

    try:
        raise ValueError("boom")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()

    with caplog.at_level(logging.CRITICAL, logger="app.error_handling"):
        sys.excepthook(exc_type, exc_value, exc_tb)

    assert shown.get("called") is True
    assert "boom" in caplog.text


def test_handler_never_raises_even_if_dialog_construction_fails(app, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    def _raise(*args, **kwargs):
        raise RuntimeError("dialog subsystem broken")

    monkeypatch.setattr(QMessageBox, "critical", _raise)
    install_excepthook()

    try:
        raise ValueError("boom")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()

    sys.excepthook(exc_type, exc_value, exc_tb)  # must not raise


def test_handler_reraises_keyboard_interrupt_via_default_hook(monkeypatch):
    install_excepthook()
    calls = []
    monkeypatch.setattr(sys, "__excepthook__", lambda *a: calls.append(a))

    try:
        raise KeyboardInterrupt()
    except KeyboardInterrupt:
        exc_type, exc_value, exc_tb = sys.exc_info()

    sys.excepthook(exc_type, exc_value, exc_tb)

    assert len(calls) == 1


# -- Reentrancy guard: don't stack a second modal dialog on a persistent fault --


def test_single_exception_still_shows_the_dialog_exactly_once(app, monkeypatch):
    """Confirms the reentrancy guard didn't change the ordinary, single-
    exception path: unchanged from before `_dialog_open` existed."""
    from PySide6.QtWidgets import QMessageBox

    mock_critical = MagicMock(return_value=QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "critical", mock_critical)
    install_excepthook()

    try:
        raise ValueError("boom")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()

    sys.excepthook(exc_type, exc_value, exc_tb)

    mock_critical.assert_called_once()


def test_second_exception_while_dialog_open_is_suppressed_but_still_logged(app, monkeypatch, caplog):
    """A persistent fault (e.g. a pulled USB drive) can make a second
    page's timer raise while the first exception's dialog is still open
    and pumping its own nested event loop -- the second must not stack
    another modal dialog, but must still reach the audit log."""
    import logging

    from PySide6.QtWidgets import QMessageBox

    mock_critical = MagicMock(return_value=QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "critical", mock_critical)
    install_excepthook()
    error_handling._dialog_open = True

    try:
        raise ValueError("second boom, first dialog still open")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()

    with caplog.at_level(logging.CRITICAL, logger="app.error_handling"):
        sys.excepthook(exc_type, exc_value, exc_tb)

    mock_critical.assert_not_called()
    assert "still open" in caplog.text


def test_dialog_open_flag_clears_after_the_dialog_is_dismissed_normally(app, monkeypatch):
    """The guard is "don't stack while one is already open", not a
    permanent suppression -- the next new exception must show a fresh
    dialog once this one is gone."""
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "critical", MagicMock(return_value=QMessageBox.StandardButton.Ok))
    install_excepthook()

    try:
        raise ValueError("boom")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()

    sys.excepthook(exc_type, exc_value, exc_tb)

    assert error_handling._dialog_open is False


def test_dialog_open_flag_clears_even_when_dialog_construction_fails(app, monkeypatch):
    """The `finally` block must reset the flag on the failure path too,
    or a broken dialog subsystem would permanently suppress every future
    error dialog for the rest of the session."""
    from PySide6.QtWidgets import QMessageBox

    def _raise(*args, **kwargs):
        raise RuntimeError("dialog subsystem broken")

    monkeypatch.setattr(QMessageBox, "critical", _raise)
    install_excepthook()

    try:
        raise ValueError("boom")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()

    sys.excepthook(exc_type, exc_value, exc_tb)

    assert error_handling._dialog_open is False
