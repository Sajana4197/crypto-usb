"""Tests for the global, last-resort exception hook."""

import sys

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
