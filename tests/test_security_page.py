"""Tests for the Access Security dashboard page."""

import sqlite3

import pytest
from PySide6.QtWidgets import QApplication

from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.lockout_policy import MAX_FAILED_ATTEMPTS
from ui.pages.security_page import SecurityPage


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def account_repository(connection):
    return AccountRepository(connection)


@pytest.fixture
def auth_controller(account_repository):
    return AuthController(account_repository)


def _make_page(app, account_repository=None):
    return SecurityPage(account_repository=account_repository)


def test_page_with_no_repository_shows_unavailable_message(app):
    page = _make_page(app)
    assert page.table.rowCount() == 0
    assert "no account repository" in page.summary_label.text().lower()


def test_page_with_no_accounts_shows_zero(app, account_repository):
    page = _make_page(app, account_repository)
    assert page.table.rowCount() == 0
    assert "0 account" in page.summary_label.text()


def test_page_shows_unlocked_account(app, account_repository, auth_controller):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")

    page = _make_page(app, account_repository)

    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == "owner-1"
    assert page.table.item(0, 2).text() == "0"  # failed attempts
    assert page.table.item(0, 3).text() == "No"  # locked


def test_page_shows_locked_account_after_max_failed_attempts(app, account_repository, auth_controller):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    for _ in range(MAX_FAILED_ATTEMPTS):
        session = auth_controller.authenticate_password("owner-1", "wrong-password")
        assert session.is_decoy is True

    page = _make_page(app, account_repository)

    assert page.table.item(0, 3).text() == "Yes"
    assert int(page.table.item(0, 4).text()) > 0
    assert "1 currently locked" in page.summary_label.text()


def test_page_shows_multiple_accounts(app, account_repository, auth_controller):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    auth_controller.register_password_account("owner-2", "another-strong-password")

    page = _make_page(app, account_repository)

    assert page.table.rowCount() == 2


def test_refresh_reflects_newly_registered_account(app, account_repository, auth_controller):
    page = _make_page(app, account_repository)
    assert page.table.rowCount() == 0

    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    page.refresh()

    assert page.table.rowCount() == 1


# -- Automatic polling --------------------------------------------------


def test_refresh_timer_is_running_after_construction(app, account_repository):
    page = _make_page(app, account_repository)

    assert page._refresh_timer.isActive() is True


def test_refresh_is_a_noop_when_no_account_is_locked_and_unchanged(app, account_repository, auth_controller, monkeypatch):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    page = _make_page(app, account_repository)

    calls = []
    monkeypatch.setattr(page, "_append_row", lambda *a, **k: calls.append(None))

    page.refresh()  # same account as construction -- nothing changed, nothing locked

    assert calls == []


def test_refresh_always_rebuilds_while_an_account_is_locked(app, account_repository, auth_controller, monkeypatch):
    """The 'Unlocks In' countdown is a function of wall-clock time, not just
    the stored account record -- a locked account must keep rebuilding on
    every poll tick even though the record itself hasn't changed, or the
    countdown would freeze (see SecurityPage.refresh)."""
    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    for _ in range(MAX_FAILED_ATTEMPTS):
        auth_controller.authenticate_password("owner-1", "wrong-password")
    page = _make_page(app, account_repository)

    calls = []
    monkeypatch.setattr(page, "_append_row", lambda *a, **k: calls.append(None))

    page.refresh()  # same locked account, unchanged record -- must still rebuild

    assert calls == [None]
