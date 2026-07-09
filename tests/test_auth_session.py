"""Tests for AuthSession and SessionManager."""

from datetime import datetime, timezone

from security.auth_session import AuthSession, SessionManager
from security.models import AuthMethod


def _session(owner_id="owner-1"):
    return AuthSession(owner_id=owner_id, method=AuthMethod.PASSWORD, authenticated_at=datetime.now(timezone.utc))


def test_session_manager_starts_unauthenticated():
    manager = SessionManager()
    assert manager.is_authenticated is False
    assert manager.current is None


def test_session_manager_set_and_current():
    manager = SessionManager()
    session = _session()

    manager.set(session)

    assert manager.is_authenticated is True
    assert manager.current is session


def test_session_manager_clear():
    manager = SessionManager()
    manager.set(_session())

    manager.clear()

    assert manager.is_authenticated is False
    assert manager.current is None


def test_session_tokens_are_unique():
    a = _session()
    b = _session()
    assert a.session_token != b.session_token
