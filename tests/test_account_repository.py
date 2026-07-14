"""Tests for SQLite persistence of user accounts."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from security.account_repository import AccountRepository
from security.models import AuthMethod, PasswordCredential, PrivateKeyCredential, UserAccount


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return AccountRepository(connection)


def _password_account(owner_id="owner-1"):
    return UserAccount(
        owner_id=owner_id,
        auth_method=AuthMethod.PASSWORD,
        credential=PasswordCredential(salt=b"\x01" * 16, digest=b"\x02" * 32, n=16384, r=8, p=1, key_len=32),
        created_at=datetime.now(timezone.utc),
    )


def _key_account(owner_id="owner-2"):
    return UserAccount(
        owner_id=owner_id,
        auth_method=AuthMethod.PRIVATE_KEY,
        credential=PrivateKeyCredential(
            public_key_pem=b"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"
        ),
        created_at=datetime.now(timezone.utc),
    )


def test_save_and_load_password_account(repository):
    account = _password_account()
    repository.save(account)

    restored = repository.load(account.owner_id)
    assert restored.owner_id == account.owner_id
    assert restored.auth_method == AuthMethod.PASSWORD
    assert restored.credential == account.credential


def test_save_and_load_private_key_account(repository):
    account = _key_account()
    repository.save(account)

    restored = repository.load(account.owner_id)
    assert restored.credential == account.credential


def test_load_missing_returns_none(repository):
    assert repository.load("nobody") is None


def test_exists(repository):
    account = _password_account()
    assert repository.exists(account.owner_id) is False
    repository.save(account)
    assert repository.exists(account.owner_id) is True


def test_save_upserts_existing_account(repository):
    account = _password_account()
    repository.save(account)

    account.failed_attempts = 3
    account.locked_until = datetime.now(timezone.utc) + timedelta(seconds=30)
    repository.save(account)

    restored = repository.load(account.owner_id)
    assert restored.failed_attempts == 3
    assert restored.locked_until is not None


def test_delete_removes_account(repository):
    account = _password_account()
    repository.save(account)

    assert repository.delete(account.owner_id) is True
    assert repository.load(account.owner_id) is None


def test_delete_missing_returns_false(repository):
    assert repository.delete("nobody") is False


def test_list_owner_ids_empty_when_no_accounts(repository):
    assert repository.list_owner_ids() == []


def test_list_owner_ids_returns_all_saved_accounts(repository):
    repository.save(_password_account("owner-1"))
    repository.save(_key_account("owner-2"))

    assert sorted(repository.list_owner_ids()) == ["owner-1", "owner-2"]


def test_created_at_is_stable_across_updates(repository):
    account = _password_account()
    repository.save(account)
    original_created_at = repository.load(account.owner_id).created_at

    account.failed_attempts = 1
    repository.save(account)

    assert repository.load(account.owner_id).created_at == original_created_at
