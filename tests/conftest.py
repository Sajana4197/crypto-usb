"""Shared pytest configuration.

Forces Qt's offscreen platform plugin so the GUI test suite runs
headlessly without flashing windows or requiring a display.
"""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def rsa_keypair_fixture():
    """A single RSA-4096 key pair reused across tests that don't test generation itself.

    RSA-4096 generation is expensive; tests that specifically exercise
    `rsa_keypair.generate_rsa_keypair()` still call it directly.
    """
    from crypto import rsa_keypair

    return rsa_keypair.generate_rsa_keypair()


@pytest.fixture(scope="session")
def other_rsa_keypair_fixture():
    """A second, distinct RSA-4096 key pair for wrong-key negative tests."""
    from crypto import rsa_keypair

    return rsa_keypair.generate_rsa_keypair()


@pytest.fixture(autouse=True)
def _isolate_vault_key_path(tmp_path, monkeypatch):
    """Redirect the SQLCipher file key (Phase 23) into this test's own
    `tmp_path`, never the real project's `data/.vault_key`.

    `utils.paths.get_vault_key_path()` is not parameterized by whatever a
    test monkeypatches `get_database_path()` to — it always resolves
    under the real project data directory unless overridden. Any test
    that constructs a real `DatabaseManager` would otherwise read/write
    the actual installation's file-encryption key, leaking state between
    test runs and polluting the real application data directory. Applied
    to every test (not just the ones that need it) since it is a no-op
    for tests that never touch `DatabaseManager`.
    """
    monkeypatch.setattr("database.file_key.get_vault_key_path", lambda: tmp_path / ".vault_key")
