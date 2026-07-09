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
