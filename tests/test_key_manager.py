"""Tests for the Key Management Module (KeyManager, ManagedKey)."""

import pytest

from crypto.exceptions import KeyDestroyedError
from crypto.key_manager import KeyManager, KeyState, ManagedKey
from crypto.key_wrapper import RSAOAEPKeyWrapper


@pytest.fixture
def manager():
    return KeyManager()


def test_generate_fek_returns_active_managed_key(manager):
    fek = manager.generate_fek()
    assert isinstance(fek, ManagedKey)
    assert fek.state is KeyState.ACTIVE
    assert len(fek.material()) == 32


def test_generate_fek_is_unique(manager):
    fek_a = manager.generate_fek()
    fek_b = manager.generate_fek()
    assert fek_a.material() != fek_b.material()


def test_destroy_key_transitions_state_and_zeroes_material(manager):
    fek = manager.generate_fek()
    manager.destroy_key(fek)

    assert fek.state is KeyState.DESTROYED
    with pytest.raises(KeyDestroyedError):
        fek.material()


def test_managed_key_context_manager_destroys_on_exit(manager):
    with manager.generate_fek() as fek:
        assert fek.state is KeyState.ACTIVE
    assert fek.state is KeyState.DESTROYED


def test_generate_rsa_keypair_is_4096(manager):
    keypair = manager.generate_rsa_keypair()
    assert keypair.private_key.key_size == 4096


def test_wrap_and_unwrap_key_round_trip(manager, rsa_keypair_fixture):
    wrapper = RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)
    fek = manager.generate_fek()
    original_material = fek.material()

    wrapped = manager.wrap_key(fek, wrapper)
    unwrapped_fek = manager.unwrap_key(wrapped, wrapper)

    assert unwrapped_fek.material() == original_material
    assert unwrapped_fek.state is KeyState.ACTIVE


def test_unwrap_key_returns_new_managed_key(manager, rsa_keypair_fixture):
    wrapper = RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)
    fek = manager.generate_fek()
    wrapped = manager.wrap_key(fek, wrapper)

    unwrapped_fek = manager.unwrap_key(wrapped, wrapper)

    assert unwrapped_fek is not fek
