"""Tests for RSA-OAEP key wrapping."""

import pytest

from crypto.exceptions import KeyUnwrappingError
from crypto.key_wrapper import RSAOAEPKeyWrapper


@pytest.fixture
def keypair(rsa_keypair_fixture):
    return rsa_keypair_fixture


def test_wrap_unwrap_round_trip(keypair):
    wrapper = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    fek = b"0" * 32

    wrapped = wrapper.wrap(fek)
    unwrapped = wrapper.unwrap(wrapped)

    assert unwrapped == fek


def test_wrapped_key_differs_from_plaintext(keypair):
    wrapper = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    fek = b"1" * 32

    wrapped = wrapper.wrap(fek)

    assert wrapped != fek
    assert len(wrapped) == 512  # RSA-4096 -> 512-byte ciphertext


def test_wrap_only_needs_public_key(keypair):
    wrapper = RSAOAEPKeyWrapper(keypair.public_key)  # no private key
    wrapped = wrapper.wrap(b"2" * 32)
    assert len(wrapped) == 512


def test_unwrap_without_private_key_raises(keypair):
    wrapper = RSAOAEPKeyWrapper(keypair.public_key)  # no private key
    wrapped = wrapper.wrap(b"3" * 32)

    unwrap_only_wrapper = RSAOAEPKeyWrapper(keypair.public_key)
    with pytest.raises(KeyUnwrappingError):
        unwrap_only_wrapper.unwrap(wrapped)


def test_unwrap_with_wrong_private_key_fails(keypair, other_rsa_keypair_fixture):
    wrapper = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    wrapped = wrapper.wrap(b"4" * 32)

    wrong_wrapper = RSAOAEPKeyWrapper(
        other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key
    )
    with pytest.raises(KeyUnwrappingError):
        wrong_wrapper.unwrap(wrapped)


def test_algorithm_name(keypair):
    wrapper = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    assert wrapper.algorithm == "RSA-OAEP"
