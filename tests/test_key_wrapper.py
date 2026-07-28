"""Tests for RSA-OAEP key wrapping."""

import pytest

from crypto.exceptions import KeyUnwrappingError
from crypto.key_wrapper import DeviceBoundKeyWrapper, RSAOAEPKeyWrapper


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


# -- DeviceBoundKeyWrapper (Phase 3: cryptographic device binding) ----------


def test_device_bound_wrap_unwrap_round_trip(keypair):
    inner = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    device_key = b"\x11" * 32
    wrapper = DeviceBoundKeyWrapper(inner, device_key)
    fek = b"5" * 32

    wrapped = wrapper.wrap(fek)
    unwrapped = wrapper.unwrap(wrapped)

    assert unwrapped == fek


def test_device_bound_wrapped_key_differs_from_inner_wrap(keypair):
    inner = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    device_key = b"\x22" * 32
    wrapper = DeviceBoundKeyWrapper(inner, device_key)
    fek = b"6" * 32

    inner_wrapped = inner.wrap(fek)
    outer_wrapped = wrapper.wrap(fek)

    assert outer_wrapped != inner_wrapped


def test_device_bound_unwrap_with_wrong_device_key_fails(keypair):
    """The core Phase 3 guarantee: a different device key (i.e. a
    different device) fails to unwrap outright -- not a policy check,
    an actual cryptographic failure."""
    inner = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    fek = b"7" * 32

    correct_wrapper = DeviceBoundKeyWrapper(inner, b"\x33" * 32)
    wrapped = correct_wrapper.wrap(fek)

    wrong_wrapper = DeviceBoundKeyWrapper(inner, b"\x44" * 32)
    with pytest.raises(KeyUnwrappingError):
        wrong_wrapper.unwrap(wrapped)


def test_device_bound_unwrap_with_wrong_inner_wrapper_fails(keypair, other_rsa_keypair_fixture):
    """A correct device key alone isn't enough either -- the inner (RSA)
    wrapper must also be correct, exactly like a bare RSAOAEPKeyWrapper."""
    inner = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    device_key = b"\x55" * 32
    wrapper = DeviceBoundKeyWrapper(inner, device_key)
    wrapped = wrapper.wrap(b"8" * 32)

    wrong_inner = RSAOAEPKeyWrapper(other_rsa_keypair_fixture.public_key, other_rsa_keypair_fixture.private_key)
    wrong_wrapper = DeviceBoundKeyWrapper(wrong_inner, device_key)
    with pytest.raises(KeyUnwrappingError):
        wrong_wrapper.unwrap(wrapped)


def test_device_bound_algorithm_name_reflects_inner(keypair):
    inner = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
    wrapper = DeviceBoundKeyWrapper(inner, b"\x66" * 32)

    assert wrapper.algorithm == "RSA-OAEP+DEVICE-BOUND-AES-GCM"
