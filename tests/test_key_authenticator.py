"""Tests for RSA-PSS challenge/response private-key authentication."""

from unittest.mock import patch

import pytest

from crypto import rsa_keypair
from security.key_authenticator import KeyAuthenticator, generate_challenge

PASSPHRASE = b"a-strong-passphrase"


@pytest.fixture
def encrypted_private_pem(rsa_keypair_fixture):
    return rsa_keypair.serialize_private_key(rsa_keypair_fixture.private_key, PASSPHRASE)


@pytest.fixture
def public_pem(rsa_keypair_fixture):
    return rsa_keypair.serialize_public_key(rsa_keypair_fixture.public_key)


def test_authenticate_succeeds_with_matching_key(encrypted_private_pem, public_pem):
    challenge = generate_challenge()
    assert KeyAuthenticator().authenticate(encrypted_private_pem, PASSPHRASE, public_pem, challenge) is True


def test_authenticate_fails_with_wrong_passphrase(encrypted_private_pem, public_pem):
    challenge = generate_challenge()
    assert (
        KeyAuthenticator().authenticate(encrypted_private_pem, b"wrong-passphrase", public_pem, challenge)
        is False
    )


def test_authenticate_fails_with_non_enrolled_public_key(
    encrypted_private_pem, other_rsa_keypair_fixture
):
    other_public_pem = rsa_keypair.serialize_public_key(other_rsa_keypair_fixture.public_key)
    challenge = generate_challenge()

    assert (
        KeyAuthenticator().authenticate(encrypted_private_pem, PASSPHRASE, other_public_pem, challenge)
        is False
    )


def test_authenticate_fails_with_wrong_private_key(public_pem, other_rsa_keypair_fixture):
    # Correct passphrase, but a private key that does not pair with the enrolled public key.
    wrong_private_pem = rsa_keypair.serialize_private_key(other_rsa_keypair_fixture.private_key, PASSPHRASE)
    challenge = generate_challenge()

    assert KeyAuthenticator().authenticate(wrong_private_pem, PASSPHRASE, public_pem, challenge) is False


def test_authenticate_fails_with_malformed_private_key_pem(public_pem):
    challenge = generate_challenge()
    assert KeyAuthenticator().authenticate(b"not a valid pem", PASSPHRASE, public_pem, challenge) is False


def test_generate_challenge_is_random_and_correct_size():
    a = generate_challenge()
    b = generate_challenge()

    assert a != b
    assert len(a) == 32


# -- Secure cleanup: temporary PEM/passphrase buffers are always wiped -----


def test_successful_authenticate_wipes_pem_and_passphrase_buffers(encrypted_private_pem, public_pem):
    challenge = generate_challenge()
    with patch("security.key_authenticator.wipe") as mock_wipe:
        assert KeyAuthenticator().authenticate(encrypted_private_pem, PASSPHRASE, public_pem, challenge) is True

    assert mock_wipe.call_count == 2
    wiped_args = [call.args[0] for call in mock_wipe.call_args_list]
    assert bytearray(encrypted_private_pem) in wiped_args
    assert bytearray(PASSPHRASE) in wiped_args


def test_failed_authenticate_still_wipes_pem_and_passphrase_buffers(encrypted_private_pem, public_pem):
    challenge = generate_challenge()
    with patch("security.key_authenticator.wipe") as mock_wipe:
        assert (
            KeyAuthenticator().authenticate(encrypted_private_pem, b"wrong-passphrase", public_pem, challenge)
            is False
        )

    assert mock_wipe.call_count == 2


def test_malformed_pem_still_wipes_buffers_before_returning(public_pem):
    challenge = generate_challenge()
    with patch("security.key_authenticator.wipe") as mock_wipe:
        assert KeyAuthenticator().authenticate(b"not a valid pem", PASSPHRASE, public_pem, challenge) is False

    assert mock_wipe.call_count == 2


def test_authenticate_actually_zeroes_the_buffers_it_holds(encrypted_private_pem, public_pem):
    # No mocking here: verify the real `wipe()` zeroed the internal copies
    # by inspecting the bytearray objects passed to it.
    captured = []
    original_wipe = pytest.importorskip("crypto.secure_cleanup").wipe

    def _spy(obj):
        result = original_wipe(obj)
        captured.append(bytes(obj) if isinstance(obj, (bytes, bytearray)) else obj)
        return result

    challenge = generate_challenge()
    with patch("security.key_authenticator.wipe", side_effect=_spy):
        KeyAuthenticator().authenticate(encrypted_private_pem, PASSPHRASE, public_pem, challenge)

    assert len(captured) == 2
    assert all(all(b == 0 for b in buf) for buf in captured)
