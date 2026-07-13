"""Tests for `OneTimeAccessEnforcer.burn` — the cryptographic-shredding
core of One-Time Access Enforcement."""

import logging
import sqlite3

import pytest

from crypto import aes_cipher
from crypto.exceptions import DecryptionError
from crypto.file_encryptor import FileEncryptor
from crypto.key_wrapper import RSAOAEPKeyWrapper
from metadata.controller import MetadataController
from metadata.exceptions import MetadataTamperError
from metadata.hashing import compute_integrity_hash
from metadata.models import UsagePolicy
from metadata.one_time_access import OneTimeAccessEnforcer
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository

PLAINTEXT = b"the one and only viewing of this content"


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return MetadataRepository(connection)


@pytest.fixture
def session_keys():
    return generate_protection_keys()


@pytest.fixture
def controller(repository, session_keys):
    return MetadataController(repository, MetadataProtector(session_keys))


@pytest.fixture
def wrapper(rsa_keypair_fixture):
    return RSAOAEPKeyWrapper(rsa_keypair_fixture.public_key, rsa_keypair_fixture.private_key)


@pytest.fixture
def container(wrapper):
    return FileEncryptor().encrypt_bytes(PLAINTEXT, wrapper)


@pytest.fixture
def one_time_metadata(controller, container):
    integrity_hash = compute_integrity_hash(container.serialize())
    return controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
        usage_policy=UsagePolicy(one_time_access=True),
    )


@pytest.fixture
def reusable_metadata(controller, container):
    integrity_hash = compute_integrity_hash(container.serialize())
    return controller.create(
        file_id="file-2",
        owner_id="owner-1",
        wrapped_key=container.wrapped_key,
        wrap_algorithm=container.wrap_algorithm,
        integrity_hash=integrity_hash,
        usage_policy=UsagePolicy(one_time_access=False),
    )


@pytest.fixture
def enforcer(repository):
    return OneTimeAccessEnforcer(repository)


# -- Required Phase 12 effects ---------------------------------------------


def test_burn_resets_access_count_to_zero(enforcer, one_time_metadata, wrapper, session_keys):
    one_time_metadata.access_count = 5

    enforcer.burn(one_time_metadata, wrapper, session_keys)

    assert one_time_metadata.access_count == 0


def test_burn_replaces_the_wrapped_key(enforcer, one_time_metadata, wrapper, session_keys, container):
    original_wrapped_key = one_time_metadata.wrapped_key

    enforcer.burn(one_time_metadata, wrapper, session_keys)

    assert one_time_metadata.wrapped_key != original_wrapped_key
    assert one_time_metadata.wrapped_key != container.wrapped_key


def test_burned_key_cannot_decrypt_the_original_ciphertext(
    enforcer, one_time_metadata, wrapper, session_keys, container
):
    """The core crypto-shredding property: even unwrapped with the same
    key_wrapper (same RSA key pair) the decoy key does not decrypt the
    real ciphertext — proof this isn't just a policy flag."""
    enforcer.burn(one_time_metadata, wrapper, session_keys)

    decoy_fek_material = wrapper.unwrap(one_time_metadata.wrapped_key)
    with pytest.raises(DecryptionError):
        aes_cipher.decrypt(container.nonce, container.ciphertext, decoy_fek_material)


def test_burn_saves_metadata_under_fresh_protection_keys(
    enforcer, repository, one_time_metadata, wrapper, session_keys
):
    new_keys = enforcer.burn(one_time_metadata, wrapper, session_keys)

    stored = repository.load("file-1")
    assert new_keys.encryption_key != session_keys.encryption_key
    assert new_keys.hmac_key != session_keys.hmac_key

    # The old ("session") keys can no longer open the record at all.
    with pytest.raises(MetadataTamperError):
        MetadataProtector(session_keys).unprotect(stored)

    # The new keys returned by burn() can.
    reopened = MetadataProtector(new_keys).unprotect(stored)
    assert reopened.file_id == "file-1"
    assert reopened.access_count == 0


def test_burn_logs_a_warning(enforcer, one_time_metadata, wrapper, session_keys, caplog):
    with caplog.at_level(logging.WARNING, logger="metadata.one_time_access"):
        enforcer.burn(one_time_metadata, wrapper, session_keys)

    assert any("consumed" in record.getMessage() for record in caplog.records)


def test_burn_refuses_a_file_not_marked_for_one_time_access(
    enforcer, reusable_metadata, wrapper, session_keys
):
    with pytest.raises(ValueError):
        enforcer.burn(reusable_metadata, wrapper, session_keys)


def test_burn_does_not_touch_the_original_container_bytes(
    enforcer, one_time_metadata, wrapper, session_keys, container
):
    """Burning must never require rewriting the file's ciphertext on disk."""
    original_ciphertext = container.ciphertext
    original_nonce = container.nonce

    enforcer.burn(one_time_metadata, wrapper, session_keys)

    assert container.ciphertext == original_ciphertext
    assert container.nonce == original_nonce
