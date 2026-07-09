"""Tests for encrypted, HMAC-protected metadata envelopes."""

from datetime import datetime, timezone

import pytest

from metadata.exceptions import MetadataTamperError
from metadata.models import FileMetadata
from metadata.protection import MetadataProtector, generate_protection_keys


def _sample_metadata(file_id: str = "file-1") -> FileMetadata:
    return FileMetadata(
        file_id=file_id,
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek-bytes",
        wrap_algorithm="RSA-OAEP",
        integrity_hash="c" * 64,
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def protector():
    return MetadataProtector(generate_protection_keys())


def test_generate_protection_keys_are_32_bytes_each():
    keys = generate_protection_keys()
    assert len(keys.encryption_key) == 32
    assert len(keys.hmac_key) == 32


def test_protect_unprotect_round_trip(protector):
    metadata = _sample_metadata()
    protected = protector.protect(metadata)
    restored = protector.unprotect(protected)
    assert restored == metadata


def test_protected_ciphertext_has_no_plaintext(protector):
    metadata = _sample_metadata()
    metadata.usage_policy.notes = "UNMISTAKABLE_PLAINTEXT_MARKER"
    protected = protector.protect(metadata)
    assert b"UNMISTAKABLE_PLAINTEXT_MARKER" not in protected.ciphertext


def test_tampered_ciphertext_raises_tamper_error(protector):
    protected = protector.protect(_sample_metadata())
    tampered_ciphertext = bytearray(protected.ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    protected.ciphertext = bytes(tampered_ciphertext)

    with pytest.raises(MetadataTamperError):
        protector.unprotect(protected)


def test_tampered_hmac_tag_raises_tamper_error(protector):
    protected = protector.protect(_sample_metadata())
    tampered_tag = bytearray(protected.hmac_tag)
    tampered_tag[0] ^= 0xFF
    protected.hmac_tag = bytes(tampered_tag)

    with pytest.raises(MetadataTamperError):
        protector.unprotect(protected)


def test_tampered_file_id_raises_tamper_error(protector):
    protected = protector.protect(_sample_metadata())
    protected.file_id = "different-file-id"

    with pytest.raises(MetadataTamperError):
        protector.unprotect(protected)


def test_wrong_hmac_key_raises_tamper_error():
    keys = generate_protection_keys()
    protector = MetadataProtector(keys)
    protected = protector.protect(_sample_metadata())

    wrong_keys = generate_protection_keys()
    wrong_keys.encryption_key = keys.encryption_key  # only the HMAC key differs
    wrong_protector = MetadataProtector(wrong_keys)

    with pytest.raises(MetadataTamperError):
        wrong_protector.unprotect(protected)


def test_wrong_encryption_key_raises_tamper_error():
    keys = generate_protection_keys()
    protector = MetadataProtector(keys)
    protected = protector.protect(_sample_metadata())

    wrong_keys = generate_protection_keys()
    wrong_keys.hmac_key = keys.hmac_key  # HMAC passes, decryption must fail
    wrong_protector = MetadataProtector(wrong_keys)

    with pytest.raises(MetadataTamperError):
        wrong_protector.unprotect(protected)
