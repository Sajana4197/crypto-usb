"""Tests for the portable metadata envelope format."""

import pytest

from metadata.exceptions import MetadataValidationError
from metadata.portable_envelope import FORMAT_VERSION, MAGIC, PortableMetadataEnvelope
from metadata.protection import ProtectedMetadata


def _sample_envelope() -> PortableMetadataEnvelope:
    return PortableMetadataEnvelope(
        salt=b"\x01" * 16,
        protected=ProtectedMetadata(
            file_id="file-1",
            metadata_version=1,
            nonce=b"\x02" * 12,
            ciphertext=b"ciphertext-bytes-here",
            hmac_tag=b"\x03" * 32,
        ),
    )


def test_serialize_starts_with_magic_and_version():
    data = _sample_envelope().serialize()
    assert data[:4] == MAGIC
    assert data[4] == FORMAT_VERSION


def test_serialize_deserialize_round_trip():
    envelope = _sample_envelope()
    restored = PortableMetadataEnvelope.deserialize(envelope.serialize())

    assert restored.salt == envelope.salt
    assert restored.protected == envelope.protected


def test_deserialize_rejects_bad_magic():
    data = b"XXXX" + _sample_envelope().serialize()[4:]
    with pytest.raises(MetadataValidationError):
        PortableMetadataEnvelope.deserialize(data)


def test_deserialize_rejects_unsupported_version():
    data = _sample_envelope().serialize()
    tampered = data[:4] + bytes([FORMAT_VERSION + 1]) + data[5:]
    with pytest.raises(MetadataValidationError):
        PortableMetadataEnvelope.deserialize(tampered)


def test_round_trip_preserves_empty_and_large_fields():
    envelope = PortableMetadataEnvelope(
        salt=b"\xff" * 32,
        protected=ProtectedMetadata(
            file_id="a-much-longer-file-identifier-1234567890",
            metadata_version=7,
            nonce=b"\x00" * 12,
            ciphertext=b"x" * 10_000,
            hmac_tag=b"\x09" * 32,
        ),
    )
    restored = PortableMetadataEnvelope.deserialize(envelope.serialize())
    assert restored == envelope
