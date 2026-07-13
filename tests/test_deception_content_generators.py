"""Tests for the individual fake-content generators."""

import json
import random
import struct
import zlib

import pytest

from deception.content_generators import (
    generate_corrupted_data,
    generate_fake_image,
    generate_fake_metadata,
    generate_fake_pdf,
    generate_fake_text,
)

FORBIDDEN_PHRASES = ["access denied", "authentication failed", "unauthorized access"]


def _rng():
    return random.Random(1234)


# -- Fake text -------------------------------------------------------------


def test_fake_text_is_nonempty_utf8():
    text = generate_fake_text(_rng())
    decoded = text.decode("utf-8")
    assert len(decoded.strip()) > 0


def test_fake_text_varies_with_seed():
    text_a = generate_fake_text(random.Random(1))
    text_b = generate_fake_text(random.Random(2))
    assert text_a != text_b


def test_fake_text_deterministic_for_same_seed():
    text_a = generate_fake_text(random.Random(42))
    text_b = generate_fake_text(random.Random(42))
    assert text_a == text_b


def test_fake_text_contains_no_denial_language():
    lowered = generate_fake_text(_rng()).decode("utf-8").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lowered


# -- Fake PDF ----------------------------------------------------------------


def test_fake_pdf_has_valid_header_and_trailer():
    pdf = generate_fake_pdf(_rng())
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")


def test_fake_pdf_object_structure_is_well_formed():
    pdf = generate_fake_pdf(_rng())
    assert pdf.count(b" 0 obj") == pdf.count(b"endobj")
    assert b"xref" in pdf
    assert b"/Root 1 0 R" in pdf


def test_fake_pdf_contains_no_denial_language():
    pdf_text = generate_fake_pdf(_rng()).decode("latin-1").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in pdf_text


# -- Fake image ----------------------------------------------------------


def test_fake_image_is_valid_png_signature():
    image = generate_fake_image(_rng())
    assert image.startswith(b"\x89PNG\r\n\x1a\n")


def test_fake_image_idat_decompresses_to_expected_size():
    width, height = 32, 16
    image = generate_fake_image(_rng(), width=width, height=height)

    pos = 8
    chunks = {}
    while pos < len(image):
        (length,) = struct.unpack(">I", image[pos : pos + 4])
        tag = image[pos + 4 : pos + 8]
        data = image[pos + 8 : pos + 8 + length]
        chunks[tag] = data
        pos += 8 + length + 4  # length + tag + data + crc

    assert b"IHDR" in chunks
    assert b"IDAT" in chunks
    assert b"IEND" in chunks

    raw = zlib.decompress(chunks[b"IDAT"])
    # one filter-type byte + 3 bytes/pixel (RGB) per scanline
    assert len(raw) == height * (1 + width * 3)


# -- Corrupted data --------------------------------------------------------


def test_corrupted_data_has_requested_size():
    data = generate_corrupted_data(_rng(), size=256)
    assert len(data) == 256


def test_corrupted_data_is_not_valid_utf8():
    data = generate_corrupted_data(random.Random(7), size=256)
    with pytest.raises(UnicodeDecodeError):
        data.decode("utf-8")


def test_corrupted_data_varies_with_seed():
    data_a = generate_corrupted_data(random.Random(1), size=128)
    data_b = generate_corrupted_data(random.Random(2), size=128)
    assert data_a != data_b


# -- Fake metadata ---------------------------------------------------------


def test_fake_metadata_is_valid_json_shaped_like_real_metadata():
    raw = generate_fake_metadata(_rng(), file_id="file-1")
    payload = json.loads(raw)

    for key in [
        "file_id",
        "owner_id",
        "wrapped_key",
        "wrap_algorithm",
        "integrity_hash",
        "created_at",
        "access_count",
        "expiry_rules",
        "device_binding",
        "usage_policy",
        "metadata_version",
    ]:
        assert key in payload


def test_fake_metadata_uses_requested_file_id():
    payload = json.loads(generate_fake_metadata(_rng(), file_id="real-file-id"))
    assert payload["file_id"] == "real-file-id"


def test_fake_metadata_generates_random_file_id_when_absent():
    payload_a = json.loads(generate_fake_metadata(random.Random(1)))
    payload_b = json.loads(generate_fake_metadata(random.Random(2)))
    assert payload_a["file_id"] != payload_b["file_id"]


def test_fake_metadata_contains_no_denial_language():
    lowered = generate_fake_metadata(_rng()).decode("utf-8").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lowered
