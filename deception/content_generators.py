"""Generators that produce believable fake content.

Every generator takes a `random.Random` so callers (and tests) can get
deterministic output by passing a seeded instance, and none of them
accept or embed the reason access was denied — the whole point of the
Deception Engine is that a rejected caller sees plausible-looking data,
never a hint that anything was checked at all.
"""

from __future__ import annotations

import json
import struct
import zlib
from datetime import datetime, timezone
from random import Random
from typing import Optional

_TITLES = [
    "Quarterly Financial Summary",
    "Project Status Report",
    "Internal Memorandum",
    "Meeting Minutes",
    "Research Notes",
    "Client Proposal Draft",
    "Inventory Reconciliation",
]

_SENTENCES = [
    "The team reviewed progress against the current milestones.",
    "Budget allocations remain within the approved range for this period.",
    "Further analysis is required before the next stakeholder review.",
    "Action items were assigned to the relevant department leads.",
    "The revised timeline reflects updated resourcing constraints.",
    "Preliminary results are consistent with expectations from last quarter.",
    "A follow-up meeting has been scheduled to address open questions.",
    "Supporting documentation is attached for reference purposes.",
    "The proposed changes were approved pending final sign-off.",
    "Data collection is ongoing and will be summarized next cycle.",
    "No significant risks were identified during this review period.",
    "The working group will reconvene once feedback has been incorporated.",
]

def generate_fake_text(rng: Random) -> bytes:
    """A short, plausible-looking plaintext document."""
    title = rng.choice(_TITLES)
    paragraph_count = rng.randint(2, 4)
    paragraphs = []
    for _ in range(paragraph_count):
        sentence_count = min(rng.randint(3, 6), len(_SENTENCES))
        sentences = rng.sample(_SENTENCES, k=sentence_count)
        paragraphs.append(" ".join(sentences))
    body = "\n\n".join(paragraphs)
    text = f"{title}\n{'=' * len(title)}\n\n{body}\n"
    return text.encode("utf-8")


def generate_fake_pdf(rng: Random) -> bytes:
    """A structurally valid, minimal single-page PDF containing fake text."""
    text = generate_fake_text(rng).decode("utf-8")
    lines = text.splitlines()[:24]

    content_lines = ["BT", "/F1 11 Tf", "50 750 Td", "14 TL"]
    for line in lines:
        escaped = line.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        content_lines.append(f"({escaped}) Tj T*")
    content_lines.append("ET")
    content_stream = "\n".join(content_lines).encode("utf-8")

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        b"5 0 obj\n<< /Length %d >>\nstream\n" % len(content_stream)
        + content_stream
        + b"\nendstream\nendobj\n",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj

    xref_offset = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode("ascii")
    pdf += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF"
    ).encode("ascii")
    return bytes(pdf)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def generate_fake_image(rng: Random, width: int = 64, height: int = 64) -> bytes:
    """A structurally valid PNG: a faint grayscale gradient with noise,
    plausible as a corrupted or low-quality scan."""
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB

    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type 0 (none) for this scanline
        base = int(255 * (y / max(height - 1, 1)))
        for _x in range(width):
            jitter = rng.randint(-20, 20)
            value = max(0, min(255, base + jitter))
            raw.extend((value, value, value))

    compressed = zlib.compress(bytes(raw), level=6)
    return (
        signature
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", compressed)
        + _png_chunk(b"IEND", b"")
    )


def generate_corrupted_data(rng: Random, size: int = 512) -> bytes:
    """Binary noise with a few fragments of legible text spliced in —
    plausible as the result of decrypting with the wrong key."""
    size = max(size, 32)
    corrupted = bytearray(rng.randbytes(size))
    fragment_source = generate_fake_text(rng)

    for _ in range(rng.randint(2, 4)):
        frag_len = rng.randint(4, min(16, len(fragment_source)))
        frag_start = rng.randint(0, len(fragment_source) - frag_len)
        fragment = fragment_source[frag_start : frag_start + frag_len]
        pos = rng.randint(0, len(corrupted) - frag_len)
        corrupted[pos : pos + frag_len] = fragment

    return bytes(corrupted)


def generate_fake_metadata(rng: Random, file_id: Optional[str] = None) -> bytes:
    """A JSON document shaped like `metadata.models.FileMetadata.to_dict()`,
    populated entirely with fabricated values."""
    now = datetime.now(timezone.utc)
    payload = {
        "file_id": file_id or f"file-{rng.getrandbits(32):08x}",
        "owner_id": f"user-{rng.getrandbits(16):04x}",
        "wrapped_key": rng.randbytes(24).hex(),
        "wrap_algorithm": "RSA-OAEP",
        "integrity_hash": rng.randbytes(32).hex(),
        "created_at": now.isoformat(),
        "last_accessed_at": now.isoformat(),
        "access_count": rng.randint(0, 5),
        "expiry_rules": {"expires_at": None, "max_access_count": None},
        "device_binding": {
            "device_id": None,
            "label": None,
            "bound": False,
            "usb_serial": None,
            "machine_fingerprint": None,
        },
        "usage_policy": {
            "one_time_access": False,
            "allow_multiple_devices": True,
            "notes": None,
        },
        "metadata_version": 1,
    }
    return json.dumps(payload, indent=2).encode("utf-8")
