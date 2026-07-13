"""The kinds of fake content the Deception Engine can hand back."""

from __future__ import annotations

from enum import Enum


class DeceptionContentType(str, Enum):
    FAKE_TEXT = "fake_text"
    FAKE_PDF = "fake_pdf"
    FAKE_IMAGE = "fake_image"
    CORRUPTED_DATA = "corrupted_data"
    FAKE_METADATA = "fake_metadata"


MIME_TYPES: dict[DeceptionContentType, str] = {
    DeceptionContentType.FAKE_TEXT: "text/plain",
    DeceptionContentType.FAKE_PDF: "application/pdf",
    DeceptionContentType.FAKE_IMAGE: "image/png",
    DeceptionContentType.CORRUPTED_DATA: "application/octet-stream",
    DeceptionContentType.FAKE_METADATA: "application/json",
}
