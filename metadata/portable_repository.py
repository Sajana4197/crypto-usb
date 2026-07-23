"""`MetadataRepository`-shaped adapter over a `.cusc` container's
embedded portable metadata section.

Gives `validation.validation_engine.ValidationEngine`,
`metadata.controller.MetadataController`, and
`metadata.one_time_access.OneTimeAccessEnforcer` — all written against
`metadata.repository.MetadataRepository`'s `.load()`/`.save()` surface
— something to read (and, for a one-time-access burn, write back)
without ever touching SQLite. `.load()` only ever knows about the one
file_id its container's portable-metadata section was created for;
`.save()` rewrites the section in place and atomically overwrites the
same `.cusc` file on disk, keeping the salt (needed to re-derive its
protection keys later) and the file's own encrypted content/local
metadata untouched — only the portable-metadata section changes — so a
burn made through this repository is visible to the next machine that
reads the same USB-resident file, not just for the rest of this
in-memory session.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from metadata.portable_envelope import PortableMetadataEnvelope
from metadata.protection import ProtectedMetadata
from usb.secure_container import SecureContainer
from usb.storage_writer import SecureStorageWriter

logger = get_logger(__name__)


class PortableMetadataRepository:
    """`MetadataRepository`-compatible (`.load`/`.save`) wrapper around
    one `.cusc` container's embedded portable-metadata section. Never
    opens or requires a local database."""

    def __init__(
        self,
        container: SecureContainer,
        path: Path,
        writer: Optional[SecureStorageWriter] = None,
    ) -> None:
        self._container = container
        self._path = Path(path)
        self._writer = writer or SecureStorageWriter()

    def load(self, file_id: str) -> Optional[ProtectedMetadata]:
        envelope = self._container.portable_metadata
        if envelope is None or envelope.protected.file_id != file_id:
            return None
        return envelope.protected

    def save(self, protected: ProtectedMetadata) -> None:
        existing = self._container.portable_metadata
        assert existing is not None  # `save` is only ever called after a successful `load`
        new_envelope = PortableMetadataEnvelope(salt=existing.salt, protected=protected)
        self._container = replace(self._container, portable_metadata=new_envelope)
        self._writer.rewrite_container_in_place(self._container, self._path)
        logger.info("Updated embedded portable metadata at %s for file_id=%s", self._path, protected.file_id)
