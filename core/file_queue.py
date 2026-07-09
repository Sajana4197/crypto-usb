"""Sender module core logic: file selection queue and validation.

Pure Python, independent of the UI, so it can be exercised directly by
tests. `ui/pages/encryption_page.py` is the Qt front-end for this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.constants import MAX_QUEUE_FILE_SIZE_BYTES
from core.logger import get_logger
from utils.formatting import format_datetime, format_file_size

logger = get_logger(__name__)


@dataclass
class QueuedFile:
    """A single file that has been added to the sender queue."""

    path: Path
    size_bytes: int
    modified: datetime
    is_valid: bool
    message: str

    @property
    def key(self) -> str:
        return str(self.path)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def extension(self) -> str:
        suffix = self.path.suffix.lstrip(".")
        return suffix.upper() if suffix else "—"

    @property
    def size_display(self) -> str:
        return format_file_size(self.size_bytes)

    @property
    def modified_display(self) -> str:
        return format_datetime(self.modified)


class FileValidator:
    """Validates that a file is a genuine, readable, non-empty candidate for encryption."""

    @staticmethod
    def validate(path: Path) -> tuple[bool, str]:
        if not path.exists():
            return False, "File does not exist"

        if path.is_dir():
            return False, "Path is a directory, not a file"

        try:
            size = path.stat().st_size
        except OSError as exc:
            return False, f"Unable to read file metadata: {exc.strerror or exc}"

        if size == 0:
            return False, "File is empty"

        if size > MAX_QUEUE_FILE_SIZE_BYTES:
            limit = format_file_size(MAX_QUEUE_FILE_SIZE_BYTES)
            return False, f"File exceeds the maximum allowed size of {limit}"

        try:
            with open(path, "rb") as fh:
                fh.read(1)
        except OSError as exc:
            return False, f"File is not readable: {exc.strerror or exc}"

        return True, "Valid"


class FileQueue:
    """Holds the set of files queued by the user, keyed by resolved path."""

    def __init__(self) -> None:
        self._items: dict[str, QueuedFile] = {}

    def _build_entry(self, path: Path) -> QueuedFile:
        is_valid, message = FileValidator.validate(path)
        try:
            stat = path.stat()
            size_bytes = stat.st_size
            modified = datetime.fromtimestamp(stat.st_mtime)
        except OSError:
            size_bytes = 0
            modified = datetime.now()
        return QueuedFile(
            path=path,
            size_bytes=size_bytes,
            modified=modified,
            is_valid=is_valid,
            message=message,
        )

    def add_paths(self, paths: list[str]) -> tuple[list[QueuedFile], list[str]]:
        """Add new files to the queue.

        Returns (added, duplicates) where `duplicates` lists paths that were
        already present in the queue and therefore skipped.
        """
        added: list[QueuedFile] = []
        duplicates: list[str] = []

        for raw_path in paths:
            path = Path(raw_path).resolve()
            key = str(path)
            if key in self._items:
                duplicates.append(key)
                continue
            entry = self._build_entry(path)
            self._items[key] = entry
            added.append(entry)
            logger.info("Queued file %s (valid=%s)", key, entry.is_valid)

        return added, duplicates

    def remove(self, key: str) -> bool:
        removed = self._items.pop(key, None)
        if removed is not None:
            logger.info("Removed file from queue: %s", key)
            return True
        return False

    def clear(self) -> None:
        self._items.clear()
        logger.info("Cleared file queue")

    def revalidate_all(self) -> None:
        """Re-check every queued file against disk (files may have moved/changed)."""
        for key, item in list(self._items.items()):
            self._items[key] = self._build_entry(item.path)

    @property
    def items(self) -> list[QueuedFile]:
        return list(self._items.values())

    @property
    def count(self) -> int:
        return len(self._items)

    @property
    def valid_count(self) -> int:
        return sum(1 for item in self._items.values() if item.is_valid)

    @property
    def invalid_count(self) -> int:
        return self.count - self.valid_count

    @property
    def total_size_bytes(self) -> int:
        return sum(item.size_bytes for item in self._items.values())
