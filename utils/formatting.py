"""Human-readable formatting helpers shared by UI pages."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

_SIZE_UNITS = ("B", "KB", "MB", "GB", "TB")


def format_file_size(size_bytes: int) -> str:
    """Render a byte count as a human-readable size, e.g. '12.4 MB'."""
    if size_bytes < 0:
        raise ValueError("size_bytes must not be negative")

    size = float(size_bytes)
    for unit in _SIZE_UNITS:
        if size < 1024.0 or unit == _SIZE_UNITS[-1]:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0


def format_datetime(dt: Optional[datetime]) -> str:
    """Render a datetime as 'YYYY-MM-DD HH:MM:SS' in the local timezone.

    Audit/tracking timestamps are stored as UTC-aware `datetime`s (see
    `datetime.now(timezone.utc)` throughout `security`/`deception`/
    `tracking`) — correct for unambiguous storage, but every UI page that
    displayed one directly with `isoformat()` showed raw UTC with a
    `+00:00` suffix, which doesn't match the viewer's wall clock. `
    `.astimezone()` with no argument converts an aware datetime to the
    system's local timezone; called on a naive datetime (e.g. a file's
    on-disk modified-time from `os.path.getmtime`), Python treats it as
    already local and this is a no-op, so this is safe for both callers.
    """
    if dt is None:
        return "—"
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
