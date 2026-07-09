"""Human-readable formatting helpers shared by UI pages."""

from __future__ import annotations

from datetime import datetime

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


def format_datetime(dt: datetime) -> str:
    """Render a datetime as 'YYYY-MM-DD HH:MM:SS'."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")
