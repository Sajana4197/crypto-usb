"""Tests for human-readable formatting helpers."""

from datetime import datetime

import pytest

from utils.formatting import format_datetime, format_file_size


@pytest.mark.parametrize(
    "size_bytes, expected",
    [
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1024 * 1024, "1.0 MB"),
        (1024 * 1024 * 1024, "1.0 GB"),
        (1024 ** 4, "1.0 TB"),
    ],
)
def test_format_file_size(size_bytes, expected):
    assert format_file_size(size_bytes) == expected


def test_format_file_size_rejects_negative():
    with pytest.raises(ValueError):
        format_file_size(-1)


def test_format_datetime():
    dt = datetime(2026, 7, 9, 13, 45, 30)
    assert format_datetime(dt) == "2026-07-09 13:45:30"
