"""Tests for human-readable formatting helpers."""

from datetime import datetime, timezone

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


def test_format_datetime_converts_utc_to_local():
    # A UTC-aware datetime (how every audit/tracking timestamp in this
    # project is actually stored) must display in the viewer's local
    # timezone, not raw UTC — computed relative to whatever timezone this
    # test happens to run in, so it isn't tied to one offset.
    dt = datetime(2026, 7, 19, 18, 6, 14, tzinfo=timezone.utc)
    expected = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    assert format_datetime(dt) == expected


def test_format_datetime_none_returns_placeholder():
    assert format_datetime(None) == "—"
