"""Tests for the Sender Module's file queue and validation logic."""

from pathlib import Path

from core.file_queue import FileQueue, FileValidator


def _make_file(tmp_path: Path, name: str, content: bytes = b"hello") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


# -- FileValidator ---------------------------------------------------------


def test_validate_missing_file(tmp_path):
    is_valid, message = FileValidator.validate(tmp_path / "missing.txt")
    assert is_valid is False
    assert "does not exist" in message


def test_validate_directory(tmp_path):
    is_valid, message = FileValidator.validate(tmp_path)
    assert is_valid is False
    assert "directory" in message


def test_validate_empty_file(tmp_path):
    empty = _make_file(tmp_path, "empty.txt", b"")
    is_valid, message = FileValidator.validate(empty)
    assert is_valid is False
    assert "empty" in message


def test_validate_valid_file(tmp_path):
    valid_file = _make_file(tmp_path, "document.txt")
    is_valid, message = FileValidator.validate(valid_file)
    assert is_valid is True
    assert message == "Valid"


def test_validate_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr("core.file_queue.MAX_QUEUE_FILE_SIZE_BYTES", 4)
    oversized = _make_file(tmp_path, "big.bin", b"too many bytes")
    is_valid, message = FileValidator.validate(oversized)
    assert is_valid is False
    assert "maximum allowed size" in message


# -- FileQueue ---------------------------------------------------------


def test_add_paths_returns_added_entries(tmp_path):
    file_a = _make_file(tmp_path, "a.txt")
    file_b = _make_file(tmp_path, "b.txt")

    queue = FileQueue()
    added, duplicates = queue.add_paths([str(file_a), str(file_b)])

    assert len(added) == 2
    assert duplicates == []
    assert queue.count == 2
    assert queue.valid_count == 2
    assert queue.invalid_count == 0


def test_add_paths_flags_invalid_files(tmp_path):
    invalid_file = _make_file(tmp_path, "empty.txt", b"")

    queue = FileQueue()
    added, _ = queue.add_paths([str(invalid_file)])

    assert added[0].is_valid is False
    assert queue.valid_count == 0
    assert queue.invalid_count == 1


def test_add_paths_skips_duplicates(tmp_path):
    file_a = _make_file(tmp_path, "a.txt")

    queue = FileQueue()
    queue.add_paths([str(file_a)])
    added, duplicates = queue.add_paths([str(file_a)])

    assert added == []
    assert len(duplicates) == 1
    assert queue.count == 1


def test_remove_file(tmp_path):
    file_a = _make_file(tmp_path, "a.txt")
    queue = FileQueue()
    queue.add_paths([str(file_a)])
    key = queue.items[0].key

    assert queue.remove(key) is True
    assert queue.count == 0
    assert queue.remove(key) is False


def test_clear(tmp_path):
    file_a = _make_file(tmp_path, "a.txt")
    file_b = _make_file(tmp_path, "b.txt")
    queue = FileQueue()
    queue.add_paths([str(file_a), str(file_b)])

    queue.clear()
    assert queue.count == 0


def test_total_size_bytes(tmp_path):
    file_a = _make_file(tmp_path, "a.txt", b"1234567890")  # 10 bytes
    file_b = _make_file(tmp_path, "b.txt", b"12345")  # 5 bytes

    queue = FileQueue()
    queue.add_paths([str(file_a), str(file_b)])

    assert queue.total_size_bytes == 15


def test_revalidate_all_detects_deleted_file(tmp_path):
    file_a = _make_file(tmp_path, "a.txt")
    queue = FileQueue()
    queue.add_paths([str(file_a)])
    assert queue.items[0].is_valid is True

    file_a.unlink()
    queue.revalidate_all()

    assert queue.items[0].is_valid is False
    assert "does not exist" in queue.items[0].message
