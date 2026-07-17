"""Tests for the SQLCipher file-encryption key (Phase 23)."""

from database.file_key import FILE_KEY_SIZE_BYTES, load_or_create_file_key


def test_creates_a_key_of_the_expected_size(tmp_path):
    key = load_or_create_file_key()

    assert isinstance(key, bytes)
    assert len(key) == FILE_KEY_SIZE_BYTES


def test_key_is_persisted_to_the_vault_key_path(tmp_path):
    from database.file_key import get_vault_key_path

    load_or_create_file_key()

    assert get_vault_key_path().exists()


def test_reusing_the_same_key_file_returns_the_same_key(tmp_path):
    first = load_or_create_file_key()
    second = load_or_create_file_key()

    assert first == second


def test_key_is_random_across_fresh_locations(tmp_path, monkeypatch):
    first = load_or_create_file_key()

    # A different vault key path is a different "installation" — must get
    # its own independently random key, not reuse the first.
    monkeypatch.setattr("database.file_key.get_vault_key_path", lambda: tmp_path / "other" / ".vault_key")
    (tmp_path / "other").mkdir()
    second = load_or_create_file_key()

    assert first != second
