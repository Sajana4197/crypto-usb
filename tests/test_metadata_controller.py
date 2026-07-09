"""Tests for the Metadata Controller: create/read/update/policy/validation."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from metadata.controller import MetadataController
from metadata.exceptions import (
    MetadataNotFoundError,
    MetadataValidationError,
    PolicyViolationError,
)
from metadata.hashing import compute_integrity_hash
from metadata.models import ExpiryRules, UsagePolicy
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository

VALID_HASH = compute_integrity_hash(b"some encrypted file container bytes")


@pytest.fixture
def controller():
    conn = sqlite3.connect(":memory:")
    repository = MetadataRepository(conn)
    protector = MetadataProtector(generate_protection_keys())
    return MetadataController(repository, protector)


def test_create_and_read_round_trip(controller):
    created = controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
    )
    read_back = controller.read("file-1")

    assert read_back == created
    assert read_back.access_count == 0
    assert read_back.last_accessed_at is None


def test_read_missing_raises_not_found(controller):
    with pytest.raises(MetadataNotFoundError):
        controller.read("does-not-exist")


def test_update_changes_fields(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
    )
    updated = controller.update("file-1", owner_id="new-owner")
    assert updated.owner_id == "new-owner"
    assert controller.read("file-1").owner_id == "new-owner"


def test_update_unknown_field_raises_validation_error(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
    )
    with pytest.raises(MetadataValidationError):
        controller.update("file-1", not_a_real_field="x")


def test_record_access_increments_count_and_timestamp(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
    )
    result = controller.record_access("file-1")

    assert result.access_count == 1
    assert result.last_accessed_at is not None

    result2 = controller.record_access("file-1")
    assert result2.access_count == 2


def test_record_access_enforces_one_time_access_policy(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
        usage_policy=UsagePolicy(one_time_access=True),
    )
    controller.record_access("file-1")  # first access succeeds

    with pytest.raises(PolicyViolationError):
        controller.record_access("file-1")  # second access denied


def test_record_access_enforces_max_access_count(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
        expiry_rules=ExpiryRules(max_access_count=2),
    )
    controller.record_access("file-1")
    controller.record_access("file-1")

    with pytest.raises(PolicyViolationError):
        controller.record_access("file-1")


def test_record_access_enforces_expiry(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
        expiry_rules=ExpiryRules(expires_at=datetime.now(timezone.utc) - timedelta(days=1)),
    )
    with pytest.raises(PolicyViolationError):
        controller.record_access("file-1")


def test_enforce_policy_allows_access_within_limits(controller):
    metadata = controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
        expiry_rules=ExpiryRules(
            expires_at=datetime.now(timezone.utc) + timedelta(days=1), max_access_count=5
        ),
    )
    controller.enforce_policy(metadata)  # must not raise


def test_create_rejects_empty_owner_id(controller):
    with pytest.raises(MetadataValidationError):
        controller.create(
            file_id="file-1",
            owner_id="",
            wrapped_key=b"wrapped-fek",
            wrap_algorithm="RSA-OAEP",
            integrity_hash=VALID_HASH,
        )


def test_create_rejects_invalid_integrity_hash(controller):
    with pytest.raises(MetadataValidationError):
        controller.create(
            file_id="file-1",
            owner_id="owner-1",
            wrapped_key=b"wrapped-fek",
            wrap_algorithm="RSA-OAEP",
            integrity_hash="not-a-valid-hash",
        )


def test_create_rejects_empty_wrapped_key(controller):
    with pytest.raises(MetadataValidationError):
        controller.create(
            file_id="file-1",
            owner_id="owner-1",
            wrapped_key=b"",
            wrap_algorithm="RSA-OAEP",
            integrity_hash=VALID_HASH,
        )


def test_delete_removes_record(controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=VALID_HASH,
    )
    assert controller.delete("file-1") is True
    with pytest.raises(MetadataNotFoundError):
        controller.read("file-1")


def test_verify_file_integrity_true_for_matching_bytes(controller):
    file_bytes = b"some encrypted file container bytes"
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(file_bytes),
    )
    assert controller.verify_file_integrity("file-1", file_bytes) is True


def test_verify_file_integrity_false_for_tampered_bytes(controller):
    file_bytes = b"some encrypted file container bytes"
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped-fek",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(file_bytes),
    )
    assert controller.verify_file_integrity("file-1", b"tampered bytes") is False
