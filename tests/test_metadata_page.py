"""Tests for the Metadata dashboard page."""

import sqlite3
from datetime import datetime, timezone

import pytest
from PySide6.QtWidgets import QApplication

from metadata.controller import MetadataController
from metadata.hashing import compute_integrity_hash
from metadata.models import DeviceBinding, ExpiryRules, UsagePolicy
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from ui.pages.metadata_page import MetadataPage


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def repository(connection):
    return MetadataRepository(connection)


@pytest.fixture
def protection_keys():
    return generate_protection_keys()


@pytest.fixture
def controller(repository, protection_keys):
    return MetadataController(repository, MetadataProtector(protection_keys))


def _make_page(app, metadata_repository=None, protection_keys=None):
    return MetadataPage(metadata_repository=metadata_repository, protection_keys=protection_keys)


def test_page_with_no_repository_shows_unavailable_message(app):
    page = _make_page(app)
    assert page.table.rowCount() == 0
    assert "no metadata repository" in page.summary_label.text().lower()


def test_page_with_empty_repository_shows_zero_records(app, repository, protection_keys):
    page = _make_page(app, repository, protection_keys)
    assert page.table.rowCount() == 0
    assert "0 record" in page.summary_label.text()


def test_page_shows_stored_metadata_record(app, controller, repository, protection_keys):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
    )

    page = _make_page(app, repository, protection_keys)

    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == "file-1"
    assert page.table.item(0, 1).text() == "owner-1"
    assert page.table.item(0, 3).text() == "0"  # access_count


def test_page_shows_one_time_access_and_device_binding_flags(app, controller, repository, protection_keys):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
        usage_policy=UsagePolicy(one_time_access=True),
        device_binding=DeviceBinding(bound=True, device_id="E:\\", usb_serial="ABCD"),
    )

    page = _make_page(app, repository, protection_keys)

    assert page.table.item(0, 4).text() == "Yes"  # one-time access
    assert page.table.item(0, 5).text() == "Yes"  # device bound


def test_page_shows_expiry_date_when_set(app, controller, repository, protection_keys):
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
        expiry_rules=ExpiryRules(expires_at=expires),
    )

    page = _make_page(app, repository, protection_keys)

    assert "2030-01-01" in page.table.item(0, 6).text()


def test_page_reports_tampered_records_without_crashing(app, repository, protection_keys, controller):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
    )
    protected = repository.load("file-1")
    tampered_tag = bytearray(protected.hmac_tag)
    tampered_tag[0] ^= 0xFF
    protected.hmac_tag = bytes(tampered_tag)
    repository.save(protected)

    page = _make_page(app, repository, protection_keys)  # must not raise

    assert page.table.rowCount() == 0
    assert "failed integrity check" in page.summary_label.text().lower()


def test_refresh_reflects_newly_created_records(app, controller, repository, protection_keys):
    page = _make_page(app, repository, protection_keys)
    assert page.table.rowCount() == 0

    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
    )
    page.refresh()

    assert page.table.rowCount() == 1


# -- Automatic polling --------------------------------------------------


def test_refresh_timer_is_running_after_construction(app, repository, protection_keys):
    page = _make_page(app, repository, protection_keys)

    assert page._refresh_timer.isActive() is True


def test_refresh_is_a_noop_when_records_are_unchanged(app, controller, repository, protection_keys, monkeypatch):
    controller.create(
        file_id="file-1",
        owner_id="owner-1",
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
    )
    page = _make_page(app, repository, protection_keys)

    calls = []
    monkeypatch.setattr(page, "_append_row", lambda *a, **k: calls.append(None))

    page.refresh()  # same record as construction -- nothing changed

    assert calls == []
