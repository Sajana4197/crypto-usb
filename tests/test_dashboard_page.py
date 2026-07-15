"""Tests for the live Dashboard page (Phase 19)."""

import sqlite3
from datetime import datetime, timezone

import pytest
from PySide6.QtWidgets import QApplication

from deception.content_types import DeceptionContentType
from deception.event_repository import DeceptionEventRepository
from deception.triggers import DeceptionTrigger
from metadata.controller import MetadataController
from metadata.hashing import compute_integrity_hash
from metadata.protection import MetadataProtector, generate_protection_keys
from metadata.repository import MetadataRepository
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import generate_tracking_keys
from tracking.tracking_service import UsageTracker
from ui.pages.dashboard_page import DashboardPage


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def metadata_repository(connection):
    return MetadataRepository(connection)


@pytest.fixture
def protection_keys():
    return generate_protection_keys()


@pytest.fixture
def metadata_controller(metadata_repository, protection_keys):
    return MetadataController(metadata_repository, MetadataProtector(protection_keys))


@pytest.fixture
def account_repository(connection):
    return AccountRepository(connection)


@pytest.fixture
def auth_controller(account_repository):
    return AuthController(account_repository)


@pytest.fixture
def deception_event_repository(connection):
    return DeceptionEventRepository(connection)


@pytest.fixture
def usage_tracker(connection):
    return UsageTracker(generate_tracking_keys(), TrackingRepository(connection))


def _make_page(
    app,
    metadata_repository=None,
    account_repository=None,
    deception_event_repository=None,
    usage_tracker=None,
):
    return DashboardPage(
        metadata_repository=metadata_repository,
        account_repository=account_repository,
        deception_event_repository=deception_event_repository,
        usage_tracker=usage_tracker,
    )


def _create_metadata_record(metadata_controller, file_id="file-1", owner_id="owner-1"):
    metadata_controller.create(
        file_id=file_id,
        owner_id=owner_id,
        wrapped_key=b"wrapped",
        wrap_algorithm="RSA-OAEP",
        integrity_hash=compute_integrity_hash(b"content"),
    )


def test_page_with_no_repositories_shows_placeholder_stats(app):
    page = _make_page(app)

    assert page.files_value_label.text() == "—"
    assert page.accounts_value_label.text() == "—"
    assert page.deception_value_label.text() == "—"
    assert page.tracking_value_label.text() == "—"
    assert "no usage tracker" in page.tracking_detail_label.text().lower()


def test_page_with_no_repositories_shows_activity_placeholder(app):
    page = _make_page(app)

    assert page.activity_list.count() == 1
    assert "no recent activity" in page.activity_list.item(0).text().lower()


def test_files_stat_counts_metadata_records(app, metadata_controller, metadata_repository):
    _create_metadata_record(metadata_controller, file_id="file-1")
    _create_metadata_record(metadata_controller, file_id="file-2")

    page = _make_page(app, metadata_repository=metadata_repository)

    assert page.files_value_label.text() == "2"


def test_accounts_stat_counts_registered_accounts(app, auth_controller, account_repository):
    auth_controller.register_password_account("owner-1", "correct-horse-battery")
    auth_controller.register_password_account("owner-2", "another-strong-password")

    page = _make_page(app, account_repository=account_repository)

    assert page.accounts_value_label.text() == "2"


def test_deception_stat_counts_recorded_events(app, deception_event_repository):
    deception_event_repository.record(
        DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "file-1", datetime.now(timezone.utc)
    )

    page = _make_page(app, deception_event_repository=deception_event_repository)

    assert page.deception_value_label.text() == "1"


def test_tracking_stat_shows_entry_count_and_integrity_ok(app, usage_tracker):
    record = usage_tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    usage_tracker.record_close(record)

    page = _make_page(app, usage_tracker=usage_tracker)

    assert page.tracking_value_label.text() == "1"
    assert "integrity ok" in page.tracking_detail_label.text().lower()


def test_tracking_stat_shows_failure_when_log_tampered(app, usage_tracker, connection):
    record = usage_tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    usage_tracker.record_close(record)

    connection.execute("UPDATE usage_log SET entry_hmac = X'deadbeef'")
    connection.commit()

    page = _make_page(app, usage_tracker=usage_tracker)  # must not raise

    assert "integrity failed" in page.tracking_detail_label.text().lower()
    assert page.tracking_value_label.text() == "—"


def test_activity_feed_does_not_crash_when_log_tampered(app, usage_tracker, connection):
    record = usage_tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    usage_tracker.record_close(record)

    connection.execute("UPDATE usage_log SET entry_hmac = X'deadbeef'")
    connection.commit()

    page = _make_page(app, usage_tracker=usage_tracker)  # must not raise

    assert page.activity_list.count() == 1
    assert "no recent activity" in page.activity_list.item(0).text().lower()


def test_activity_feed_includes_tracking_session(app, usage_tracker):
    record = usage_tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    usage_tracker.record_close(record)

    page = _make_page(app, usage_tracker=usage_tracker)

    assert page.activity_list.count() == 1
    assert "alice" in page.activity_list.item(0).text()
    assert "file-1" in page.activity_list.item(0).text()


def test_activity_feed_includes_deception_event(app, deception_event_repository):
    deception_event_repository.record(
        DeceptionTrigger.DEVICE_MISMATCH, DeceptionContentType.FAKE_PDF, "file-2", datetime.now(timezone.utc)
    )

    page = _make_page(app, deception_event_repository=deception_event_repository)

    assert page.activity_list.count() == 1
    assert "deception triggered" in page.activity_list.item(0).text().lower()
    assert "file-2" in page.activity_list.item(0).text()


def test_activity_feed_orders_most_recent_first(app, deception_event_repository):
    earlier = datetime(2025, 1, 1, tzinfo=timezone.utc)
    later = datetime(2025, 6, 1, tzinfo=timezone.utc)
    deception_event_repository.record(
        DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "old-file", earlier
    )
    deception_event_repository.record(
        DeceptionTrigger.DEVICE_MISMATCH, DeceptionContentType.FAKE_PDF, "new-file", later
    )

    page = _make_page(app, deception_event_repository=deception_event_repository)

    assert "new-file" in page.activity_list.item(0).text()
    assert "old-file" in page.activity_list.item(1).text()


def test_activity_feed_merges_both_sources(app, usage_tracker, deception_event_repository):
    record = usage_tracker.start_session(user="alice", machine_id="m", file_id="file-1")
    usage_tracker.record_close(record)
    deception_event_repository.record(
        DeceptionTrigger.WRONG_CREDENTIALS, DeceptionContentType.FAKE_TEXT, "file-2", datetime.now(timezone.utc)
    )

    page = _make_page(app, usage_tracker=usage_tracker, deception_event_repository=deception_event_repository)

    assert page.activity_list.count() == 2
    combined = "\n".join(page.activity_list.item(i).text() for i in range(page.activity_list.count()))
    assert "file-1" in combined
    assert "file-2" in combined


def test_quick_action_buttons_emit_navigate_requested(app):
    page = _make_page(app)
    seen: list[str] = []
    page.navigate_requested.connect(seen.append)

    page.encrypt_button.click()
    page.decrypt_button.click()
    page.validate_device_button.click()

    assert seen == ["encryption", "decryption", "devices"]


def test_refresh_reflects_newly_added_data(app, metadata_controller, metadata_repository):
    page = _make_page(app, metadata_repository=metadata_repository)
    assert page.files_value_label.text() == "0"

    _create_metadata_record(metadata_controller, file_id="file-1")
    page.refresh()

    assert page.files_value_label.text() == "1"


