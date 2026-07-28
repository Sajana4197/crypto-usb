"""Tests for the Deception Module dashboard page."""

import random
import sqlite3

import pytest
from PySide6.QtWidgets import QApplication

from deception.deception_engine import DeceptionEngine
from deception.event_repository import DeceptionEventRepository, PresentedDeviceInfo
from deception.triggers import DeceptionTrigger
from ui.pages.deception_page import DeceptionPage, _format_device_info


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def connection():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def event_repository(connection):
    return DeceptionEventRepository(connection)


def _make_page(app, event_repository=None):
    return DeceptionPage(event_repository=event_repository)


def test_page_with_no_repository_shows_unavailable_message(app):
    page = _make_page(app)
    assert page.table.rowCount() == 0
    assert "no deception event repository" in page.summary_label.text().lower()


def test_page_with_no_events_shows_zero(app, event_repository):
    page = _make_page(app, event_repository)
    assert page.table.rowCount() == 0
    assert "0 recorded" in page.summary_label.text()


def test_page_shows_recorded_activation(app, event_repository):
    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    engine.activate(DeceptionTrigger.METADATA_TAMPERING, file_id="file-1")

    page = _make_page(app, event_repository)

    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == DeceptionTrigger.METADATA_TAMPERING.value
    assert page.table.item(0, 2).text() == "file-1"


def test_page_never_shows_fabricated_content(app, event_repository):
    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    response = engine.activate(DeceptionTrigger.WRONG_CREDENTIALS)

    page = _make_page(app, event_repository)

    for column in range(page.table.columnCount()):
        cell_text = page.table.item(0, column).text()
        assert cell_text.encode("latin-1", errors="ignore") != response.content


def test_page_shows_events_most_recent_first(app, event_repository):
    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    engine.activate(DeceptionTrigger.WRONG_CREDENTIALS, file_id="file-1")
    engine.activate(DeceptionTrigger.DEVICE_MISMATCH, file_id="file-2")

    page = _make_page(app, event_repository)

    assert page.table.item(0, 2).text() == "file-2"
    assert page.table.item(1, 2).text() == "file-1"


def test_refresh_reflects_new_activations(app, event_repository):
    page = _make_page(app, event_repository)
    assert page.table.rowCount() == 0

    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    engine.activate(DeceptionTrigger.ACCESS_ALREADY_USED, file_id="file-1")
    page.refresh()

    assert page.table.rowCount() == 1


# -- Automatic polling --------------------------------------------------


def test_refresh_timer_is_running_after_construction(app, event_repository):
    page = _make_page(app, event_repository)

    assert page._refresh_timer.isActive() is True


def test_refresh_is_a_noop_when_events_are_unchanged(app, event_repository, monkeypatch):
    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    engine.activate(DeceptionTrigger.METADATA_TAMPERING, file_id="file-1")
    page = _make_page(app, event_repository)

    calls = []
    monkeypatch.setattr(page, "_append_row", lambda *a, **k: calls.append(None))

    page.refresh()  # same events as construction -- nothing changed

    assert calls == []


# -- Presented device info (Phase 5) -----------------------------------------


def test_page_shows_presented_device_column_when_recorded(app, event_repository):
    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    engine.activate(
        DeceptionTrigger.DEVICE_MISMATCH,
        file_id="file-1",
        device_info=PresentedDeviceInfo(
            usb_serial="ABCD1234:FAT32:1000000",
            vendor_id="SANDISK",
            product_id="CRUZER_BLADE",
            hardware_serial="4C530001A2B3C4D5",
            mount_point="E:\\",
            label="MYUSB",
        ),
    )

    page = _make_page(app, event_repository)

    device_cell = page.table.item(0, 4).text()
    assert "MYUSB" in device_cell
    assert "SANDISK" in device_cell


def test_page_shows_dash_for_events_without_device_info(app, event_repository):
    engine = DeceptionEngine(rng=random.Random(1), event_repository=event_repository)
    engine.activate(DeceptionTrigger.WRONG_CREDENTIALS, file_id="file-1")

    page = _make_page(app, event_repository)

    assert page.table.item(0, 4).text() == "—"


def test_format_device_info_empty_is_a_dash():
    assert _format_device_info(PresentedDeviceInfo()) == "—"


def test_format_device_info_falls_back_to_usb_serial_when_nothing_else_available():
    text = _format_device_info(PresentedDeviceInfo(usb_serial="ABCD1234:FAT32:1000000"))
    assert text == "ABCD1234:FAT32:1000000"
