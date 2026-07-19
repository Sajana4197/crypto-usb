"""Tests for the Deception Module dashboard page."""

import random
import sqlite3

import pytest
from PySide6.QtWidgets import QApplication

from deception.deception_engine import DeceptionEngine
from deception.event_repository import DeceptionEventRepository
from deception.triggers import DeceptionTrigger
from ui.pages.deception_page import DeceptionPage


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
