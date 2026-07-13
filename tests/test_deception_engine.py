"""Tests for the Deception Engine orchestration."""

import itertools
import logging
import random

import pytest

from deception.content_types import DeceptionContentType
from deception.deception_engine import DeceptionEngine, DeceptionResponse
from deception.triggers import DeceptionTrigger

FORBIDDEN_PHRASES = ["access denied", "authentication failed", "unauthorized access"]

ALL_TRIGGERS = list(DeceptionTrigger)
ALL_CONTENT_TYPES = list(DeceptionContentType)


@pytest.fixture
def engine():
    return DeceptionEngine(rng=random.Random(99))


# -- Basic activation ------------------------------------------------------


def test_activate_returns_deception_response(engine):
    response = engine.activate(DeceptionTrigger.WRONG_CREDENTIALS)
    assert isinstance(response, DeceptionResponse)
    assert response.trigger == DeceptionTrigger.WRONG_CREDENTIALS
    assert response.content_type in ALL_CONTENT_TYPES
    assert isinstance(response.content, bytes)
    assert len(response.content) > 0
    assert response.mime_type
    assert response.filename


@pytest.mark.parametrize("trigger", ALL_TRIGGERS)
def test_activate_handles_every_required_trigger(engine, trigger):
    response = engine.activate(trigger)
    assert response.trigger == trigger
    assert len(response.content) > 0


@pytest.mark.parametrize("content_type", ALL_CONTENT_TYPES)
def test_activate_can_force_a_specific_content_type(engine, content_type):
    response = engine.activate(DeceptionTrigger.INTEGRITY_FAILURE, content_type=content_type)
    assert response.content_type == content_type


def test_activate_without_content_type_varies_across_calls():
    engine = DeceptionEngine(rng=random.Random(0))
    seen_types = {
        engine.activate(DeceptionTrigger.DEVICE_MISMATCH).content_type for _ in range(30)
    }
    assert len(seen_types) > 1


def test_activate_is_deterministic_for_a_seeded_engine():
    response_a = DeceptionEngine(rng=random.Random(555)).activate(DeceptionTrigger.METADATA_TAMPERING)
    response_b = DeceptionEngine(rng=random.Random(555)).activate(DeceptionTrigger.METADATA_TAMPERING)
    assert response_a.content_type == response_b.content_type
    assert response_a.content == response_b.content


# -- Never reveal the denial ------------------------------------------------


@pytest.mark.parametrize(
    "trigger,content_type", list(itertools.product(ALL_TRIGGERS, ALL_CONTENT_TYPES))
)
def test_response_content_never_contains_denial_language(trigger, content_type):
    engine = DeceptionEngine(rng=random.Random(1))
    response = engine.activate(trigger, content_type=content_type)

    lowered = response.content.decode("latin-1").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lowered


@pytest.mark.parametrize("trigger", ALL_TRIGGERS)
def test_response_content_never_contains_the_trigger_name(trigger):
    engine = DeceptionEngine(rng=random.Random(1))
    response = engine.activate(trigger)

    lowered = response.content.decode("latin-1").lower()
    assert trigger.value.replace("_", " ") not in lowered
    assert trigger.value not in lowered


# -- Logging -----------------------------------------------------------------


def test_activate_logs_a_deception_event(engine, caplog):
    with caplog.at_level(logging.WARNING, logger="deception.deception_engine"):
        engine.activate(DeceptionTrigger.ACCESS_ALREADY_USED, file_id="file-42")

    messages = [record.getMessage() for record in caplog.records]
    assert any("Deception activated" in message for message in messages)
    assert any("access_already_used" in message for message in messages)
    assert any("file-42" in message for message in messages)


def test_activate_logs_even_without_file_id(engine, caplog):
    with caplog.at_level(logging.WARNING, logger="deception.deception_engine"):
        engine.activate(DeceptionTrigger.WRONG_CREDENTIALS)

    messages = [record.getMessage() for record in caplog.records]
    assert any("Deception activated" in message for message in messages)


@pytest.mark.parametrize("trigger", ALL_TRIGGERS)
def test_every_trigger_produces_exactly_one_log_event(engine, caplog, trigger):
    with caplog.at_level(logging.WARNING, logger="deception.deception_engine"):
        engine.activate(trigger)

    deception_records = [r for r in caplog.records if "Deception activated" in r.getMessage()]
    assert len(deception_records) == 1
