"""Exceptions raised by the tracking package."""

from __future__ import annotations


class TrackingError(Exception):
    """Base class for all usage-tracking errors."""


class TrackingTamperError(TrackingError):
    """Raised when a stored usage log entry fails its HMAC or chain-link check.

    Covers both a modified entry (HMAC mismatch) and a deleted, inserted,
    or reordered entry (chain-link mismatch against the previous entry's
    HMAC) — see `tracking.tamper_evident_log` for the chain design.
    """
