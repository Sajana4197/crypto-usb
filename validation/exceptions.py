"""Exceptions raised by the Validation Engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from validation.validation_engine import ValidationReport


class ValidationError(Exception):
    """Base class for all validation errors."""


class ValidationFailedError(ValidationError):
    """Raised by `ValidationEngine.validate_or_raise` when any check fails.

    Carries the full `ValidationReport` so a caller can inspect exactly
    which check(s) failed rather than parsing the message.
    """

    def __init__(self, report: "ValidationReport") -> None:
        reasons = "; ".join(report.reasons) if report.reasons else "validation failed"
        super().__init__(f"Validation failed for file_id={report.file_id}: {reasons}")
        self.report = report
