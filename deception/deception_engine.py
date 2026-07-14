"""The Deception Engine: what a caller gets back instead of a denial.

The rest of the application (security/auth, validation/validation_engine)
is responsible for *detecting* a problem. Once one of them has decided
access must not be granted, it hands control here instead of surfacing
"Access Denied", "Authentication Failed", or "Unauthorized Access" to
whoever — or whatever — is on the other end. This engine's only job is
to fabricate a believable response and record, internally, that
deception was used.

Nothing here reveals *why* access was refused: `DeceptionResponse`
carries the trigger for the audit log only — the generated `content`
itself never mentions credentials, devices, tampering, or expiry.

When an `event_repository` is supplied, every activation is also
recorded there (trigger, content type, file_id, timestamp — never the
fabricated `content` itself) so `ui.pages.deception_page.DeceptionPage`
has something queryable to show. This is purely an audit trail of
decisions already made — nothing here reads the repository back to
decide what to do, so it cannot change this engine's behavior.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from core.logger import get_logger
from deception.content_generators import (
    generate_corrupted_data,
    generate_fake_image,
    generate_fake_metadata,
    generate_fake_pdf,
    generate_fake_text,
)
from deception.content_types import MIME_TYPES, DeceptionContentType
from deception.triggers import DeceptionTrigger

if TYPE_CHECKING:
    from deception.event_repository import DeceptionEventRepository

logger = get_logger(__name__)

_EXTENSIONS: dict[DeceptionContentType, str] = {
    DeceptionContentType.FAKE_TEXT: "txt",
    DeceptionContentType.FAKE_PDF: "pdf",
    DeceptionContentType.FAKE_IMAGE: "png",
    DeceptionContentType.CORRUPTED_DATA: "bin",
    DeceptionContentType.FAKE_METADATA: "json",
}

_GENERATORS = {
    DeceptionContentType.FAKE_TEXT: lambda rng, file_id: generate_fake_text(rng),
    DeceptionContentType.FAKE_PDF: lambda rng, file_id: generate_fake_pdf(rng),
    DeceptionContentType.FAKE_IMAGE: lambda rng, file_id: generate_fake_image(rng),
    DeceptionContentType.CORRUPTED_DATA: lambda rng, file_id: generate_corrupted_data(rng),
    DeceptionContentType.FAKE_METADATA: lambda rng, file_id: generate_fake_metadata(rng, file_id),
}


@dataclass
class DeceptionResponse:
    """What gets handed back to the caller in place of a real denial.

    `trigger` and `generated_at` exist for the audit trail — they are
    not meant to ever be rendered to whoever triggered the deception.
    """

    trigger: DeceptionTrigger
    content_type: DeceptionContentType
    content: bytes
    mime_type: str
    filename: str
    generated_at: datetime


class DeceptionEngine:
    """Fabricates a believable response for a detected failure and logs it.

    Never raises for a "denial" — that concept does not exist at this
    layer. Callers pass a `DeceptionTrigger` describing which upstream
    check failed; the engine decides what fake content to return.
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        event_repository: Optional["DeceptionEventRepository"] = None,
    ) -> None:
        self._rng = rng or random.Random()
        self._event_repository = event_repository

    def activate(
        self,
        trigger: DeceptionTrigger,
        file_id: Optional[str] = None,
        content_type: Optional[DeceptionContentType] = None,
    ) -> DeceptionResponse:
        """Generate and log a deceptive response for `trigger`.

        `content_type` forces a specific kind of fake content; if
        omitted, one is chosen at random so behavior is not predictable
        from the outside.
        """
        chosen_type = content_type or self._rng.choice(list(DeceptionContentType))
        content = _GENERATORS[chosen_type](self._rng, file_id)

        response = DeceptionResponse(
            trigger=trigger,
            content_type=chosen_type,
            content=content,
            mime_type=MIME_TYPES[chosen_type],
            filename=self._filename_for(chosen_type),
            generated_at=datetime.now(timezone.utc),
        )

        self._log_event(trigger, chosen_type, file_id)
        if self._event_repository is not None:
            self._event_repository.record(trigger, chosen_type, file_id, response.generated_at)
        return response

    def _filename_for(self, content_type: DeceptionContentType) -> str:
        stem = self._rng.choice(["report", "document", "file", "data", "notes"])
        return f"{stem}_{self._rng.randint(1000, 9999)}.{_EXTENSIONS[content_type]}"

    @staticmethod
    def _log_event(
        trigger: DeceptionTrigger, content_type: DeceptionContentType, file_id: Optional[str]
    ) -> None:
        # Internal audit trail only — never surfaced to the caller that
        # triggered it, so it is safe to name the real reason here.
        logger.warning(
            "Deception activated: trigger=%s content_type=%s file_id=%s",
            trigger.value,
            content_type.value,
            file_id or "unknown",
        )
