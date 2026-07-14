"""The authenticated session, and where future modules can find it.

`AuthSession` is the proof-of-authentication object `AuthController`
hands back on success. `SessionManager` holds the single current
session in memory (never persisted) for the lifetime of the running
application — future validation/access-control phases (device
binding, one-time access enforcement, key invalidation) are expected
to consult `SessionManager.current` rather than re-authenticating,
the same way `ui.main_window.MainWindow` already carries a
`db_manager` attribute for later phases to use.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from security.models import AuthMethod


@dataclass(frozen=True)
class AuthSession:
    """Proof that `owner_id` successfully authenticated via `method`."""

    owner_id: str
    method: AuthMethod
    authenticated_at: datetime
    session_token: str = field(default_factory=lambda: uuid.uuid4().hex)


class SessionManager:
    """Holds the current authenticated session for the running application."""

    def __init__(self) -> None:
        self._session: Optional[AuthSession] = None

    @property
    def current(self) -> Optional[AuthSession]:
        return self._session

    @property
    def is_authenticated(self) -> bool:
        return self._session is not None

    def set(self, session: AuthSession) -> None:
        self._session = session

    def clear(self) -> None:
        self._session = None
