"""Exceptions raised by the security (authentication) package."""

from __future__ import annotations


class SecurityError(Exception):
    """Base class for all authentication/security errors."""


class AccountNotFoundError(SecurityError):
    """Raised when no account exists for a given owner_id."""


class AccountAlreadyExistsError(SecurityError):
    """Raised when attempting to register an owner_id that already has an account."""


class InvalidCredentialsError(SecurityError):
    """Raised when a password or private key fails to authenticate."""


class AccountLockedError(SecurityError):
    """Raised when authentication is attempted against a temporarily locked account."""

    def __init__(self, message: str, seconds_remaining: int) -> None:
        super().__init__(message)
        self.seconds_remaining = seconds_remaining


class WeakPasswordError(SecurityError):
    """Raised when a password fails the minimum strength policy."""
