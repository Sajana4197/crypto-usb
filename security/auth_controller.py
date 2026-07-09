"""Authentication Controller: the single entry point for registering and
authenticating a local account, by password or by private key.

Composes `PasswordHasher`/`KeyAuthenticator` (credential verification),
`LockoutPolicy` (brute-force protection), and `AccountRepository`
(persistence) so callers never touch any of them directly, and never
get an `AuthSession` back unless the credential actually validated.
This is the module the Secure Authentication Dialog talks to, and the
module any future validation phase should talk to as well — it does
not decrypt or touch files itself.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from core.logger import get_logger
from security import password_hasher
from security.account_repository import AccountRepository
from security.exceptions import (
    AccountAlreadyExistsError,
    AccountLockedError,
    AccountNotFoundError,
    InvalidCredentialsError,
)
from security.key_authenticator import KeyAuthenticator, generate_challenge
from security.lockout_policy import LockoutPolicy
from security.models import AuthMethod, PasswordCredential, PrivateKeyCredential, UserAccount
from security.auth_session import AuthSession

logger = get_logger(__name__)


class AuthController:
    """Registers and authenticates local accounts by password or private key."""

    def __init__(
        self,
        repository: AccountRepository,
        lockout_policy: Optional[LockoutPolicy] = None,
        key_authenticator: Optional[KeyAuthenticator] = None,
    ) -> None:
        self._repository = repository
        self._lockout_policy = lockout_policy or LockoutPolicy()
        self._key_authenticator = key_authenticator or KeyAuthenticator()

    def has_account(self, owner_id: str) -> bool:
        return self._repository.exists(owner_id)

    def get_account(self, owner_id: str) -> UserAccount:
        account = self._repository.load(owner_id)
        if account is None:
            raise AccountNotFoundError(f"No account found for owner_id={owner_id}")
        return account

    # -- Registration ------------------------------------------------------

    def register_password_account(self, owner_id: str, password: str) -> UserAccount:
        """Create a new account authenticated by password. Raises
        `AccountAlreadyExistsError` if one exists, or `WeakPasswordError`
        (from `security.password_hasher`) if the password is too weak.
        """
        if self._repository.exists(owner_id):
            raise AccountAlreadyExistsError(f"An account already exists for owner_id={owner_id}")

        credential = password_hasher.hash_password(password)
        account = UserAccount(
            owner_id=owner_id,
            auth_method=AuthMethod.PASSWORD,
            credential=credential,
            created_at=datetime.now(timezone.utc),
        )
        self._repository.save(account)
        logger.info("Registered password account for owner_id=%s", owner_id)
        return account

    def register_private_key_account(self, owner_id: str, public_key_pem: bytes) -> UserAccount:
        """Create a new account authenticated by private key. Only the
        public key is ever persisted. Raises `AccountAlreadyExistsError`
        if one exists.
        """
        if self._repository.exists(owner_id):
            raise AccountAlreadyExistsError(f"An account already exists for owner_id={owner_id}")

        credential = PrivateKeyCredential(public_key_pem=public_key_pem)
        account = UserAccount(
            owner_id=owner_id,
            auth_method=AuthMethod.PRIVATE_KEY,
            credential=credential,
            created_at=datetime.now(timezone.utc),
        )
        self._repository.save(account)
        logger.info("Registered private-key account for owner_id=%s", owner_id)
        return account

    # -- Authentication ------------------------------------------------------

    def authenticate_password(self, owner_id: str, password: str) -> AuthSession:
        """Validate `password` against the stored account. Raises
        `AccountNotFoundError`, `AccountLockedError`, or
        `InvalidCredentialsError` — only ever returns a session on success.
        """
        account = self._require_unlocked_account(owner_id, AuthMethod.PASSWORD)

        assert isinstance(account.credential, PasswordCredential)
        if password_hasher.verify_password(password, account.credential):
            return self._succeed(account)

        self._fail(account, "password")
        raise InvalidCredentialsError("Incorrect password")

    def authenticate_private_key(self, owner_id: str, private_key_pem: bytes, passphrase: bytes) -> AuthSession:
        """Validate possession of the enrolled private key via challenge/response.
        Raises `AccountNotFoundError`, `AccountLockedError`, or
        `InvalidCredentialsError` — only ever returns a session on success.
        """
        account = self._require_unlocked_account(owner_id, AuthMethod.PRIVATE_KEY)

        assert isinstance(account.credential, PrivateKeyCredential)
        challenge = generate_challenge()
        verified = self._key_authenticator.authenticate(
            private_key_pem, passphrase, account.credential.public_key_pem, challenge
        )
        if verified:
            return self._succeed(account)

        self._fail(account, "private key")
        raise InvalidCredentialsError("Private key authentication failed")

    # -- Shared helpers ------------------------------------------------------

    def _require_unlocked_account(self, owner_id: str, expected_method: AuthMethod) -> UserAccount:
        account = self.get_account(owner_id)

        if self._lockout_policy.is_locked(account):
            seconds = self._lockout_policy.seconds_remaining(account)
            logger.warning("Authentication rejected for owner_id=%s: account locked (%ds remaining)", owner_id, seconds)
            raise AccountLockedError(
                f"Account is locked for {seconds} more second(s) after repeated failed attempts", seconds
            )

        if account.auth_method != expected_method:
            # Wrong method entirely still counts as a failed attempt.
            self._fail(account, expected_method.value)
            raise InvalidCredentialsError(
                f"Account owner_id={owner_id} does not use {expected_method.value} authentication"
            )

        return account

    def _succeed(self, account: UserAccount) -> AuthSession:
        self._lockout_policy.register_success(account)
        self._repository.save(account)
        logger.info("Authentication succeeded for owner_id=%s method=%s", account.owner_id, account.auth_method.value)
        return AuthSession(
            owner_id=account.owner_id,
            method=account.auth_method,
            authenticated_at=datetime.now(timezone.utc),
        )

    def _fail(self, account: UserAccount, attempted_with: str) -> None:
        self._lockout_policy.register_failure(account)
        self._repository.save(account)
        logger.warning(
            "Authentication failed for owner_id=%s (attempted with %s); failed_attempts=%d",
            account.owner_id, attempted_with, account.failed_attempts,
        )
