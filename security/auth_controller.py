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

import os
from datetime import datetime, timezone
from typing import Optional

from app.protection_keys import (
    establish_vault_master_key,
    unwrap_vault_master_key_via_password,
    unwrap_vault_master_key_via_recovery,
    wrap_vault_master_key_for_password,
    wrap_vault_master_key_for_recovery,
)
from core.logger import get_logger
from crypto.secure_cleanup import CleanupReason, cleanup
from database.db_manager import DatabaseManager
from deception.deception_engine import DeceptionEngine
from deception.triggers import DeceptionTrigger
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
        deception_engine: Optional[DeceptionEngine] = None,
        db_manager: Optional[DatabaseManager] = None,
    ) -> None:
        self._repository = repository
        self._lockout_policy = lockout_policy or LockoutPolicy()
        self._key_authenticator = key_authenticator or KeyAuthenticator()
        # Optional: when supplied, lets password registration/change/reset
        # establish and rewrap the Vault Master Key (see
        # `app.protection_keys`) alongside the credential itself, so
        # already-encrypted metadata and the tamper-evident usage log
        # stay readable/verifiable across a credential rotation. `None`
        # in tests that only exercise credential logic in isolation.
        self._db_manager = db_manager
        self._deception_engine = deception_engine or DeceptionEngine()

    def has_account(self, owner_id: str) -> bool:
        return self._repository.exists(owner_id)

    def get_account(self, owner_id: str) -> UserAccount:
        account = self._repository.load(owner_id)
        if account is None:
            raise AccountNotFoundError(f"No account found for owner_id={owner_id}")
        return account

    # -- Registration ------------------------------------------------------

    def register_password_account(self, owner_id: str, password: str) -> tuple[UserAccount, str]:
        """Create a new account authenticated by password. Raises
        `AccountAlreadyExistsError` if one exists, or `WeakPasswordError`
        (from `security.password_hasher`) if the password is too weak.

        Also generates a one-time recovery code, hashes it into the
        credential (same scrypt scheme as the password), and returns the
        plaintext code alongside the account — this is the only moment it
        is ever available; the caller must show it to the user now.
        """
        if self._repository.exists(owner_id):
            raise AccountAlreadyExistsError(f"An account already exists for owner_id={owner_id}")

        credential = password_hasher.hash_password(password)
        recovery_code = password_hasher.generate_recovery_code()
        recovery_code_hash = password_hasher.hash_recovery_code(recovery_code)
        account = UserAccount(
            owner_id=owner_id,
            auth_method=AuthMethod.PASSWORD,
            credential=credential,
            created_at=datetime.now(timezone.utc),
            recovery_code_hash=recovery_code_hash,
        )
        self._repository.save(account)
        self._rewrap_vault_master_key(None, credential, password, recovery_code_hash, recovery_code)
        logger.info("Registered password account for owner_id=%s", owner_id)
        return account, recovery_code

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
        `AccountNotFoundError` or `AccountLockedError`. Wrong credentials
        against an existing, unlocked account never raise — matching the
        proposal's Deceptive Protection Mechanism, this activates the
        Deception Engine and returns a decoy `AuthSession` (`is_decoy=True`)
        instead, so a wrong password looks like a successful sign-in.
        Lockout tracking (`_fail`) still runs exactly as before.
        """
        account = self._require_unlocked_account(owner_id, AuthMethod.PASSWORD)

        assert isinstance(account.credential, PasswordCredential)
        if password_hasher.verify_password(password, account.credential):
            if account.credential.key_wrap_salt is None:
                # Self-heal: account was created before vault-key wrapping
                # existed. Generate the missing salt once, on first login.
                account.credential.key_wrap_salt = os.urandom(password_hasher.SALT_LEN_BYTES)
                self._repository.save(account)
            vault_key = password_hasher.derive_vault_key(password, account.credential.key_wrap_salt)
            return self._succeed(account, vault_key=vault_key)

        self._fail(account, "password")
        self._deception_engine.activate(DeceptionTrigger.WRONG_CREDENTIALS)
        return AuthSession(
            owner_id=owner_id,
            method=AuthMethod.PASSWORD,
            authenticated_at=datetime.now(timezone.utc),
            is_decoy=True,
        )

    def authenticate_private_key(self, owner_id: str, private_key_pem: bytes, passphrase: bytes) -> AuthSession:
        """Validate possession of the enrolled private key via challenge/response.
        Raises `AccountNotFoundError` or `AccountLockedError`. Wrong
        credentials against an existing, unlocked account never raise —
        matching the proposal's Deceptive Protection Mechanism, this
        activates the Deception Engine and returns a decoy `AuthSession`
        (`is_decoy=True`) instead, so a wrong key looks like a successful
        sign-in. Lockout tracking (`_fail`) still runs exactly as before.
        """
        account = self._require_unlocked_account(owner_id, AuthMethod.PRIVATE_KEY)

        assert isinstance(account.credential, PrivateKeyCredential)
        challenge = generate_challenge()
        verified = self._key_authenticator.authenticate(
            private_key_pem, passphrase, account.credential.public_key_pem, challenge
        )
        if verified:
            if account.credential.key_wrap_salt is None:
                # Self-heal: account was created before vault-key wrapping
                # existed. Generate the missing salt once, on first login.
                account.credential.key_wrap_salt = os.urandom(password_hasher.SALT_LEN_BYTES)
                self._repository.save(account)
            vault_key = password_hasher.derive_vault_key_from_bytes(
                private_key_pem + b"|" + passphrase, account.credential.key_wrap_salt
            )
            return self._succeed(account, vault_key=vault_key)

        self._fail(account, "private key")
        self._deception_engine.activate(DeceptionTrigger.WRONG_CREDENTIALS)
        return AuthSession(
            owner_id=owner_id,
            method=AuthMethod.PRIVATE_KEY,
            authenticated_at=datetime.now(timezone.utc),
            is_decoy=True,
        )

    # -- Password change & recovery ------------------------------------------

    def change_password(self, owner_id: str, current_password: str, new_password: str) -> tuple[UserAccount, str]:
        """Verify `current_password`, then re-hash and save `new_password`.
        Subject to the same lockout policy as a normal password sign-in.
        Raises `AccountNotFoundError`, `AccountLockedError`,
        `InvalidCredentialsError` (wrong current password), or
        `WeakPasswordError` (from `security.password_hasher`).

        Also rotates the recovery code: a fresh one is generated and hashed
        in, invalidating the old one, and returned alongside the account —
        same one-time-reveal contract as `register_password_account`, since
        an attacker who learned the old recovery code should not be able to
        use it after the legitimate owner changes their password.

        If this controller was constructed with a `db_manager`, the Vault
        Master Key reachable via the old password is carried forward into
        new password/recovery slots (see `_rewrap_vault_master_key`), so
        already-encrypted metadata and the tamper-evident usage log stay
        readable/verifiable under the new password rather than being
        silently orphaned.
        """
        account = self._require_unlocked_account(owner_id, AuthMethod.PASSWORD)

        assert isinstance(account.credential, PasswordCredential)
        if password_hasher.verify_password(current_password, account.credential):
            old_vmk = self._unwrap_vmk_via_password(account.credential, current_password)
            account.credential = password_hasher.hash_password(new_password)
            recovery_code = password_hasher.generate_recovery_code()
            account.recovery_code_hash = password_hasher.hash_recovery_code(recovery_code)
            self._lockout_policy.register_success(account)
            self._repository.save(account)
            self._rewrap_vault_master_key(
                old_vmk, account.credential, new_password, account.recovery_code_hash, recovery_code
            )
            logger.info("Password changed for owner_id=%s", owner_id)
            return account, recovery_code

        self._fail(account, "current password")
        raise InvalidCredentialsError("Incorrect current password")

    def reset_password_with_recovery_code(
        self, owner_id: str, recovery_code: str, new_password: str
    ) -> tuple[UserAccount, str]:
        """Verify `recovery_code` against its stored hash, then set
        `new_password`. Subject to the same lockout policy as a normal
        sign-in, so repeated bad codes cannot be used to brute-force it.
        Raises `AccountNotFoundError`, `AccountLockedError`,
        `InvalidCredentialsError` (wrong/missing recovery code), or
        `WeakPasswordError`.

        The recovery code is single-use: a fresh one is generated and
        hashed in, invalidating the one just used, and returned alongside
        the account — same one-time-reveal contract as
        `register_password_account`/`change_password`.

        If this controller was constructed with a `db_manager`, the Vault
        Master Key reachable via the recovery code just used is carried
        forward into new password/recovery slots (see
        `_rewrap_vault_master_key`) — the same mechanism `change_password`
        uses, just unlocked via the recovery slot instead of the password
        slot, since a forgotten password can't re-derive the old vault
        key. This is what lets a recovery-code reset preserve
        already-encrypted metadata and the tamper-evident usage log
        instead of silently orphaning them.
        """
        account = self._require_unlocked_account(owner_id, AuthMethod.PASSWORD)

        assert isinstance(account.credential, PasswordCredential)
        if account.recovery_code_hash is not None and password_hasher.verify_recovery_code(
            recovery_code, account.recovery_code_hash
        ):
            old_vmk = self._unwrap_vmk_via_recovery(account.recovery_code_hash, recovery_code)
            account.credential = password_hasher.hash_password(new_password)
            new_recovery_code = password_hasher.generate_recovery_code()
            account.recovery_code_hash = password_hasher.hash_recovery_code(new_recovery_code)
            self._lockout_policy.register_success(account)
            self._repository.save(account)
            self._rewrap_vault_master_key(
                old_vmk, account.credential, new_password, account.recovery_code_hash, new_recovery_code
            )
            logger.info("Password reset via recovery code for owner_id=%s", owner_id)
            return account, new_recovery_code

        self._fail(account, "recovery code")
        raise InvalidCredentialsError("Invalid recovery code")

    # -- Shared helpers ------------------------------------------------------

    def _unwrap_vmk_via_password(self, old_credential: PasswordCredential, password: str) -> Optional[bytes]:
        """The VMK reachable via the credential *before* a password
        change/reset overwrites it, or `None` if there's nothing to
        preserve (no `db_manager`, a pre-vault-key-wrapping account that
        was never self-healed by a login, or no VMK established yet)."""
        if self._db_manager is None or old_credential.key_wrap_salt is None:
            return None
        old_vault_key = password_hasher.derive_vault_key(password, old_credential.key_wrap_salt)
        return unwrap_vault_master_key_via_password(self._db_manager, old_vault_key)

    def _unwrap_vmk_via_recovery(
        self, old_recovery_code_hash: PasswordCredential, recovery_code: str
    ) -> Optional[bytes]:
        """The VMK reachable via the recovery code *before* a
        recovery-code reset overwrites its hash, or `None` if there's
        nothing to preserve (no `db_manager`, a recovery code issued
        before the recovery slot existed, or no recovery slot populated
        yet). This is what lets `reset_password_with_recovery_code` carry
        the VMK forward without ever knowing the old password."""
        if self._db_manager is None or old_recovery_code_hash.key_wrap_salt is None:
            return None
        old_recovery_key = password_hasher.derive_recovery_key(
            recovery_code, old_recovery_code_hash.key_wrap_salt
        )
        return unwrap_vault_master_key_via_recovery(self._db_manager, old_recovery_key)

    def _rewrap_vault_master_key(
        self,
        old_vmk: Optional[bytes],
        new_credential: PasswordCredential,
        new_password: str,
        new_recovery_code_hash: PasswordCredential,
        new_recovery_code: str,
    ) -> None:
        """No-op when constructed without a `db_manager` (e.g. tests that
        only exercise credential logic). Otherwise persists `old_vmk` —
        or a freshly generated VMK, if there was nothing to carry
        forward — into new password/recovery slots derived from the
        just-established new credential and new recovery code. Carrying
        the *same* VMK forward (rather than always minting a new one) is
        what keeps already-encrypted metadata and the tamper-evident
        usage log readable/verifiable across a credential rotation."""
        if self._db_manager is None:
            return

        assert new_credential.key_wrap_salt is not None
        assert new_recovery_code_hash.key_wrap_salt is not None
        new_vault_key = password_hasher.derive_vault_key(new_password, new_credential.key_wrap_salt)
        new_recovery_key = password_hasher.derive_recovery_key(
            new_recovery_code, new_recovery_code_hash.key_wrap_salt
        )

        if old_vmk is not None:
            wrap_vault_master_key_for_password(self._db_manager, old_vmk, new_vault_key)
            wrap_vault_master_key_for_recovery(self._db_manager, old_vmk, new_recovery_key)
        else:
            establish_vault_master_key(self._db_manager, new_vault_key, new_recovery_key)

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

    def _succeed(self, account: UserAccount, vault_key: Optional[bytes] = None) -> AuthSession:
        self._lockout_policy.register_success(account)
        self._repository.save(account)
        logger.info("Authentication succeeded for owner_id=%s method=%s", account.owner_id, account.auth_method.value)
        return AuthSession(
            owner_id=account.owner_id,
            method=account.auth_method,
            authenticated_at=datetime.now(timezone.utc),
            vault_key=vault_key,
        )

    def _fail(self, account: UserAccount, attempted_with: str) -> None:
        self._lockout_policy.register_failure(account)
        self._repository.save(account)
        logger.warning(
            "Authentication failed for owner_id=%s (attempted with %s); failed_attempts=%d",
            account.owner_id, attempted_with, account.failed_attempts,
        )
        # Any credential buffers involved in this attempt (e.g. a private
        # key PEM / passphrase) are already wiped by whichever module held
        # them (see `security.key_authenticator`); this records the
        # guaranteed cleanup pass for the failed-authentication moment.
        cleanup(CleanupReason.FAILED_AUTHENTICATION)
