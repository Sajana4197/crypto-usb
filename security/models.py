"""Data model for a local user account and its authentication credential.

An account holds exactly one credential: either a `PasswordCredential`
(salt + scrypt digest, never the password itself) or a
`PrivateKeyCredential` (the enrolled public key only — the matching
private key is never stored by the application, see
`security.key_authenticator`). `UserAccount` also carries the
brute-force lockout state so `security.lockout_policy` has somewhere
to persist it between attempts.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union


class AuthMethod(str, Enum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"


@dataclass
class PasswordCredential:
    """A scrypt password digest. Never holds the plaintext password."""

    salt: bytes
    digest: bytes
    n: int
    r: int
    p: int
    key_len: int
    # Independent salt for deriving the vault key (see
    # `security.password_hasher.derive_vault_key`) that wraps the app's
    # metadata/tracking protection keys. Kept separate from `salt` so the
    # vault key is cryptographically independent from the password
    # verification digest. `None` for accounts persisted before this was
    # introduced; `security.auth_controller` self-heals it on first login.
    key_wrap_salt: Optional[bytes] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "digest": base64.b64encode(self.digest).decode("ascii"),
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "key_len": self.key_len,
            "key_wrap_salt": (
                base64.b64encode(self.key_wrap_salt).decode("ascii") if self.key_wrap_salt is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PasswordCredential":
        key_wrap_salt = data.get("key_wrap_salt")
        return cls(
            salt=base64.b64decode(data["salt"]),
            digest=base64.b64decode(data["digest"]),
            n=data["n"],
            r=data["r"],
            p=data["p"],
            key_len=data["key_len"],
            key_wrap_salt=base64.b64decode(key_wrap_salt) if key_wrap_salt is not None else None,
        )


@dataclass
class PrivateKeyCredential:
    """The enrolled public key for challenge-response private-key authentication."""

    public_key_pem: bytes
    # See `PasswordCredential.key_wrap_salt` — same purpose, derived from
    # the private key PEM + passphrase instead of a password.
    key_wrap_salt: Optional[bytes] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_key_pem": base64.b64encode(self.public_key_pem).decode("ascii"),
            "key_wrap_salt": (
                base64.b64encode(self.key_wrap_salt).decode("ascii") if self.key_wrap_salt is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PrivateKeyCredential":
        key_wrap_salt = data.get("key_wrap_salt")
        return cls(
            public_key_pem=base64.b64decode(data["public_key_pem"]),
            key_wrap_salt=base64.b64decode(key_wrap_salt) if key_wrap_salt is not None else None,
        )


Credential = Union[PasswordCredential, PrivateKeyCredential]


@dataclass
class UserAccount:
    owner_id: str
    auth_method: AuthMethod
    credential: Credential
    created_at: datetime
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    # Only ever set for AuthMethod.PASSWORD accounts. Private-key accounts
    # have no recovery code — the enrolled private key file already is
    # their recovery mechanism. Hashed with the same scrypt scheme as the
    # password itself (see `security.password_hasher`); the plaintext code
    # is returned once, at registration time, and never stored.
    recovery_code_hash: Optional[PasswordCredential] = None
