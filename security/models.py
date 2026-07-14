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

    def to_dict(self) -> dict[str, Any]:
        return {
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "digest": base64.b64encode(self.digest).decode("ascii"),
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "key_len": self.key_len,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PasswordCredential":
        return cls(
            salt=base64.b64decode(data["salt"]),
            digest=base64.b64decode(data["digest"]),
            n=data["n"],
            r=data["r"],
            p=data["p"],
            key_len=data["key_len"],
        )


@dataclass
class PrivateKeyCredential:
    """The enrolled public key for challenge-response private-key authentication."""

    public_key_pem: bytes

    def to_dict(self) -> dict[str, Any]:
        return {"public_key_pem": base64.b64encode(self.public_key_pem).decode("ascii")}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PrivateKeyCredential":
        return cls(public_key_pem=base64.b64decode(data["public_key_pem"]))


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
