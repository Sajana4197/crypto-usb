"""User Authentication.

- `models` — `UserAccount` and its credential types.
- `password_hasher` — scrypt password hashing/verification.
- `key_authenticator` — RSA-PSS challenge/response private-key authentication.
- `lockout_policy` — brute-force protection via escalating lockout.
- `account_repository` — SQLite persistence for accounts.
- `auth_controller` — the single entry point: register/authenticate.
- `auth_session` — `AuthSession` / `SessionManager`, consumed by future
  validation and access-control phases (one-time access enforcement, key
  invalidation). Authentication does not decrypt or touch files itself.
"""
