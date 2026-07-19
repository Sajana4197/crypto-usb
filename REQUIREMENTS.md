# Requirements Traceability

Maps each approved research requirement for *A Cryptographic Security Layer
for USB Storage* to the module(s) that implement it and the automated tests
that verify it. This is the artifact Phase 15 ("prepare for demonstration")
produces to confirm every requirement has actually been built and tested,
not just listed on the Dashboard page. Phase 16 ("close the UI gap") then
built read-only dashboard pages over the four requirements that were
already fully implemented and tested at the service layer but had no UI.
Phases 18-24 and the post-Phase-24 hardening pass (see below) closed every
remaining gap between the original proposal and the actual implementation —
as of this revision, all 27 rows below are fully implemented and verified,
with no known requirement gaps. `DEMO_GUIDE.md` has a click-by-click
walkthrough of all of it.

| # | Requirement | Implementing module(s) | Verified by |
|---|---|---|---|
| 1 | Hybrid encryption (AES-256-GCM content + RSA-OAEP key wrapping) | `crypto/aes_cipher.py`, `crypto/file_encryptor.py`, `crypto/key_wrapper.py`, `crypto/rsa_keypair.py` | `tests/test_aes_cipher.py`, `tests/test_file_encryptor.py`, `tests/test_key_wrapper.py`, `tests/test_rsa_keypair.py` |
| 2 | Key management & lifecycle (generate, wrap/unwrap, destroy) | `crypto/key_manager.py`, `crypto/secure_bytes.py` | `tests/test_key_manager.py`, `tests/test_secure_bytes.py` |
| 3 | Metadata-driven access control (expiry, one-time access, device binding, encrypted+HMAC'd at rest) | `metadata/models.py`, `metadata/controller.py`, `metadata/protection.py`, `metadata/repository.py`, `metadata/hashing.py` | `tests/test_metadata_*.py` |
| 4 | USB device detection & validation (removable, writable, capacity) | `usb/device_detector.py`, `usb/device_validator.py` | `tests/test_device_detector.py`, `tests/test_device_validator.py` |
| 5 | Secure storage layer (self-contained `.cusc` container, atomic write, overwrite protection, post-write verification) | `usb/secure_container.py`, `usb/storage_writer.py`, `usb/secure_storage_service.py`, `ui/pages/encryption_page.py` (the sender-side page, since Phase 24 — see below) | `tests/test_secure_container.py`, `tests/test_storage_writer.py`, `tests/test_secure_storage_service.py`, `tests/test_encryption_page.py` |
| 6 | User authentication (password and private-key, brute-force lockout, password change & one-time-recovery-code reset, deception on wrong credentials — see Phase 20 below) | `security/auth_controller.py`, `security/password_hasher.py`, `security/key_authenticator.py`, `security/lockout_policy.py`, `security/account_repository.py`, `ui/dialogs/recovery_dialog.py`, `ui/pages/settings_page.py` | `tests/test_auth_controller.py`, `tests/test_password_hasher.py`, `tests/test_key_authenticator.py`, `tests/test_lockout_policy.py`, `tests/test_account_repository.py`, `tests/test_auth_dialog.py`, `tests/test_settings_page.py` |
| 7 | Device/machine binding & fingerprinting | `validation/usb_identifier.py`, `validation/machine_fingerprint.py`, `validation/device_binding_validator.py` | `tests/test_usb_identifier.py`, `tests/test_machine_fingerprint.py`, `tests/test_device_binding_validator.py` |
| 8 | Validation engine (every access-time check: HMAC, structural integrity, file integrity, expiry, access count, device binding) | `validation/validation_engine.py` | `tests/test_validation_engine.py` |
| 9 | One-time access enforcement (crypto-shredding: decoy key swap, indistinguishable from an unused file) | `metadata/one_time_access.py` | `tests/test_one_time_access_enforcer.py` |
| 10 | Key invalidation | Same mechanism as #9 — burning a file's `wrapped_key` *is* key invalidation for that file | `tests/test_one_time_access_enforcer.py`, `tests/test_secure_access_service.py` |
| 11 | RAM-only decryption (never touches disk) | `crypto/secure_decryptor.py` | `tests/test_secure_decryptor.py` |
| 12 | Secure controlled viewer (no copy/print/export; screen-capture-resistant with an active reaction, not just detection; zoom in/out/fit-to-window — see Phase 22 and "Post-Phase-24 hardening and polish" below) | `viewer/secure_viewer_widget.py`, `viewer/screen_capture_protection.py`, `viewer/interfaces.py` | `tests/test_secure_viewer_widget.py`, `tests/test_screen_capture_protection.py`, `tests/test_viewer_interfaces.py` |
| 13 | Deception module (fabricated, indistinguishable decoy response on any denied access, including wrong login credentials — see Phase 20 below) | `deception/deception_engine.py`, `deception/content_generators.py`, `security/auth_controller.py`, `usb/secure_access_service.py` | `tests/test_deception_engine.py`, `tests/test_deception_content_generators.py`, `tests/test_auth_controller.py`, `tests/test_secure_access_service.py` |
| 14 | Usage tracking (tamper-evident, hash-chained access log, including tampering-event recording — see "Post-Phase-24 hardening and polish" below) | `tracking/tracking_service.py`, `tracking/tamper_evident_log.py`, `tracking/repository.py`, `usb/secure_access_service.py` | `tests/test_tracking_service.py`, `tests/test_tracking_models.py`, `tests/test_tracking_repository.py`, `tests/test_secure_access_service.py` |
| 15 | Secure cleanup (key/buffer zeroing on success, failure, or exit) | `crypto/secure_cleanup.py`, integrated into `security/auth_controller.py`, `usb/secure_access_service.py`, `ui/main_window.py` | `tests/test_secure_cleanup.py` |
| 16 | Full workflow integration (write → validate → decrypt → view → track → burn/deceive, sharing one metadata/tracking store) | `usb/secure_storage_service.py`, `usb/secure_access_service.py`, `ui/main_window.py`, `ui/pages/device_page.py`, `ui/pages/decryption_page.py`, `app/protection_keys.py` | `tests/test_integration_workflow.py`, `tests/test_decryption_page.py`, `tests/test_e2e_demo.py` |
| 17 | Graceful, non-crashing error handling | `app/error_handling.py`, per-page `try`/`except` blocks | `tests/test_error_handling.py`, `tests/test_device_page.py`, `tests/test_decryption_page.py` |
| 18 | Path-traversal hardening on device writes | `usb/storage_writer.py` | `tests/test_storage_writer.py` |
| 19 | Deception activation audit trail (queryable record of trigger/content-type/file_id/timestamp — never the fabricated content) | `deception/event_repository.py`, wired into `deception/deception_engine.py` | `tests/test_deception_event_repository.py`, `tests/test_deception_engine.py`, `tests/test_deception_page.py` |
| 20 | Usage Tracking dashboard (read-only view over the tamper-evident log, with a log-integrity verification action) | `ui/pages/tracking_page.py` | `tests/test_tracking_page.py` |
| 21 | Metadata dashboard (read-only view over stored metadata records) | `ui/pages/metadata_page.py` | `tests/test_metadata_page.py` |
| 22 | Access Security dashboard (read-only view over account lockout state) | `ui/pages/security_page.py`, `security/account_repository.py::list_owner_ids` | `tests/test_security_page.py`, `tests/test_account_repository.py` |
| 23 | Deception Module dashboard (read-only view over the new event audit trail) | `ui/pages/deception_page.py` | `tests/test_deception_page.py` |
| 24 | Database-file encryption at rest (SQLCipher, whole-file, machine-resident key — separate layer from #25) | `database/db_manager.py`, `database/file_key.py` | `tests/test_database.py`, `tests/test_file_key.py` |
| 25 | Credential-derived protection-key wrapping (metadata/tracking keys AES-GCM-wrapped under a key derived from the authenticated user's own password/private-key via scrypt, never stored in cleartext) | `app/protection_keys.py`, `security/password_hasher.py`, `security/auth_controller.py`, `security/auth_session.py` | `tests/test_protection_keys.py`, `tests/test_password_hasher.py`, `tests/test_auth_controller.py` |
| 26 | Screen-capture active reaction (Print Screen blanks content and closes the viewer immediately, not just detection/logging) and tampering-event audit recording (a genuine metadata/integrity failure, not a device mismatch or reuse attempt, is recorded to the usage log) | `viewer/secure_viewer_widget.py`, `viewer/screen_capture_protection.py`, `usb/secure_access_service.py`, `tracking/tracking_service.py` | `tests/test_secure_viewer_widget.py`, `tests/test_secure_access_service.py` |
| 27 | Live auto-refreshing dashboards (Dashboard, Metadata, Access Security, Deception Module, Usage Tracking all poll every 2 seconds — see "Post-Phase-24 hardening and polish" below) | `ui/pages/dashboard_page.py`, `ui/pages/metadata_page.py`, `ui/pages/security_page.py`, `ui/pages/deception_page.py`, `ui/pages/tracking_page.py` | `tests/test_dashboard_page.py`, `tests/test_metadata_page.py`, `tests/test_security_page.py`, `tests/test_deception_page.py`, `tests/test_tracking_page.py` |

## UI status (Phase 16)

All four navigation pages flagged as stubs in Phase 15 are now real,
read-only dashboards wired through `ui.main_window.MainWindow`'s shared
services, exactly like `DevicePage`/`DecryptionPage` (Phase 14):

- **Metadata** — table over `MetadataRepository` records: owner, access
  count, one-time-access policy, device binding, expiry.
- **Access Security** — table over account lockout state
  (`security.lockout_policy.LockoutPolicy`, read-only): failed attempts,
  locked/unlocked, seconds until unlock, last login.
- **Usage Tracking** — table over the tamper-evident access log
  (`tracking.tracking_service.UsageTracker.read_all_records`), plus a
  "Verify Log Integrity" button.
- **Deception Module** — table over a new, purpose-built audit trail
  (`deception.event_repository.DeceptionEventRepository`). This was the
  one place Phase 16 touched production security code: `DeceptionEngine`
  gained an optional `event_repository` parameter that records
  `(trigger, content_type, file_id, generated_at)` — never the fabricated
  `content` — after `activate()` has already decided what to fabricate.
  Nothing reads the repository back to make a decision, so this cannot
  change the engine's behavior; it is purely an audit trail of decisions
  already made. Confirmed by
  `test_recorded_event_never_stores_the_fabricated_content` and
  `test_activate_without_a_repository_does_not_require_one` (the engine
  works identically with no repository, exactly as before Phase 16).

(At the time of Phase 16, `ui/pages/encryption_page.py` was still an
orphaned file-queue preview and `ui/pages/device_page.py` was the actual
write-side page — Phase 24 later reversed this; see below.)

## Password change & recovery (Phase 17)

Extends requirement #6 (User authentication) rather than adding a new
numbered requirement: password accounts can now change their password
in-app and recover from a forgotten one, without weakening brute-force
protection.

- **Recovery code issuance** — `AuthController.register_password_account`
  now also generates a random 24-character recovery code, hashes it with
  the same scrypt scheme as the password itself (`PasswordCredential`,
  stored in the new `UserAccount.recovery_code_hash` field /
  `accounts.recovery_code_hash_json` column — migrated in place for
  pre-Phase-17 databases via `AccountRepository.ensure_schema`), and
  returns the plaintext code once. `ui/dialogs/recovery_dialog.RecoveryCodeDialog`
  shows it exactly once, right after registration succeeds, with an
  explicit "it won't be shown again" warning.
- **Change password** — `AuthController.change_password` verifies the
  current password and re-hashes the new one, gated by the same
  `LockoutPolicy` as a normal sign-in. It also *rotates* the recovery
  code — a fresh one is generated and hashed in, invalidating the old
  one — since an attacker who learned the old code should not be able
  to use it after the legitimate owner changes their password. Exposed
  in-app via a "Change Password" section on
  `ui/pages/settings_page.SettingsPage`, shown only for password
  accounts (private-key accounts see an explanatory note instead —
  their enrolled key file is their recovery mechanism); the new code is
  shown once more via the same `RecoveryCodeDialog` as registration.
- **Reset via recovery code** — `AuthController.reset_password_with_recovery_code`
  verifies the recovery code against its hash and re-hashes the new
  password, also gated by `LockoutPolicy` (repeated bad codes lock the
  account exactly like repeated bad passwords). The code is single-use:
  a successful reset also rotates in a fresh recovery code (the one just
  used stops working), shown once more via `RecoveryCodeDialog` before
  the reset dialog closes. Exposed via a "Forgot
  password?" link on the password sign-in screen
  (`ui/dialogs/recovery_dialog.PasswordResetDialog`).

Private-key accounts never get a `recovery_code_hash` — attempting a
recovery-code reset against one fails like a wrong-method sign-in
attempt (and still counts toward lockout), since there is no code to
check it against.

## Phase 18: Live Dashboard

Replaced the Dashboard's static, hardcoded "Implemented" module checklist
with live stat cards (protected files, registered accounts, deception
triggers, tracking log entries + integrity status), a recent-activity feed
merging tracking and deception events by timestamp, and quick-action buttons
to jump straight to Encrypt File / Decrypt File / Validate Device — all
reading from the same repositories every other page already uses. Landed
alongside a full theme rework (the current cyan HUD-style dark/light QSS in
`ui/theme/theme_manager.py`).

## Phase 19: Layout fixes

Several controls (Settings' theme dropdown and password fields, Decrypt &
View's passphrase field and buttons) were stretching to the full width of
the page instead of a sane fixed width, because nothing capped them inside
their `QVBoxLayout`. Fixed with explicit `setMaximumWidth()` calls; no
behavior change.

## Phase 20: Deception on wrong login credentials

Closed the gap where a wrong password or private key showed a real
"incorrect password" error instead of the deceptive response the proposal
describes. `AuthController.authenticate_password`/`authenticate_private_key`
now, on a wrong credential against an existing unlocked account, still track
the real failed-attempt count for lockout purposes but return a decoy
`AuthSession` (`is_decoy=True`) instead of raising — the login dialog closes
normally, as if it succeeded. `usb.secure_access_service.SecureAccessService.attempt_access`
gained a `force_deception` parameter so a decoy session's every subsequent
file-access attempt is served fabricated content before any real validation,
key material, or decryption is ever touched. Deliberately out of scope:
`AccountLockedError`, `AccountNotFoundError`, and the wrong-auth-method case
still raise real errors, as does `change_password`/`reset_password_with_recovery_code`
(faking those would be actively harmful, not deceptive-in-a-useful-sense).

## Phase 21: Credential-derived protection-key wrapping

Closed the gap where the metadata/tracking-log protection keys (used to
encrypt the actual stored records) were randomly generated once and stored
in cleartext, base64-encoded, in the same database they protected —
regardless of who was logged in. Now `security/password_hasher.py`'s
`derive_vault_key`/`derive_vault_key_from_bytes` (scrypt, a dedicated salt
per account, independent from the password-verification digest) derive a
"vault key" at successful login — from the password for password accounts,
from the private key + passphrase for private-key accounts — carried on
`AuthSession.vault_key`. `app/protection_keys.py`'s key loaders now
AES-GCM-wrap the actual protection keys under this vault key instead of
storing them raw, with a self-healing regeneration path if an old,
pre-Phase-21 cleartext key is ever encountered. A decoy session
(`is_decoy=True`) never gets a real vault key, so `MainWindow._build_shared_services()`
correctly returns no working metadata/tracking access for one — an
honeypot login can't read or write real records even indirectly.

## Phase 22: Screen-capture reaction timing and usage-log accuracy

Two related fixes to when the usage-tracking session actually closes.
Previously `SecureAccessService.attempt_access` called `record_close`
immediately after decryption completed — before the viewer window the user
is actually looking at was even shown — so "usage duration" measured decrypt
time, not view time, and there was no live tracking record for the viewer to
attach a screen-capture event to. `AccessOutcome` now carries
`on_view_closed`/`on_screen_capture_detected` callbacks bound to the real
record; `attempt_access` no longer closes the record itself.
`SecureViewerWidget` gained a `closed` signal and a `set_screen_capture_handler`
hook, wired by `DecryptionPage`. `_on_printscreen_detected` now blanks all
rendered content and closes the viewer immediately (a project decision —
see "Post-Phase-24 hardening and polish" below for the related
tampering-recording fix), rather than only logging the detection as before.

## Phase 23: SQLCipher database-file encryption

Closed the gap where the proposal's "SQLite/SQLCipher" storage claim wasn't
actually true — the database file itself was plain, unencrypted SQLite; only
specific record values were protected (Phase 21). `database/db_manager.py`
now connects via `sqlcipher3.dbapi2` and sets a `PRAGMA key` from
`database/file_key.py`'s `load_or_create_file_key()` — a random key
generated once and stored in its own file next to the database
(`data/.vault_key`), deliberately *not* derived from user credentials, since
the accounts table must be readable to check a password before any
credential-derived key could exist. This is a separate, outer layer from
Phase 21's credential-derived key: SQLCipher protects the whole file at
rest (e.g. against the file being copied elsewhere without the key file);
the vault key additionally protects the specific metadata/tracking values
inside it against anyone who has both files but not the right password.
`packaging/crypto_usb.spec` was updated to bundle `sqlcipher3`'s native
library into the frozen build — verified against an actual PyInstaller
build and run, not just `python main.py`.

## Phase 24: Split Device Validation and Encrypt File

Device Validation and Encrypt File used to be the same page
(`ui/pages/device_page.py`) doing both device health-checking and the real
encrypt-and-write workflow, while `ui/pages/encryption_page.py` was an
orphaned file-queue stub that was never wired to anything (its own docstring
said "encryption itself is implemented in a later phase"). Confirmed that
validating a device and writing to it were already independent operations
in the code (the write button was never gated on the validation checklist's
result), so this was a pure UI reorganization: `device_page.py` is now a
standalone device-health utility with no write path and no repository
dependencies at all; `encryption_page.py` was rebuilt to mirror
`decryption_page.py`'s structure — its own device table, the write panel
(Choose File / Write Secure Container / Export Key Pair, moved over
verbatim), and a new "Files encrypted on this device" table that lists
`.cusc` containers on the selected device and refreshes automatically after
a write. Also added, in the same phase: the one-time-access checkbox in the
write panel, threading `UsagePolicy(one_time_access=...)` into `store_file`
— previously implemented and tested end-to-end at the service layer
(#9/#10) but with no way to actually turn it on from the UI.

## Post-Phase-24 hardening and polish

A round of manual testing after Phase 24 surfaced several real defects,
fixed together (not as separately numbered phases, but real, verified
fixes, each with its own test coverage):

- **Decoy sessions couldn't reach the deception path when viewing a file.**
  Phase 21 made `MainWindow._build_shared_services()` correctly return no
  `metadata_repository` for a decoy session (since it has no vault key) —
  but `DecryptionPage._on_view_clicked` checked `metadata_repository is None`
  *before* checking whether the session was a decoy, so a wrong-password
  login got a real "no metadata repository" error instead of the intended
  fake content. Fixed by checking `is_decoy` first; `force_deception=True`
  never touches the repository anyway.
- **Multi-page PDFs only showed page 1.** `_SecurePdfView` never set a page
  mode, so `QPdfView` defaulted to `SinglePage` with no navigation control
  to reach later pages. Fixed with `PageMode.MultiPage` (continuous scroll).
- **Wrong-credential deception events were never recorded to the audit
  trail.** `app/main.py`'s `bootstrap()` constructed the real login dialog's
  `AuthController` without a `DeceptionEngine`/`DeceptionEventRepository` at
  all, so `activate()` had nothing to persist to — the honeypot worked, but
  was invisible to the Deception Module dashboard even after logging back in
  correctly. Fixed by constructing a `DeceptionEventRepository` from the
  database connection at bootstrap time (safe pre-login, since event rows
  aren't credential-wrapped) and wiring it through.
- **Important action results (write/export success or failure, key-load
  results, change-password results, log-integrity verification) now also
  show as a popup**, not just the bottom-of-page status label, which could
  be out of view depending on window size. Routine/informational messages
  (device counts, "private key loaded") intentionally stay inline-only.
- **File/key selections reset after their one-time action completes** —
  Encrypt File clears the chosen source file after a successful key export;
  Decrypt & View clears the loaded private key and passphrase after the
  viewer closes (any reason), so a new file always needs a fresh key load.
- **The secure viewer gained zoom controls** (in/out/fit-to-window, for
  text, image, and PDF content), with images and PDFs now defaulting to
  fit-to-window on first display instead of native/unscaled size.
- **Tampering events are now actually recorded to the audit trail.**
  `tracking.tracking_service.UsageTracker.record_tampering_event` existed
  and was displayed on the Usage Tracking dashboard's "Tampering" column,
  but nothing in the real access path ever called it. `SecureAccessService.attempt_access`'s
  validation-failure branch now calls it specifically when the failure's
  trigger is `METADATA_TAMPERING` or `INTEGRITY_FAILURE` — not for a device
  mismatch or a reused one-time-access file, which are different failure
  categories.
- **A real (deterministic, not flaky) bug in the device-table "nothing
  changed" refresh optimization** left the "No removable devices detected"
  summary blank on first load with zero devices, since both `device_page.py`
  and `encryption_page.py` initialized their device list to `[]`, making the
  very first refresh's "unchanged" comparison a false positive. Fixed by
  initializing to `None` (a real "never refreshed yet" sentinel) instead.
- **Dashboard, Metadata, Access Security, Deception Module, and Usage
  Tracking now auto-refresh every 2 seconds**, matching the pre-existing
  device-table polling pattern, so activity from any other page appears
  without a manual refresh. Landed alongside two real correctness fixes
  found while building it: Dashboard's stat-card snapshot now also watches
  file/account/deception counts (a file can be encrypted without ever being
  viewed, so watching only the tracking log missed that activity), and
  Usage Tracking's `refresh()` now catches `TrackingTamperError` instead of
  letting it escape the poll timer.
- **A test-suite hang, and a related production hardening fix.** Running
  the full test suite as a single `pytest` process (rather than in batches)
  reliably froze partway through — traced via `faulthandler` to a genuine
  infinite mutual recursion: a permanently-installed `sys.excepthook` (no
  test ever reset it) plus zombie, un-torn-down page objects whose
  `QTimer`-driven `refresh()` fired against a closed database connection
  from an earlier, unrelated test, raising an exception that routed to the
  global exception handler's `QMessageBox.critical()` — whose own nested
  event loop let *another* zombie timer fire and raise again, recursing
  indefinitely. Fixed in `tests/conftest.py` with two autouse fixtures that
  reset the excepthook and force garbage collection after every test. The
  same investigation surfaced a real, if narrower, production risk in
  `app/error_handling.py`: nothing prevented a second unhandled exception
  arriving while a first exception's dialog was still open from stacking a
  second nested modal dialog — bounded, not infinite, but genuinely
  reachable (e.g. a USB drive pulled mid-session while multiple
  auto-refreshing pages' timers are all live). Fixed with a `_dialog_open`
  reentrancy guard: a second exception while a dialog is already showing is
  still logged, just not shown as another stacked dialog.
- **Added an application icon** (`resources/icons/app_icon.ico`/`.png`),
  wired into `QApplication`, `MainWindow`, and the PyInstaller spec's
  `EXE(...)` icon parameter.
- **Audit timestamps were displayed in raw UTC instead of local time.**
  Every stored timestamp is correctly a UTC-aware `datetime` (standard,
  unambiguous practice for an audit trail), but the Dashboard, Metadata,
  Access Security, Deception Module, and Usage Tracking pages each
  formatted one directly with `isoformat()`, showing e.g. `18:06:14+00:00`
  when the actual local time was `23:36:14` — confusing to read live, even
  though the underlying data was correct. Fixed by converting to the
  viewer's local timezone at display time only (`utils/formatting.py`'s
  `format_datetime`, via `.astimezone()`) — storage is unchanged — and
  consolidating five near-identical private `_fmt` helpers into that one
  shared function.

## Security review (Phase 15)

A full manual review of `app/`, `core/`, `crypto/`, `database/`, `deception/`,
`metadata/`, `security/`, `tracking/`, `usb/`, `validation/`, `viewer/`, and
`ui/` found no medium/high-severity issues:

- No secret (password, passphrase, key material, session token) reaches a
  log line, exception message, or UI string anywhere in the codebase.
- Every SQL query is parameterized; no string-built SQL exists.
- No `eval`/`exec`/`pickle`/`subprocess(shell=True)`/`os.system`.
- No hardcoded credentials.
- Every AES-GCM nonce and every key/salt is generated fresh via `os.urandom`;
  `random` (non-cryptographic) is used only for picking *which* fake
  decoy content to fabricate, never for anything security-relevant.
- Atomic, temp-file-then-`os.replace` writes with cleanup on failure; no
  plaintext ever touches disk.
- `.gitignore` correctly excludes `data/`, `logs/`, `.venv/`.

One low-severity, purely defensive-depth gap was found and fixed: filename
path-traversal hardening in `usb/storage_writer.SecureStorageWriter.write_container`
(the sole caller always supplies a server-generated UUID, so this was not
exploitable today, but the method itself had no guard against a future
caller passing an unsanitized name).
