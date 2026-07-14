# Requirements Traceability

Maps each approved research requirement for *A Cryptographic Security Layer
for USB Storage* to the module(s) that implement it and the automated tests
that verify it. This is the artifact Phase 15 ("prepare for demonstration")
produces to confirm every requirement has actually been built and tested,
not just listed on the Dashboard page.

| # | Requirement | Implementing module(s) | Verified by |
|---|---|---|---|
| 1 | Hybrid encryption (AES-256-GCM content + RSA-OAEP key wrapping) | `crypto/aes_cipher.py`, `crypto/file_encryptor.py`, `crypto/key_wrapper.py`, `crypto/rsa_keypair.py` | `tests/test_aes_cipher.py`, `tests/test_file_encryptor.py`, `tests/test_key_wrapper.py`, `tests/test_rsa_keypair.py` |
| 2 | Key management & lifecycle (generate, wrap/unwrap, destroy) | `crypto/key_manager.py`, `crypto/secure_bytes.py` | `tests/test_key_manager.py`, `tests/test_secure_bytes.py` |
| 3 | Metadata-driven access control (expiry, one-time access, device binding, encrypted+HMAC'd at rest) | `metadata/models.py`, `metadata/controller.py`, `metadata/protection.py`, `metadata/repository.py`, `metadata/hashing.py` | `tests/test_metadata_*.py` |
| 4 | USB device detection & validation (removable, writable, capacity) | `usb/device_detector.py`, `usb/device_validator.py` | `tests/test_device_detector.py`, `tests/test_device_validator.py` |
| 5 | Secure storage layer (self-contained `.cusc` container, atomic write, overwrite protection, post-write verification) | `usb/secure_container.py`, `usb/storage_writer.py`, `usb/secure_storage_service.py` | `tests/test_secure_container.py`, `tests/test_storage_writer.py`, `tests/test_secure_storage_service.py` |
| 6 | User authentication (password and private-key, brute-force lockout) | `security/auth_controller.py`, `security/password_hasher.py`, `security/key_authenticator.py`, `security/lockout_policy.py`, `security/account_repository.py` | `tests/test_auth_controller.py`, `tests/test_password_hasher.py`, `tests/test_key_authenticator.py`, `tests/test_lockout_policy.py`, `tests/test_account_repository.py` |
| 7 | Device/machine binding & fingerprinting | `validation/usb_identifier.py`, `validation/machine_fingerprint.py`, `validation/device_binding_validator.py` | `tests/test_usb_identifier.py`, `tests/test_machine_fingerprint.py`, `tests/test_device_binding_validator.py` |
| 8 | Validation engine (every access-time check: HMAC, structural integrity, file integrity, expiry, access count, device binding) | `validation/validation_engine.py` | `tests/test_validation_engine.py` |
| 9 | One-time access enforcement (crypto-shredding: decoy key swap, indistinguishable from an unused file) | `metadata/one_time_access.py` | `tests/test_one_time_access_enforcer.py` |
| 10 | Key invalidation | Same mechanism as #9 — burning a file's `wrapped_key` *is* key invalidation for that file | `tests/test_one_time_access_enforcer.py`, `tests/test_secure_access_service.py` |
| 11 | RAM-only decryption (never touches disk) | `crypto/secure_decryptor.py` | `tests/test_secure_decryptor.py` |
| 12 | Secure controlled viewer (no copy/print/export/screenshot-resistant) | `viewer/secure_viewer_widget.py`, `viewer/screen_capture_protection.py`, `viewer/interfaces.py` | `tests/test_secure_viewer_widget.py`, `tests/test_screen_capture_protection.py`, `tests/test_viewer_interfaces.py` |
| 13 | Deception module (fabricated, indistinguishable decoy response on any denied access) | `deception/deception_engine.py`, `deception/content_generators.py` | `tests/test_deception_engine.py`, `tests/test_deception_content_generators.py` |
| 14 | Usage tracking (tamper-evident, hash-chained access log) | `tracking/tracking_service.py`, `tracking/tamper_evident_log.py`, `tracking/repository.py` | `tests/test_tracking_service.py`, `tests/test_tracking_models.py`, `tests/test_tracking_repository.py` |
| 15 | Secure cleanup (key/buffer zeroing on success, failure, or exit) | `crypto/secure_cleanup.py`, integrated into `security/auth_controller.py`, `usb/secure_access_service.py`, `ui/main_window.py` | `tests/test_secure_cleanup.py` |
| 16 | Full workflow integration (write → validate → decrypt → view → track → burn/deceive, sharing one metadata/tracking store) | `usb/secure_storage_service.py`, `usb/secure_access_service.py`, `ui/main_window.py`, `ui/pages/device_page.py`, `ui/pages/decryption_page.py`, `app/protection_keys.py` | `tests/test_integration_workflow.py`, `tests/test_decryption_page.py`, `tests/test_e2e_demo.py` |
| 17 | Graceful, non-crashing error handling | `app/error_handling.py`, per-page `try`/`except` blocks | `tests/test_error_handling.py`, `tests/test_device_page.py`, `tests/test_decryption_page.py` |
| 18 | Path-traversal hardening on device writes | `usb/storage_writer.py` | `tests/test_storage_writer.py` |

## Known UI gaps (documented, not silently skipped)

Every requirement above is fully implemented and tested **at the service
layer** and reachable through the two working end-to-end pages (Device
Validation for writing, Decrypt & View for reading). Four navigation pages
are still placeholder stubs with no dashboard UI, even though the data they
would display is already being correctly recorded:

- **Metadata** — no browsing UI over `MetadataRepository` records.
- **Access Security** — no UI over account lockout state (`security.lockout_policy`).
- **Deception Module** — deception events are logged (`core.logger`) but not
  surfaced in a dashboard; no separate event store exists to query (adding
  one was judged out of scope for a "polish, don't redesign" phase).
- **Usage Tracking** — no UI over the tamper-evident log; `UsageTracker`
  records every attempt correctly (see `tests/test_integration_workflow.py`),
  it's just not visualized yet.

These were flagged as a known gap before Phase 15 began and are explicitly
out of scope for it (Phase 15's task list is polish/hardening/packaging, not
new dashboards) — see `ui/pages/metadata_page.py`, `security_page.py`,
`deception_page.py`, `tracking_page.py` for the honest "not yet implemented"
placeholders. `ui/pages/encryption_page.py` is similarly an orphaned queue
preview; `ui/pages/device_page.py` is the actual working write-side page.

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
