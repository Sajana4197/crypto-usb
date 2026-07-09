"""Secure Storage Layer: USB device detection/validation and secure container I/O.

- `device_detector` — enumerates attached removable devices.
- `device_validator` — confirms a device is safe to write to.
- `secure_container` — the `.cusc` container format (encrypted file + wrapped
  key + encrypted metadata, never plaintext) and its integrity verification.
- `storage_writer` — atomic, overwrite-protected, self-verifying writes.
- `secure_storage_service` — orchestrates the above into one operation.
"""
