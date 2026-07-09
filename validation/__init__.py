"""The Validation Engine.

- `machine_fingerprint` — stable host identity (Windows MachineGuid).
- `usb_identifier` — stable USB device identity (volume serial + filesystem + capacity).
- `device_binding_validator` — device/machine binding checks; distinguishes
  a cloned USB from an unauthorized device from a machine mismatch.
- `validation_engine` — orchestrates access count, expiry, device binding,
  machine fingerprint, USB identifier, metadata integrity, HMAC, and file
  integrity checks into one `ValidationReport`. Read-only: does not mutate
  access state and does not decrypt files. What happens on a rejected
  access (deception-module behavior) is a later phase.
"""
