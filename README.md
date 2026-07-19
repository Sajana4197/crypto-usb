# A Cryptographic Security Layer for USB Storage

Final-year research project: a secure software layer that protects confidential
files stored on USB devices using hybrid encryption (AES + RSA/ECC), secure
metadata-driven access control, device validation, one-time access enforcement,
key invalidation, a deception module, usage tracking, and RAM-only decryption.

## Status

**Feature-complete against every proposal requirement, with no known gaps.**
The sender side (**Encrypt File** page: validate a device, encrypt a file,
wrap its key, export the key pair, store it as a `.cusc` secure container
bound to that device) and the receiver side (**Decrypt & View** page:
authenticate, load the key, validate, decrypt strictly in RAM, view once)
share the same metadata repository, protection keys, and usage tracker, so a
file written on one side can be validated and read back on the other end to
end. **Device Validation** is a separate, standalone device-health check —
validating a device and writing to one are independent operations, not a
sequential gate.

Beyond the core write/read workflow, the project also implements:

- **Deception as a first-class security layer, not just a slogan** — wrong
  login credentials silently grant a decoy session that serves fabricated
  content for every subsequent action, indistinguishable from success to an
  attacker; device mismatch, metadata tampering, and one-time-access reuse
  are independently detected and deceived the same way. Every trigger is
  recorded to an audit trail the legitimate operator can review (Deception
  Module page), even though the attacker never sees anything is wrong.
- **Two-layer storage encryption** — the SQLite database file itself is
  SQLCipher-encrypted at rest (a locally-generated, machine-resident key,
  since the account table must be readable before login can even check a
  password), and on top of that, the specific metadata/usage-log protection
  keys are further wrapped under a key derived from the authenticated user's
  own credentials via scrypt — so even someone with both the raw database
  file and its file-level key still can't read protected records without
  the correct password or private key.
- **Live, auto-refreshing dashboards** — Dashboard, Metadata, Access
  Security, Deception Module, and Usage Tracking all poll their underlying
  repositories every 2 seconds, so activity started from any other page
  shows up automatically, without a manual refresh.
- **A hardened secure viewer** — RAM-only decryption, disabled
  copy/paste/print/context-menu, zoom in/out/fit-to-window controls, and a
  Print Screen reaction that blanks and closes the viewer immediately
  (detection-only is a genuine platform limit on Windows — this reacts as
  fast as the platform allows rather than merely logging it).

See `REQUIREMENTS.md` for the full requirement-by-requirement traceability
table and write-ups of every phase, and `DEMO_GUIDE.md` for a click-by-click
walkthrough of every feature mapped to the requirement it proves.

Implemented modules (see the in-app Dashboard for live counts of these):

- Hybrid Encryption (AES-256-GCM + RSA key wrapping)
- Metadata-Driven Access Control
- Device Validation (USB + machine fingerprinting)
- Secure Storage Layer (encrypted `.cusc` containers, SQLCipher-encrypted database)
- User Authentication (password and private-key, with deception on wrong credentials)
- Validation Engine (device, integrity, tampering checks)
- One-Time Access Enforcement (with a UI toggle on the sender side)
- Key Invalidation (crypto-shredding)
- RAM-Only Decryption
- Secure Controlled Viewer (zoom, copy/print lockdown, screen-capture reaction)
- Deception Module (indistinguishable decoy responses on repeat/invalid/unauthorized access)
- Usage Tracking (tamper-evident access log, including tampering-event recording)
- Secure Cleanup (RAM/key wiping on success, failure, or exit)
- Full Workflow Integration

788 automated tests pass (`pytest`, single process, no batching required),
spanning unit, integration, UI-level, and end-to-end demo-script coverage,
plus a clean `ruff check .`. Every navigation page is a real, working view —
`ui/pages/encryption_page.py` is the actual sender workflow (not a stub);
`ui/pages/device_page.py` is a standalone device-validation utility with no
write path of its own.

## Requirements

- Python 3.11+
- Windows (uses `pywin32` for device/OS integration)

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running

```powershell
python main.py
```

On first launch you'll be asked to create a local account (password or
private-key). See `REQUIREMENTS.md` for what each part of the application
does, and `packaging/README.md` if you want a standalone `.exe` instead of
running from source.

## Testing

```powershell
pip install -r requirements-dev.txt   # adds ruff (lint) and pyinstaller (packaging)
pytest
ruff check app core crypto database deception metadata security tracking usb validation viewer ui utils main.py
```

## Project layout

```
app/            Application composition root: entry point, config, persisted protection keys, error handling
core/           Cross-cutting foundation: constants, logging
crypto/         Hybrid AES-256-GCM + RSA/ECC encryption engine, key wrapping, secure cleanup
metadata/       Secure metadata-driven access control and integrity protection
database/       SQLite initialization and connection management
security/       Authentication sessions, one-time access enforcement, key invalidation
viewer/         RAM-only secure file viewer
usb/            USB device detection, secure storage/access services
deception/      Deception module (fabricated decoy responses on denied access)
tracking/       Usage monitoring and tamper-evident access log
validation/     Device/machine fingerprinting and validation engine
ui/             PySide6 UI: main window, theme manager, navigation, pages, busy/progress widgets
utils/          Shared utility helpers (path resolution)
resources/      Icons and static assets
packaging/      PyInstaller spec + Inno Setup installer script (see packaging/README.md)
tests/          Automated tests (788 passing)
REQUIREMENTS.md Requirement-by-requirement traceability + security review notes
DEMO_GUIDE.md   Step-by-step demonstration script, every feature mapped to the requirement it proves
```

## Data locations

- SQLite database (SQLCipher-encrypted): `data/crypto_usb.db`
- Database file-encryption key: `data/.vault_key`
- Application config: `data/config.json`
- Logs: `logs/app.log`

Both `data/` and `logs/` are created automatically at runtime next to
`main.py` (or next to the installed `.exe` in a packaged build — see
`packaging/README.md`) and are git-ignored. Deleting `data/` resets the
application to a fresh first-run state (no accounts, no stored files) —
useful for a clean demo, but note that any `.cusc` containers already
written to a USB device remain on that device and cannot be decrypted again
once their protection keys are gone.

## Packaging

A standalone Windows executable can be built with PyInstaller, and an
installer with Inno Setup. See `packaging/README.md` — including two
real packaging bugs (a third-party-library name collision, and a
project-root path resolution bug) this process found and fixed, verified
against an actual built-and-run executable.
