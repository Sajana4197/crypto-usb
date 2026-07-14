# A Cryptographic Security Layer for USB Storage

Final-year research project: a secure software layer that protects confidential
files stored on USB devices using hybrid encryption (AES + RSA/ECC), secure
metadata-driven access control, device validation, one-time access enforcement,
key invalidation, a deception module, usage tracking, and RAM-only decryption.

## Status

**All 16 phases are complete.** The write side (Device Validation page:
encrypt a file, wrap its key, store it as a `.cusc` secure container bound to
a specific USB device) and the read side (Decrypt & View page: authenticate,
validate, decrypt strictly in RAM, view once) share the same metadata
repository, protection keys, and usage tracker, so a file written by one page
can be validated and read back by the other end to end. Phase 15 hardened,
polished, and packaged the application for demonstration; Phase 16 then
added read-only dashboard pages (Metadata, Access Security, Deception
Module, Usage Tracking) over data that was already being correctly recorded
— see `REQUIREMENTS.md` for the full requirement-by-requirement traceability
table and security review notes.

Implemented modules (see the in-app Dashboard for the same list):

- Hybrid Encryption (AES-256-GCM + RSA/ECC key wrapping)
- Metadata-Driven Access Control
- Device Validation (USB + machine fingerprinting)
- Secure Storage Layer (encrypted `.cusc` containers)
- User Authentication (password and private-key)
- Validation Engine (device, integrity, tampering checks)
- One-Time Access Enforcement
- Key Invalidation (crypto-shredding)
- RAM-Only Decryption
- Secure Controlled Viewer
- Deception Module (indistinguishable decoy responses on repeat/invalid access)
- Usage Tracking (tamper-evident access log)
- Secure Cleanup (RAM/key wiping on success, failure, or exit)
- Full Workflow Integration

594 automated tests pass (`pytest`), spanning unit, integration, UI-level,
and end-to-end demo-script coverage. Every navigation page is now a real,
working view — see "UI status (Phase 16)" in `REQUIREMENTS.md` for exactly
what each dashboard shows. `ui/pages/encryption_page.py` remains an orphaned
file-queue preview (`ui/pages/device_page.py` is the actual working
write-side page) — the one documented, intentional exception.

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
tests/          Automated tests (553 passing)
REQUIREMENTS.md Requirement-by-requirement traceability + security review notes
```

## Data locations

- SQLite database: `data/crypto_usb.db`
- Application config: `data/config.json`
- Logs: `logs/app.log`

Both `data/` and `logs/` are created automatically at runtime next to
`main.py` (or next to the installed `.exe` in a packaged build — see
`packaging/README.md`) and are git-ignored.

## Packaging

A standalone Windows executable can be built with PyInstaller, and an
installer with Inno Setup. See `packaging/README.md` — including two
real packaging bugs (a third-party-library name collision, and a
project-root path resolution bug) this process found and fixed, verified
against an actual built-and-run executable.
