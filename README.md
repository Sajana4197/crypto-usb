# A Cryptographic Security Layer for USB Storage

Final-year research project: a secure software layer that protects confidential
files stored on USB devices using hybrid encryption (AES + RSA/ECC), secure
metadata-driven access control, device validation, one-time access enforcement,
key invalidation, a deception module, usage tracking, and RAM-only decryption.

## Status

**Phase 1 — Foundation** is complete: project scaffolding, configuration,
logging, SQLite initialization, and the PySide6 UI shell (theme manager,
navigation, placeholder pages). No cryptographic functionality is implemented
yet — that begins in the Crypto Core phase.

## Requirements

- Python 3.11+ (project targets 3.13; developed against 3.11 due to local
  availability — recommend upgrading to 3.13 before final submission)
- Windows (uses `pywin32` for device/OS integration in later phases)

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

## Testing

```powershell
pytest
```

## Project layout

```
app/            Application composition root: entry point, config system
core/           Cross-cutting foundation: constants, logging
crypto/         Hybrid AES + RSA/ECC encryption engine (future phase)
metadata/       Secure metadata-driven access control (future phase)
database/       SQLite initialization and connection management
security/       One-time access enforcement, key invalidation, RAM-only decryption (future phase)
viewer/         RAM-only secure file viewer (future phase)
usb/            USB device validation (future phase)
deception/      Deception module (future phase)
tracking/       Usage monitoring and access tracking (future phase)
validation/     User authentication and device validation (future phase)
ui/             PySide6 UI: main window, theme manager, navigation, pages
utils/          Shared utility helpers (path resolution)
resources/      Icons and static assets
tests/          Automated tests
```

## Data locations

- SQLite database: `data/crypto_usb.db`
- Application config: `data/config.json`
- Logs: `logs/app.log`

Both `data/` and `logs/` are created automatically at runtime and are
git-ignored.
