# Packaging

Builds a standalone Windows application (no separate Python install
required to run it) and, optionally, a single-file installer.

## 1. Build the executable (PyInstaller)

```powershell
pip install -r requirements-dev.txt   # adds pyinstaller (and ruff) as build-time-only tools
pyinstaller packaging/crypto_usb.spec --noconfirm --distpath dist --workpath build
```

Output: `dist/CryptoUSB/CryptoUSB.exe`, plus its bundled `_internal/`
directory (PySide6, `cryptography`, `sqlcipher3`'s native extension,
`resources/` — including the application icon — etc.). Run it directly —
`data/` (SQLCipher-encrypted `crypto_usb.db`, its `.vault_key` file,
`config.json`) and `logs/` are created next to the `.exe` on first launch,
exactly as they are next to `main.py` when running from source.

Note: `build/crypto_usb/CryptoUSB.exe` (the intermediate build step's
output, *before* `COLLECT` assembles the final `_internal/` folder) is
**not** a runnable app on its own — it will fail with a "Failed to load
Python DLL" error if launched directly. Only `dist/CryptoUSB/CryptoUSB.exe`
is the complete, distributable build; `build/` is safe to delete and is
regenerated on every run.

This has been built and smoke-tested end to end in this environment: the
executable launches, reaches the authentication dialog, and correctly
creates a genuinely SQLCipher-encrypted `data/crypto_usb.db` (verified by
inspecting the raw file header — random ciphertext, not the plaintext
`SQLite format 3` magic string every normal SQLite file starts with) and
`logs/app.log` next to itself.

### Packaging-specific bugs this build surfaced and fixed

Building for real is what caught these — none were visible running from
source, and all are now covered by the fixes described below (no automated
test can exercise a frozen build, so this section is the record of that
verification):

1. **`usb`/PyUSB name collision.** `pyinstaller-hooks-contrib` ships a
   build-time hook *and* a runtime hook for a top-level package named
   `usb`, written for the third-party PyUSB library. This project's own
   `usb/` package (USB device detection) has the same top-level name but
   no relation to PyUSB, so the stock hooks crashed the frozen build
   (`ModuleNotFoundError: No module named 'usb.backend'`) at startup.
   Fixed with two no-op overrides in `packaging/pyinstaller_hooks/`
   (`hook-usb.py` and `rthooks.dat` + `rthooks/pyi_rth_usb_noop.py`),
   wired in via the spec's `hookspath`.
2. **`PROJECT_ROOT` path resolution.** `utils/paths.py` derived the
   project root from `Path(__file__).resolve().parent.parent`, which
   resolves to somewhere inside PyInstaller's bundled internals when
   frozen, not a stable, writable location next to the installed `.exe` —
   `data/`/`logs/` would have been created in the wrong place (or
   silently failed). Fixed by anchoring to `sys.executable`'s directory
   when `sys.frozen` is set, and to `sys._MEIPASS` specifically for the
   bundled, read-only `resources/` directory.
3. **`sqlcipher3` native library bundling.** Added when database-file
   encryption (SQLCipher) was introduced — `sqlcipher3.dbapi2` is a
   compiled extension module, not pure Python. The spec's `binaries=`
   uses `collect_dynamic_libs("sqlcipher3")` and `hiddenimports` includes
   `sqlcipher3.dbapi2` defensively, in case a future wheel links against a
   separate OpenSSL/SQLCipher DLL instead of a single statically-linked
   `.pyd`. Verified by actually building and running the frozen `.exe` and
   confirming the database opens and is genuinely encrypted, not just that
   the build completes without error.

## 2. Build the installer (optional, Windows-only tool)

Requires [Inno Setup](https://jrsoftware.org/isinfo.php) (a separate
Windows application — not pip-installable, and not run as part of this
repository's automated build; `packaging/installer.iss` is prepared and
ready but has not been compiled in this environment).

```powershell
iscc packaging/installer.iss
```

Output: `packaging/Output/CryptoUSB-Setup.exe`. Installs per-user (no
administrator elevation required), with a Start Menu entry and an
optional desktop shortcut. Uninstalling also removes the installed
`data/` and `logs/` directories — deliberately: this is a security tool,
and uninstalling it should not silently leave an account database and
access log behind (see the script's `[UninstallDelete]` section).

## Requirements for a rebuild

- Python 3.11+ with this project's `requirements.txt` installed
- `pyinstaller` (not in `requirements.txt` — it's a build-time-only tool,
  not a runtime dependency; install it separately, as above)
- Windows (this project is Windows-only already — see the main README)
