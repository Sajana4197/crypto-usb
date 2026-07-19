# PyInstaller spec for A Cryptographic Security Layer for USB Storage.
#
# Builds a single-folder, windowed (no console) executable. Bundles
# `resources/` (icons/assets) as read-only application data; `data/`,
# `logs/`, and `config.json` are deliberately NOT bundled — those are
# created at runtime in the installed application's own directory (see
# `utils/paths.py`), exactly as they are when running from source.
#
# Build from the repository root:
#   pyinstaller packaging/crypto_usb.spec --noconfirm
#
# Output: dist/CryptoUSB/CryptoUSB.exe

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_dynamic_libs

block_cipher = None

REPO_ROOT = Path(SPECPATH).resolve().parent

a = Analysis(
    [str(REPO_ROOT / "main.py")],
    pathex=[str(REPO_ROOT)],
    # `sqlcipher3._sqlite3` (imported by `sqlcipher3.dbapi2`, which
    # `database.db_manager` imports directly — Phase 23) is a compiled
    # extension module PyInstaller's static analysis does find on its
    # own, but `collect_dynamic_libs` is added defensively in case the
    # wheel's build ever links against a separate OpenSSL/SQLCipher DLL
    # instead of a single statically-linked .pyd.
    binaries=collect_dynamic_libs("sqlcipher3"),
    datas=[
        (str(REPO_ROOT / "resources"), "resources"),
    ],
    hiddenimports=[
        # win32 modules are imported lazily (inside try/except) by
        # usb.device_detector / validation.usb_identifier /
        # validation.machine_fingerprint, so PyInstaller's static
        # analysis won't discover them on its own.
        "win32api",
        "win32file",
        "winreg",
        # Belt-and-braces alongside `database.db_manager`'s direct
        # `import sqlcipher3.dbapi2 as sqlcipher` — see the `binaries=`
        # comment above.
        "sqlcipher3.dbapi2",
    ],
    # `pyinstaller_hooks/hook-usb.py` overrides a community hook meant for
    # the third-party PyUSB library — see that file's comment. It must be
    # searched before PyInstaller's own contrib hooks to take effect.
    hookspath=[str(REPO_ROOT / "packaging" / "pyinstaller_hooks")],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CryptoUSB",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(REPO_ROOT / "resources" / "icons" / "app_icon.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CryptoUSB",
)
