"""Filesystem path resolution helpers.

Centralizes every on-disk location the application depends on (project root,
resources, icons, assets, runtime data, logs) so no other module needs to
hardcode or re-derive a path.
"""

from __future__ import annotations

import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    # Running from a PyInstaller build: `__file__`-relative resolution
    # breaks here, since this module is imported from inside the bundled
    # PYZ archive rather than from a real file on disk next to `main.py`
    # (a naive `Path(__file__).resolve().parent.parent` would resolve to
    # somewhere inside the frozen bundle's internals, not a stable,
    # writable location next to the installed executable). Anchor
    # writable runtime data (`data/`, `logs/`) to the executable's own
    # directory instead — same directory they live in when running from
    # source next to `main.py`.
    PROJECT_ROOT = Path(sys.executable).resolve().parent
    # Bundled, read-only assets (`resources/`) are unpacked by PyInstaller
    # to `sys._MEIPASS` (the onedir build's `_internal/` folder, or a
    # temp extraction directory for a onefile build) — see
    # `packaging/crypto_usb.spec`'s `datas` entry — which is not
    # necessarily the same directory as the executable itself.
    _BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    _BUNDLE_ROOT = PROJECT_ROOT


def get_project_root() -> Path:
    return PROJECT_ROOT


def get_resources_dir() -> Path:
    return _BUNDLE_ROOT / "resources"


def get_icons_dir() -> Path:
    return get_resources_dir() / "icons"


def get_assets_dir() -> Path:
    return get_resources_dir() / "assets"


def get_data_dir() -> Path:
    path = PROJECT_ROOT / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_logs_dir() -> Path:
    path = PROJECT_ROOT / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_config_path() -> Path:
    from core.constants import CONFIG_FILE_NAME

    return get_data_dir() / CONFIG_FILE_NAME


def get_database_path() -> Path:
    from core.constants import DATABASE_FILE_NAME

    return get_data_dir() / DATABASE_FILE_NAME


def get_vault_key_path() -> Path:
    """The SQLCipher file-encryption key's on-disk location — a random,
    locally-generated key (see `database.file_key`), not derived from any
    user credential. Separate from `data/crypto_usb.db` itself so the key
    and the encrypted file it unlocks are two distinct pieces of state."""
    return get_data_dir() / ".vault_key"


def get_icon(name: str) -> Path:
    """Resolve an icon file by name inside the icons directory."""
    return get_icons_dir() / name
