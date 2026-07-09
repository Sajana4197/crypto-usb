"""Filesystem path resolution helpers.

Centralizes every on-disk location the application depends on (project root,
resources, icons, assets, runtime data, logs) so no other module needs to
hardcode or re-derive a path.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_project_root() -> Path:
    return PROJECT_ROOT


def get_resources_dir() -> Path:
    return PROJECT_ROOT / "resources"


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


def get_icon(name: str) -> Path:
    """Resolve an icon file by name inside the icons directory."""
    return get_icons_dir() / name
