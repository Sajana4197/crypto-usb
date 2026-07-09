"""Application configuration system.

Loads and persists user-editable settings (theme, log level, window size)
as JSON in the data directory, falling back to defaults when no config
file exists yet or a field is missing/invalid.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from core.constants import DEFAULT_LOG_LEVEL
from utils.paths import get_config_path


@dataclass
class AppConfig:
    theme: str = "dark"
    log_level: str = DEFAULT_LOG_LEVEL
    window_width: int = 1200
    window_height: int = 760
    last_page: str = "dashboard"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AppConfig":
        known_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


class ConfigManager:
    """Loads, holds, and persists the application's :class:`AppConfig`."""

    def __init__(self) -> None:
        self._path = get_config_path()
        self.config = self._load()

    def _load(self) -> AppConfig:
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                return AppConfig.from_dict(data)
            except (json.JSONDecodeError, OSError, TypeError):
                return AppConfig()
        return AppConfig()

    def save(self) -> None:
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(self.config.to_dict(), fh, indent=2)

    def update(self, **kwargs) -> None:
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        self.save()
