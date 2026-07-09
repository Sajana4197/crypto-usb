"""Centralized logging configuration.

Every module obtains its logger via :func:`get_logger` after
:func:`setup_logging` has been called once during application bootstrap.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from core.constants import DEFAULT_LOG_LEVEL, LOG_FILE_NAME
from utils.paths import get_logs_dir

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup_logging(level: str = DEFAULT_LOG_LEVEL) -> None:
    """Configure the root logger with a rotating file handler and console output.

    Safe to call multiple times; only the first call takes effect.
    """
    global _configured
    if _configured:
        return

    log_level = getattr(logging, level.upper(), logging.INFO)
    log_path = get_logs_dir() / LOG_FILE_NAME

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_path, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger. Calls :func:`setup_logging` if needed."""
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
