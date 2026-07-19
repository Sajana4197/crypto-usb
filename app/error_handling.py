"""Global, last-resort error handling for the running application.

Anything that reaches `install_excepthook`'s handler is a bug — every
*expected* failure (wrong password, tampered file, USB unplugged,
weak passphrase, ...) is already caught and handled at the specific
call site where it can happen (see `security.exceptions`,
`usb.exceptions`, `crypto.exceptions`, and the `try`/`except` blocks in
`ui.pages`). This module exists so an *unexpected* exception during a
live demonstration shows the presenter a plain message box and keeps
the application running, instead of PySide6's default behavior for an
exception escaping a Qt slot: printed to a console window nobody in
the room can see, with the whole application then in an undefined,
possibly-frozen state.
"""

from __future__ import annotations

import sys
import traceback
from types import TracebackType
from typing import Optional, Type

from core.logger import get_logger

logger = get_logger(__name__)

_installed = False
_dialog_open = False


def install_excepthook() -> None:
    """Route any exception that escapes Qt's event loop to the log and a
    message box instead of crashing silently. Safe to call more than
    once; only the first call takes effect.
    """
    global _installed
    if _installed:
        return
    _installed = True

    def _handle(
        exc_type: Type[BaseException], exc_value: BaseException, exc_tb: Optional[TracebackType]
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return

        logger.critical(
            "Unhandled exception reached the top level:\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )

        global _dialog_open
        if _dialog_open:
            logger.critical(
                "A second unhandled exception arrived while the first error dialog was "
                "still open; logged only, not shown, to avoid stacking modal dialogs."
            )
            return
        _show_error_dialog(exc_type, exc_value)

    sys.excepthook = _handle


def _show_error_dialog(exc_type: Type[BaseException], exc_value: BaseException) -> None:
    # Imported lazily: this module must not require Qt to already be
    # initialized just to be imported (e.g. from a non-UI entry point),
    # and a failure constructing the dialog itself must never raise.
    global _dialog_open
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox

        app = QApplication.instance()
        if app is None:
            return
        _dialog_open = True
        QMessageBox.critical(
            None,
            "Unexpected Error",
            "An unexpected error occurred and has been written to the log.\n\n"
            f"{exc_type.__name__}: {exc_value}",
        )
    except Exception:
        logger.exception("Failed to display the unexpected-error dialog")
    finally:
        _dialog_open = False
