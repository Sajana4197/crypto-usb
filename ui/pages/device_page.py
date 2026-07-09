"""Device validation page: authorized USB device binding and checks. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class DevicePage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Device Validation",
            "Identifies and validates authorized USB devices. "
            "Implemented in the Device Validation phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
