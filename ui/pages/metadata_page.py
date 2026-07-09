"""Metadata page: secure metadata-driven access control. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class MetadataPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Metadata",
            "Secure, metadata-driven access control for protected files. "
            "Implemented in the Metadata & Database phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
