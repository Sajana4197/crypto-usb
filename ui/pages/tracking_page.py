"""Tracking page: access/usage monitoring and audit trail. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class TrackingPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Usage Tracking",
            "Access history and usage monitoring audit trail. "
            "Implemented in the Usage Tracking phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
