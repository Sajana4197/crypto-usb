"""Security page: one-time access enforcement and key invalidation. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class SecurityPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Access Security",
            "One-time access enforcement and key invalidation controls. "
            "Implemented in the Access Enforcement phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
