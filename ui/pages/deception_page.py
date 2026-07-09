"""Deception page: decoy behavior on unauthorized access attempts. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class DeceptionPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Deception Module",
            "Presents decoy content and traps for unauthorized access attempts. "
            "Implemented in the Deception Module phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
