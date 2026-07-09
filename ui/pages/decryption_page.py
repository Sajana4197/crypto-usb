"""Decryption page: RAM-only decryption with one-time access enforcement. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class DecryptionPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Decrypt File",
            "RAM-only decryption, enforcing one-time access and key invalidation. "
            "Implemented in the Access Enforcement phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
