"""Encryption page: hybrid AES + RSA/ECC file encryption. Built in a later phase."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from ui.pages.base_page import BasePage


class EncryptionPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Encrypt File",
            "Hybrid AES (file) + RSA/ECC (key) encryption workflow. "
            "Implemented in the Crypto Core phase.",
            parent,
        )
        self.add_widget(QLabel("This module is not yet implemented."))
