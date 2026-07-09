"""Dashboard: landing page summarizing module build status."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QListWidget, QListWidgetItem

from ui.pages.base_page import BasePage

_MODULES = (
    ("Hybrid Encryption (AES + RSA/ECC)", "Not yet implemented"),
    ("Metadata-Driven Access Control", "Not yet implemented"),
    ("Device Validation", "Implemented"),
    ("Secure Storage Layer", "Implemented"),
    ("User Authentication", "Implemented"),
    ("One-Time Access Enforcement", "Not yet implemented"),
    ("Key Invalidation", "Not yet implemented"),
    ("RAM-Only Decryption", "Not yet implemented"),
    ("Deception Module", "Not yet implemented"),
    ("Usage Tracking", "Not yet implemented"),
)


class DashboardPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Dashboard",
            "Overview of A Cryptographic Security Layer for USB Storage.",
            parent,
        )

        status_heading = QLabel("Module status")
        status_heading.setStyleSheet("font-weight: 600; font-size: 11pt;")
        self.add_widget(status_heading)

        module_list = QListWidget()
        module_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for name, status in _MODULES:
            item = QListWidgetItem(f"{name}  —  {status}")
            module_list.addItem(item)
        module_list.setFixedHeight(220)
        self.add_widget(module_list)
