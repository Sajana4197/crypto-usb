"""Settings page: theme toggle and application preferences."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QFormLayout, QLabel, QWidget

from ui.pages.base_page import BasePage


class SettingsPage(BasePage):
    theme_changed = Signal(str)

    def __init__(self, current_theme: str = "dark", parent=None) -> None:
        super().__init__(
            "Settings",
            "Application preferences.",
            parent,
        )

        form_container = QWidget()
        form = QFormLayout(form_container)
        form.setContentsMargins(0, 0, 0, 0)

        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["dark", "light"])
        self.theme_selector.setCurrentText(current_theme)
        self.theme_selector.currentTextChanged.connect(self.theme_changed.emit)
        form.addRow(QLabel("Theme:"), self.theme_selector)

        self.add_widget(form_container)

    def set_theme(self, theme: str) -> None:
        self.theme_selector.blockSignals(True)
        self.theme_selector.setCurrentText(theme)
        self.theme_selector.blockSignals(False)
