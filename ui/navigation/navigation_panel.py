"""Sidebar navigation framework.

`NavigationPanel` renders a checkable button per registered page and emits
`page_selected` when the user switches pages. It knows nothing about the
page widgets themselves — `MainWindow` wires the signal to a
`QStackedWidget`.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QButtonGroup, QFrame, QLabel, QPushButton, QVBoxLayout


@dataclass(frozen=True)
class NavItem:
    page_id: str
    label: str


DEFAULT_NAV_ITEMS: tuple[NavItem, ...] = (
    NavItem("dashboard", "Dashboard"),
    NavItem("encryption", "Encrypt File"),
    NavItem("decryption", "Decrypt File"),
    NavItem("devices", "Device Validation"),
    NavItem("metadata", "Metadata"),
    NavItem("security", "Access Security"),
    NavItem("deception", "Deception Module"),
    NavItem("tracking", "Usage Tracking"),
    NavItem("settings", "Settings"),
)


class NavigationPanel(QFrame):
    """Checkable sidebar button list; emits `page_selected(page_id)`."""

    page_selected = Signal(str)

    def __init__(self, items: tuple[NavItem, ...] = DEFAULT_NAV_ITEMS, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("navigationPanel")
        self.setFixedWidth(220)

        self._buttons: dict[str, QPushButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 12)
        layout.setSpacing(0)

        brand = QLabel("CryptoUSB")
        brand.setObjectName("navBrand")
        layout.addWidget(brand)

        for item in items:
            button = QPushButton(item.label)
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.clicked.connect(lambda _checked, pid=item.page_id: self._on_clicked(pid))
            self._group.addButton(button)
            self._buttons[item.page_id] = button
            layout.addWidget(button)

        layout.addStretch(1)

        if items:
            self._buttons[items[0].page_id].setChecked(True)

    def _on_clicked(self, page_id: str) -> None:
        self.page_selected.emit(page_id)

    def set_active(self, page_id: str) -> None:
        button = self._buttons.get(page_id)
        if button is not None:
            button.setChecked(True)
