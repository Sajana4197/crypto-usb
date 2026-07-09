"""Common page layout shared by every navigation destination."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class BasePage(QWidget):
    """A page with a title, subtitle, and a content area for subclasses to fill."""

    def __init__(self, title: str, subtitle: str = "", parent=None) -> None:
        super().__init__(parent)

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(32, 28, 32, 28)
        self._layout.setSpacing(6)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        title_label = QLabel(title)
        title_label.setObjectName("pageTitle")
        self._layout.addWidget(title_label)

        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("pageSubtitle")
            subtitle_label.setWordWrap(True)
            self._layout.addWidget(subtitle_label)

        self._layout.addSpacing(18)

    def add_widget(self, widget: QWidget) -> None:
        self._layout.addWidget(widget)
