"""Common page layout shared by every navigation destination."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QScrollArea, QVBoxLayout, QWidget


class BasePage(QWidget):
    """A page with a title, subtitle, and a content area for subclasses to fill.

    The content area lives inside a borderless `QScrollArea` rather than
    directly in `self`'s own layout: a page's total content height can
    exceed the window's available height (e.g. a page gains a new
    control and no longer fits within the default window size) — without
    a scroll area, Qt has no choice but to shrink widgets below their
    `sizeHint()` to force everything into the space available, which
    clips text rather than making the extra content reachable. Scrolling
    is the correct way to handle "more content than window height" in
    general, rather than something to special-case per page.
    """

    def __init__(self, title: str, subtitle: str = "", parent=None) -> None:
        super().__init__(parent)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        outer_layout.addWidget(scroll_area)

        content = QWidget()
        scroll_area.setWidget(content)

        self._layout = QVBoxLayout(content)
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
