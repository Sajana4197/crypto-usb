"""Application theming.

Provides dark and light QSS stylesheets and a `ThemeManager` that applies
a theme to the running `QApplication` and reports the active theme name.
"""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

_DARK_QSS = """
QWidget {
    background-color: #1e1f26;
    color: #e8e8ec;
    font-family: 'Segoe UI', sans-serif;
    font-size: 10.5pt;
}
QMainWindow, QStackedWidget {
    background-color: #1e1f26;
}
QLabel#pageTitle {
    font-size: 18pt;
    font-weight: 600;
    color: #ffffff;
}
QLabel#pageSubtitle {
    color: #9a9bab;
    font-size: 10pt;
}
QFrame#navigationPanel {
    background-color: #16171d;
    border-right: 1px solid #2a2b35;
}
QLabel#navBrand {
    color: #ffffff;
    font-size: 13pt;
    font-weight: 700;
    padding: 18px 16px 6px 16px;
}
QPushButton#navButton {
    text-align: left;
    padding: 10px 16px;
    border: none;
    border-radius: 6px;
    color: #c7c8d6;
    background-color: transparent;
    margin: 2px 8px;
}
QPushButton#navButton:hover {
    background-color: #262834;
}
QPushButton#navButton:checked {
    background-color: #3a5bd9;
    color: #ffffff;
    font-weight: 600;
}
QStatusBar {
    background-color: #16171d;
    color: #9a9bab;
    border-top: 1px solid #2a2b35;
}
QMenuBar {
    background-color: #16171d;
    color: #e8e8ec;
}
QMenuBar::item:selected {
    background-color: #262834;
}
QMenu {
    background-color: #20212b;
    color: #e8e8ec;
    border: 1px solid #2a2b35;
}
QMenu::item:selected {
    background-color: #3a5bd9;
}
QPushButton {
    background-color: #2a2c38;
    color: #e8e8ec;
    border: 1px solid #3a3c4a;
    border-radius: 6px;
    padding: 8px 16px;
}
QPushButton:hover {
    background-color: #333544;
}
QPushButton:pressed {
    background-color: #23252f;
}
QPushButton:disabled {
    background-color: #22232b;
    color: #5c5d6b;
    border-color: #2a2b35;
}
QPushButton#primaryButton {
    background-color: #3a5bd9;
    border: none;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#primaryButton:hover {
    background-color: #4a6bef;
}
QPushButton#primaryButton:disabled {
    background-color: #2b2f45;
    color: #6b6d80;
    border: none;
}
QTableWidget {
    background-color: #20212b;
    alternate-background-color: #24252f;
    gridline-color: #2a2b35;
    border: 1px solid #2a2b35;
    border-radius: 6px;
    selection-background-color: #3a5bd9;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 4px 8px;
}
QHeaderView::section {
    background-color: #16171d;
    color: #9a9bab;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #2a2b35;
    font-weight: 600;
}
QLineEdit, QComboBox {
    background-color: #20212b;
    border: 1px solid #2a2b35;
    border-radius: 6px;
    padding: 6px 10px;
}
QFrame#detailsPanel {
    background-color: #20212b;
    border: 1px solid #2a2b35;
    border-radius: 6px;
}
QLabel#summaryLabel {
    color: #c7c8d6;
    font-weight: 600;
}
QLabel#noticeLabel {
    color: #f2b84b;
}
QLabel#dropHint {
    color: #6f7183;
    font-style: italic;
}
QScrollBar:vertical {
    background: #16171d;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #2a2b35;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

_LIGHT_QSS = """
QWidget {
    background-color: #f5f6fa;
    color: #1c1d24;
    font-family: 'Segoe UI', sans-serif;
    font-size: 10.5pt;
}
QMainWindow, QStackedWidget {
    background-color: #f5f6fa;
}
QLabel#pageTitle {
    font-size: 18pt;
    font-weight: 600;
    color: #101116;
}
QLabel#pageSubtitle {
    color: #5b5c6b;
    font-size: 10pt;
}
QFrame#navigationPanel {
    background-color: #ffffff;
    border-right: 1px solid #e1e2ea;
}
QLabel#navBrand {
    color: #101116;
    font-size: 13pt;
    font-weight: 700;
    padding: 18px 16px 6px 16px;
}
QPushButton#navButton {
    text-align: left;
    padding: 10px 16px;
    border: none;
    border-radius: 6px;
    color: #40414f;
    background-color: transparent;
    margin: 2px 8px;
}
QPushButton#navButton:hover {
    background-color: #eceefa;
}
QPushButton#navButton:checked {
    background-color: #3a5bd9;
    color: #ffffff;
    font-weight: 600;
}
QStatusBar {
    background-color: #ffffff;
    color: #5b5c6b;
    border-top: 1px solid #e1e2ea;
}
QMenuBar {
    background-color: #ffffff;
    color: #1c1d24;
}
QMenuBar::item:selected {
    background-color: #eceefa;
}
QMenu {
    background-color: #ffffff;
    color: #1c1d24;
    border: 1px solid #e1e2ea;
}
QMenu::item:selected {
    background-color: #3a5bd9;
    color: #ffffff;
}
QPushButton {
    background-color: #ffffff;
    color: #1c1d24;
    border: 1px solid #d4d6e2;
    border-radius: 6px;
    padding: 8px 16px;
}
QPushButton:hover {
    background-color: #eceefa;
}
QPushButton:pressed {
    background-color: #dfe1f0;
}
QPushButton:disabled {
    background-color: #f0f1f6;
    color: #a4a6b6;
    border-color: #e1e2ea;
}
QPushButton#primaryButton {
    background-color: #3a5bd9;
    border: none;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#primaryButton:hover {
    background-color: #4a6bef;
}
QPushButton#primaryButton:disabled {
    background-color: #c7cdef;
    color: #eef0fb;
    border: none;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f5f6fa;
    gridline-color: #e1e2ea;
    border: 1px solid #e1e2ea;
    border-radius: 6px;
    selection-background-color: #3a5bd9;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 4px 8px;
}
QHeaderView::section {
    background-color: #f5f6fa;
    color: #5b5c6b;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #e1e2ea;
    font-weight: 600;
}
QLineEdit, QComboBox {
    background-color: #ffffff;
    border: 1px solid #d4d6e2;
    border-radius: 6px;
    padding: 6px 10px;
}
QFrame#detailsPanel {
    background-color: #ffffff;
    border: 1px solid #e1e2ea;
    border-radius: 6px;
}
QLabel#summaryLabel {
    color: #40414f;
    font-weight: 600;
}
QLabel#noticeLabel {
    color: #a06400;
}
QLabel#dropHint {
    color: #8f90a0;
    font-style: italic;
}
QScrollBar:vertical {
    background: #f5f6fa;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #d4d6e2;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

THEMES = {
    "dark": _DARK_QSS,
    "light": _LIGHT_QSS,
}


class ThemeManager:
    """Applies and tracks the active application theme."""

    def __init__(self, app: QApplication, theme: str = "dark") -> None:
        self._app = app
        self._current = theme if theme in THEMES else "dark"

    @property
    def current_theme(self) -> str:
        return self._current

    def apply(self, theme: str | None = None) -> None:
        if theme is not None:
            self._current = theme if theme in THEMES else "dark"
        self._app.setStyleSheet(THEMES[self._current])

    def toggle(self) -> str:
        self.apply("light" if self._current == "dark" else "dark")
        return self._current
