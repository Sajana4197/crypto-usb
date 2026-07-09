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
