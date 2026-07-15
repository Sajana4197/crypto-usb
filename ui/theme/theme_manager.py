"""Application theming.

Provides dark and light QSS stylesheets and a `ThemeManager` that applies
a theme to the running `QApplication` and reports the active theme name.
"""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

_DARK_QSS = """
QWidget {
    background-color: #0a0e14;
    color: #d7ecf5;
    font-family: 'Segoe UI', sans-serif;
    font-size: 10.5pt;
}
QMainWindow, QStackedWidget {
    background-color: #0a0e14;
}
QLabel#pageTitle {
    font-size: 18pt;
    font-weight: 600;
    color: #eaf9ff;
}
QLabel#pageSubtitle {
    color: #5c7a8a;
    font-size: 10pt;
}
QFrame#navigationPanel {
    background-color: #060a0f;
    border-right: 1px solid #113247;
}
QLabel#navBrand {
    color: #00e5ff;
    font-size: 13pt;
    font-weight: 700;
    padding: 18px 16px 6px 16px;
}
QPushButton#navButton {
    text-align: left;
    padding: 10px 16px;
    border: 1px solid transparent;
    border-left: 3px solid transparent;
    border-radius: 3px;
    color: #8fa8b5;
    background-color: transparent;
    margin: 2px 8px;
}
QPushButton#navButton:hover {
    background-color: #0d1720;
    border-left: 3px solid #0e5a70;
    color: #cdeef7;
}
QPushButton#navButton:checked {
    background-color: rgba(0, 229, 255, 0.12);
    border: 1px solid #0e5a70;
    border-left: 3px solid #00e5ff;
    color: #ffffff;
    font-weight: 600;
}
QStatusBar {
    background-color: #060a0f;
    color: #5c7a8a;
    border-top: 1px solid #113247;
}
QMenuBar {
    background-color: #060a0f;
    color: #d7ecf5;
}
QMenuBar::item:selected {
    background-color: #0d1720;
}
QMenu {
    background-color: #0a0e14;
    color: #d7ecf5;
    border: 1px solid #113247;
}
QMenu::item:selected {
    background-color: rgba(0, 229, 255, 0.16);
    color: #ffffff;
}
QPushButton {
    background-color: #0d1720;
    color: #cdeef7;
    border: 1px solid #1a3d4d;
    border-radius: 3px;
    padding: 8px 16px;
}
QPushButton:hover {
    background-color: #12212c;
    border: 1px solid #00b8d4;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #081117;
}
QPushButton:disabled {
    background-color: #0a0e14;
    color: #3c4d55;
    border-color: #16232a;
}
QPushButton#primaryButton {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00b8d4, stop:1 #00e5ff);
    border: 1px solid #6df3ff;
    color: #04151a;
    font-weight: 700;
}
QPushButton#primaryButton:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1cd4ec, stop:1 #6df3ff);
}
QPushButton#primaryButton:disabled {
    background-color: #163540;
    color: #4f6b74;
    border: 1px solid #1a3d4d;
}
QTableWidget {
    background-color: #060a0f;
    alternate-background-color: #0a121a;
    gridline-color: #16232a;
    border: 1px solid #113247;
    border-radius: 3px;
    selection-background-color: rgba(0, 229, 255, 0.22);
    selection-color: #ffffff;
    font-family: 'Cascadia Code', 'Consolas', monospace;
}
QTableWidget::item {
    padding: 4px 8px;
}
QHeaderView::section {
    background-color: #060a0f;
    color: #4fa8c9;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #113247;
    font-weight: 600;
}
QLineEdit, QComboBox {
    background-color: #060a0f;
    color: #d7ecf5;
    border: 1px solid #1a3d4d;
    border-radius: 3px;
    padding: 6px 10px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #00e5ff;
}
QFrame#detailsPanel {
    background-color: #060a0f;
    border: 1px solid #113247;
    border-radius: 3px;
}
QLabel#summaryLabel {
    color: #8fa8b5;
    font-weight: 600;
}
QLabel#noticeLabel {
    color: #f2b84b;
}
QLabel#dropHint {
    color: #455964;
    font-style: italic;
}
QScrollBar:vertical {
    background: #060a0f;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #1a3d4d;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #00b8d4;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QProgressBar {
    background-color: #060a0f;
    border: 1px solid #113247;
    border-radius: 3px;
    text-align: center;
    color: #d7ecf5;
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00b8d4, stop:1 #00e5ff);
    border-radius: 2px;
}
QMessageBox, QInputDialog, QDialog {
    background-color: #0a0e14;
}
QFrame#statCard {
    background-color: #060a0f;
    border: 1px solid #113247;
    border-radius: 4px;
}
QFrame#statCard:hover {
    border: 1px solid #00b8d4;
}
QLabel#statValue {
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 22pt;
    font-weight: 700;
    color: #00e5ff;
}
QLabel#statTitle {
    color: #5c7a8a;
    font-size: 9pt;
}
QLabel#statDetail {
    font-size: 8.5pt;
}
QListWidget#activityFeed {
    background-color: #060a0f;
    border: 1px solid #113247;
    border-radius: 3px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 9.5pt;
    color: #9fc3d1;
    padding: 4px;
}
QListWidget#activityFeed::item {
    padding: 6px 8px;
    border-bottom: 1px solid #0d1720;
}
QListWidget#activityFeed::item:selected {
    background-color: rgba(0, 229, 255, 0.16);
    color: #ffffff;
}
"""

_LIGHT_QSS = """
QWidget {
    background-color: #eef4f7;
    color: #0b1f2a;
    font-family: 'Segoe UI', sans-serif;
    font-size: 10.5pt;
}
QMainWindow, QStackedWidget {
    background-color: #eef4f7;
}
QLabel#pageTitle {
    font-size: 18pt;
    font-weight: 600;
    color: #06222c;
}
QLabel#pageSubtitle {
    color: #4a6572;
    font-size: 10pt;
}
QFrame#navigationPanel {
    background-color: #ffffff;
    border-right: 1px solid #cfe4ea;
}
QLabel#navBrand {
    color: #0891b2;
    font-size: 13pt;
    font-weight: 700;
    padding: 18px 16px 6px 16px;
}
QPushButton#navButton {
    text-align: left;
    padding: 10px 16px;
    border: 1px solid transparent;
    border-left: 3px solid transparent;
    border-radius: 3px;
    color: #375561;
    background-color: transparent;
    margin: 2px 8px;
}
QPushButton#navButton:hover {
    background-color: #e3f3f7;
    border-left: 3px solid #8fd4e3;
    color: #06222c;
}
QPushButton#navButton:checked {
    background-color: rgba(8, 145, 178, 0.12);
    border: 1px solid #8fd4e3;
    border-left: 3px solid #0891b2;
    color: #06222c;
    font-weight: 600;
}
QStatusBar {
    background-color: #ffffff;
    color: #4a6572;
    border-top: 1px solid #cfe4ea;
}
QMenuBar {
    background-color: #ffffff;
    color: #0b1f2a;
}
QMenuBar::item:selected {
    background-color: #e3f3f7;
}
QMenu {
    background-color: #ffffff;
    color: #0b1f2a;
    border: 1px solid #cfe4ea;
}
QMenu::item:selected {
    background-color: #0891b2;
    color: #ffffff;
}
QPushButton {
    background-color: #ffffff;
    color: #0b1f2a;
    border: 1px solid #b9d8e0;
    border-radius: 3px;
    padding: 8px 16px;
}
QPushButton:hover {
    background-color: #e3f3f7;
    border: 1px solid #0891b2;
}
QPushButton:pressed {
    background-color: #cfe9ef;
}
QPushButton:disabled {
    background-color: #f2f6f8;
    color: #a3b7bf;
    border-color: #d9e7ec;
}
QPushButton#primaryButton {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0891b2, stop:1 #06b6d4);
    border: 1px solid #06647a;
    color: #ffffff;
    font-weight: 700;
}
QPushButton#primaryButton:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #06a4c4, stop:1 #22d3ee);
}
QPushButton#primaryButton:disabled {
    background-color: #bfe4ec;
    color: #ffffff;
    border: 1px solid #b9d8e0;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f2f8fa;
    gridline-color: #d9e7ec;
    border: 1px solid #cfe4ea;
    border-radius: 3px;
    selection-background-color: #0891b2;
    selection-color: #ffffff;
    font-family: 'Cascadia Code', 'Consolas', monospace;
}
QTableWidget::item {
    padding: 4px 8px;
}
QHeaderView::section {
    background-color: #f2f8fa;
    color: #0e6b82;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #cfe4ea;
    font-weight: 600;
}
QLineEdit, QComboBox {
    background-color: #ffffff;
    color: #0b1f2a;
    border: 1px solid #b9d8e0;
    border-radius: 3px;
    padding: 6px 10px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #0891b2;
}
QFrame#detailsPanel {
    background-color: #ffffff;
    border: 1px solid #cfe4ea;
    border-radius: 3px;
}
QLabel#summaryLabel {
    color: #375561;
    font-weight: 600;
}
QLabel#noticeLabel {
    color: #a06400;
}
QLabel#dropHint {
    color: #7d97a1;
    font-style: italic;
}
QScrollBar:vertical {
    background: #eef4f7;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #b9d8e0;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #0891b2;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QProgressBar {
    background-color: #ffffff;
    border: 1px solid #cfe4ea;
    border-radius: 3px;
    text-align: center;
    color: #0b1f2a;
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0891b2, stop:1 #06b6d4);
    border-radius: 2px;
}
QMessageBox, QInputDialog, QDialog {
    background-color: #eef4f7;
}
QFrame#statCard {
    background-color: #ffffff;
    border: 1px solid #cfe4ea;
    border-radius: 4px;
}
QFrame#statCard:hover {
    border: 1px solid #0891b2;
}
QLabel#statValue {
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 22pt;
    font-weight: 700;
    color: #0891b2;
}
QLabel#statTitle {
    color: #4a6572;
    font-size: 9pt;
}
QLabel#statDetail {
    font-size: 8.5pt;
}
QListWidget#activityFeed {
    background-color: #ffffff;
    border: 1px solid #cfe4ea;
    border-radius: 3px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 9.5pt;
    color: #375561;
    padding: 4px;
}
QListWidget#activityFeed::item {
    padding: 6px 8px;
    border-bottom: 1px solid #eef4f7;
}
QListWidget#activityFeed::item:selected {
    background-color: rgba(8, 145, 178, 0.16);
    color: #06222c;
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
