"""Sender Module: select, queue, inspect, and validate files ahead of encryption.

Encryption itself is implemented in a later phase — this page only prepares
the file queue that the Crypto Core will eventually consume.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.file_queue import FileQueue, QueuedFile
from core.logger import get_logger
from ui.pages.base_page import BasePage
from utils.formatting import format_file_size

logger = get_logger(__name__)

_VALID_COLOR = QColor("#3ecf8e")
_INVALID_COLOR = QColor("#e5484d")

_COLUMN_TITLES = ("Name", "Type", "Size", "Modified", "Status")


class EncryptionPage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Encrypt File",
            "Select and queue the files you want to protect. "
            "Hybrid AES + RSA/ECC encryption is implemented in a later phase.",
            parent,
        )

        self._queue = FileQueue()
        self.setAcceptDrops(True)

        self.add_widget(self._build_toolbar())
        self.add_widget(self._build_notice_label())
        self.add_widget(self._build_table())
        self.add_widget(self._build_details_panel())
        self.add_widget(self._build_footer())

        self._refresh()

    # -- UI construction -------------------------------------------------

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)

        self.add_button = QPushButton("Add Files...")
        self.add_button.clicked.connect(self._on_add_files_clicked)
        layout.addWidget(self.add_button)

        self.remove_button = QPushButton("Remove Selected")
        self.remove_button.clicked.connect(self._on_remove_selected_clicked)
        layout.addWidget(self.remove_button)

        self.revalidate_button = QPushButton("Revalidate All")
        self.revalidate_button.clicked.connect(self._on_revalidate_clicked)
        layout.addWidget(self.revalidate_button)

        self.clear_button = QPushButton("Clear All")
        self.clear_button.clicked.connect(self._on_clear_clicked)
        layout.addWidget(self.clear_button)

        layout.addStretch(1)

        self.summary_label = QLabel()
        self.summary_label.setObjectName("summaryLabel")
        layout.addWidget(self.summary_label)

        return bar

    def _build_notice_label(self) -> QWidget:
        self.notice_label = QLabel(
            "Drag and drop files here, or use “Add Files...”"
        )
        self.notice_label.setObjectName("dropHint")
        return self.notice_label

    def _build_table(self) -> QWidget:
        self.table = QTableWidget(0, len(_COLUMN_TITLES))
        self.table.setHorizontalHeaderLabels(list(_COLUMN_TITLES))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(260)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(_COLUMN_TITLES)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        return self.table

    def _build_details_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailsPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 12)

        self.details_label = QLabel("Select a queued file to view its details.")
        self.details_label.setWordWrap(True)
        layout.addWidget(self.details_label)

        return panel

    def _build_footer(self) -> QWidget:
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addStretch(1)

        self.encrypt_button = QPushButton("Encrypt Selected Files")
        self.encrypt_button.setObjectName("primaryButton")
        self.encrypt_button.setEnabled(False)
        self.encrypt_button.setToolTip(
            "Available once hybrid AES + RSA/ECC encryption is implemented "
            "in the Crypto Core phase."
        )
        layout.addWidget(self.encrypt_button)

        return footer

    # -- Drag and drop -----------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            self._handle_selected_paths(paths)
        event.acceptProposedAction()

    # -- Actions -------------------------------------------------------

    def _on_add_files_clicked(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Queue")
        if paths:
            self._handle_selected_paths(paths)

    def _handle_selected_paths(self, paths: list[str]) -> None:
        added, duplicates = self._queue.add_paths(paths)
        self._refresh()

        if duplicates:
            self._show_notice(
                f"{len(duplicates)} file(s) were already queued and skipped."
            )
        elif added:
            self._show_notice(f"{len(added)} file(s) added to the queue.")

    def _on_remove_selected_clicked(self) -> None:
        keys = {
            self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            for row in {index.row() for index in self.table.selectedIndexes()}
        }
        for key in keys:
            self._queue.remove(key)
        self._refresh()
        if keys:
            self._show_notice(f"Removed {len(keys)} file(s) from the queue.")

    def _on_revalidate_clicked(self) -> None:
        self._queue.revalidate_all()
        self._refresh()
        self._show_notice("Revalidated all queued files.")

    def _on_clear_clicked(self) -> None:
        self._queue.clear()
        self._refresh()
        self.details_label.setText("Select a queued file to view its details.")

    def _on_selection_changed(self) -> None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if len(rows) != 1:
            self.details_label.setText("Select a queued file to view its details.")
            return

        row = next(iter(rows))
        key = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        item = next((f for f in self._queue.items if f.key == key), None)
        if item is None:
            return

        status = "Valid" if item.is_valid else f"Invalid — {item.message}"
        self.details_label.setText(
            f"<b>Path:</b> {item.path}<br>"
            f"<b>Size:</b> {item.size_display} ({item.size_bytes:,} bytes)<br>"
            f"<b>Type:</b> {item.extension}<br>"
            f"<b>Modified:</b> {item.modified_display}<br>"
            f"<b>Status:</b> {status}"
        )

    # -- Rendering -------------------------------------------------------

    def _refresh(self) -> None:
        self._populate_table()
        self._update_summary()

    def _populate_table(self) -> None:
        self.table.setRowCount(0)
        for item in self._queue.items:
            self._append_row(item)

    def _append_row(self, item: QueuedFile) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        name_item = QTableWidgetItem(item.name)
        name_item.setData(Qt.ItemDataRole.UserRole, item.key)
        name_item.setToolTip(str(item.path))

        status_text = "Valid" if item.is_valid else "Invalid"
        status_item = QTableWidgetItem(status_text)
        status_item.setForeground(_VALID_COLOR if item.is_valid else _INVALID_COLOR)
        status_item.setToolTip(item.message)

        values = (name_item, QTableWidgetItem(item.extension), QTableWidgetItem(item.size_display),
                  QTableWidgetItem(item.modified_display), status_item)
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)

    def _update_summary(self) -> None:
        queue = self._queue
        if queue.count == 0:
            self.summary_label.setText("No files queued")
        else:
            self.summary_label.setText(
                f"{queue.count} file(s) queued · {queue.valid_count} valid · "
                f"{queue.invalid_count} invalid · {format_file_size(queue.total_size_bytes)} total"
            )
        self.encrypt_button.setEnabled(False)

    def _show_notice(self, message: str) -> None:
        self.notice_label.setText(message)
        logger.info(message)
