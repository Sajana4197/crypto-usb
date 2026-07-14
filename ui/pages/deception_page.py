"""Deception Module page: a read-only view over recorded deception activations.

Reads from `deception.event_repository.DeceptionEventRepository`, which
`deception.deception_engine.DeceptionEngine` writes to on every
`activate()` call (see that module's docstring). This page never shows
the fabricated content itself — only the audit metadata (trigger,
content type, file_id, timestamp) — matching the repository's own
storage contract.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from core.logger import get_logger
from deception.event_repository import DeceptionEventRecord, DeceptionEventRepository
from ui.pages.base_page import BasePage

logger = get_logger(__name__)

_COLUMN_TITLES = ("Trigger", "Content Type", "File ID", "Generated At")


def _fmt(value) -> str:
    return value.isoformat(sep=" ", timespec="seconds") if value is not None else "—"


class DeceptionPage(BasePage):
    def __init__(self, event_repository: Optional[DeceptionEventRepository] = None, parent=None) -> None:
        super().__init__(
            "Deception Module",
            "Read-only audit trail of every time the Deception Engine fired: which "
            "check failed, and what kind of decoy was fabricated in response. Never "
            "shows the fabricated content itself.",
            parent,
        )

        self._event_repository = event_repository

        self.add_widget(self._build_toolbar())
        self.add_widget(self._build_table())
        self.add_widget(self._build_status_label())

        self.refresh()

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_button)

        layout.addStretch(1)

        self.summary_label = QLabel()
        layout.addWidget(self.summary_label)

        return bar

    def _build_table(self) -> QWidget:
        self.table = QTableWidget(0, len(_COLUMN_TITLES))
        self.table.setHorizontalHeaderLabels(list(_COLUMN_TITLES))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(280)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(_COLUMN_TITLES)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        return self.table

    def _build_status_label(self) -> QWidget:
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("dropHint")
        return self.status_label

    def refresh(self) -> None:
        self.table.setRowCount(0)
        if self._event_repository is None:
            self.summary_label.setText("No deception event repository is available in this session.")
            return

        events = self._event_repository.list_events()
        for event in events:
            self._append_row(event)
        self.summary_label.setText(f"{len(events)} recorded event(s)")

    def _append_row(self, event: DeceptionEventRecord) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = (
            QTableWidgetItem(event.trigger.value),
            QTableWidgetItem(event.content_type.value),
            QTableWidgetItem(event.file_id or "—"),
            QTableWidgetItem(_fmt(event.generated_at)),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)
