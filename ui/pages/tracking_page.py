"""Usage Tracking page: a read-only view over the tamper-evident access log.

Every attempt `usb.secure_access_service.SecureAccessService` makes
(granted or denied) is already recorded by
`tracking.tracking_service.UsageTracker` — see
`tests/test_integration_workflow.py`. This page adds no new write path;
it only calls `UsageTracker.read_all_records()` and
`UsageTracker.verify_log_integrity()`, both already-existing read
operations.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtGui import QColor
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
from tracking.models import UsageRecord
from tracking.tracking_service import UsageTracker
from ui.pages.base_page import BasePage

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_COLUMN_TITLES = (
    "Session",
    "User",
    "File ID",
    "Login Time",
    "Open Time",
    "Close Time",
    "Duration (s)",
    "Auth OK",
    "Validation OK",
    "Screen Captures",
    "Tampering",
)


def _fmt(value) -> str:
    return value.isoformat(sep=" ", timespec="seconds") if value is not None else "—"


def _bool_display(value: Optional[bool]) -> str:
    if value is None:
        return "—"
    return "Yes" if value else "No"


class TrackingPage(BasePage):
    def __init__(self, usage_tracker: Optional[UsageTracker] = None, parent=None) -> None:
        super().__init__(
            "Usage Tracking",
            "Read-only view of the tamper-evident access log: every attempt to view a "
            "protected file, granted or denied, in the order it happened.",
            parent,
        )

        self._usage_tracker = usage_tracker
        self._records: list[UsageRecord] = []

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

        self.verify_button = QPushButton("Verify Log Integrity")
        self.verify_button.clicked.connect(self._on_verify_clicked)
        layout.addWidget(self.verify_button)

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
        if self._usage_tracker is None:
            self._records = []
            self.summary_label.setText("No usage tracker is available in this session.")
            self.table.setRowCount(0)
            return

        self._records = list(reversed(self._usage_tracker.read_all_records()))
        self.table.setRowCount(0)
        for record in self._records:
            self._append_row(record)
        self.summary_label.setText(f"{len(self._records)} recorded session(s)")

    def _append_row(self, record: UsageRecord) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        auth_item = QTableWidgetItem(_bool_display(record.authentication_result))
        auth_item.setForeground(self._result_color(record.authentication_result))

        validation_item = QTableWidgetItem(_bool_display(record.validation_result))
        validation_item.setForeground(self._result_color(record.validation_result))

        values = (
            QTableWidgetItem(record.session_id[:8]),
            QTableWidgetItem(record.user),
            QTableWidgetItem(record.file_id),
            QTableWidgetItem(_fmt(record.login_time)),
            QTableWidgetItem(_fmt(record.open_time)),
            QTableWidgetItem(_fmt(record.close_time)),
            QTableWidgetItem(f"{record.duration_seconds:.3f}" if record.duration_seconds is not None else "—"),
            auth_item,
            validation_item,
            QTableWidgetItem(str(record.screen_capture_attempts)),
            QTableWidgetItem(str(record.tampering_events)),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)

    @staticmethod
    def _result_color(value: Optional[bool]) -> QColor:
        if value is None:
            return QColor("#8f90a0")
        return _OK_COLOR if value else _FAIL_COLOR

    def _on_verify_clicked(self) -> None:
        if self._usage_tracker is None:
            self._show_status("No usage tracker is available in this session.", ok=False)
            return

        result = self._usage_tracker.verify_log_integrity()
        if result.ok:
            self._show_status(f"Log integrity verified: {result.verified_count} entrie(s), chain intact.")
        else:
            self._show_status(f"Log integrity check FAILED: {result.reason}", ok=False)

    def _show_status(self, message: str, ok: bool = True) -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {(_OK_COLOR if ok else _FAIL_COLOR).name()};")
        if ok:
            logger.info(message)
        else:
            logger.warning(message)
