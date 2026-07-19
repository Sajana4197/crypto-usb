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

from PySide6.QtCore import QTimer
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
from tracking.exceptions import TrackingTamperError
from tracking.models import UsageRecord
from tracking.tracking_service import UsageTracker
from ui.pages.base_page import BasePage
from ui.widgets.busy import show_result_popup
from utils.formatting import format_datetime

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

# Matches the device-table poll interval used elsewhere (Phase 22/23) so
# every page feels equally "live".
_REFRESH_INTERVAL_MS = 2000

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
        # None, not [], is "never refreshed yet" — otherwise a fresh account
        # with zero real records would see `[] == []` on the very first
        # refresh() call and skip rendering the summary label entirely
        # (same class of bug fixed in DevicePage._refresh_devices).
        self._records: Optional[list[UsageRecord]] = None

        self.add_widget(self._build_toolbar())
        self.add_widget(self._build_table())
        self.add_widget(self._build_status_label())

        self.refresh()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(_REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start()

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

        try:
            records = list(reversed(self._usage_tracker.read_all_records()))
        except TrackingTamperError as exc:
            # `read_all_records()` decrypts and HMAC-verifies every entry,
            # raising on the first one that fails — a poll tick must survive
            # this the same way a manual refresh would (see DashboardPage
            # ._read_tracking_records_safely), not crash the timer callback.
            logger.warning("Usage log record(s) failed integrity check: %s", exc)
            self._records = []
            self.table.setRowCount(0)
            self.summary_label.setText("Usage log failed its integrity check — see Verify Log Integrity.")
            return

        # Skip the rebuild when nothing actually changed — a background poll
        # should never reset the table's scroll position while the record
        # set is unchanged (same principle as DevicePage._refresh_devices).
        if records == self._records:
            return
        self._records = records

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
            QTableWidgetItem(format_datetime(record.login_time)),
            QTableWidgetItem(format_datetime(record.open_time)),
            QTableWidgetItem(format_datetime(record.close_time)),
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
            self._show_status(
                f"Log integrity verified: {result.verified_count} entrie(s), chain intact.", important=True
            )
        else:
            self._show_status(f"Log integrity check FAILED: {result.reason}", ok=False, important=True)

    def _show_status(self, message: str, ok: bool = True, important: bool = False) -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {(_OK_COLOR if ok else _FAIL_COLOR).name()};")
        if ok:
            logger.info(message)
        else:
            logger.warning(message)
        if important:
            show_result_popup(self, message, ok=ok)
