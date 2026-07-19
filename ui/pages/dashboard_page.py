"""Dashboard: live overview of protected files, accounts, deception activity,
and tracking log health, plus quick actions to jump to the write/verify pages.

Reads from the same shared, persisted repositories every other page already
gets from `ui.main_window.MainWindow._build_shared_services()` (Phase 14/16)
— no new write path, no schema changes. Purely read-only aggregation over
`MetadataRepository.list_file_ids()`, `AccountRepository.list_owner_ids()`,
`DeceptionEventRepository.count()/list_events()`, and
`UsageTracker.read_all_records()/verify_log_integrity()`, all of which
already exist and are already exercised by the Metadata / Access Security /
Deception Module / Usage Tracking pages (Phase 16). Follows the same
None-tolerant constructor pattern as those pages: every repository is
optional and a missing one degrades its stat card / feed entry rather than
crashing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from deception.event_repository import DeceptionEventRepository
from metadata.repository import MetadataRepository
from security.account_repository import AccountRepository
from tracking.exceptions import TrackingTamperError
from tracking.models import UsageRecord
from tracking.tracking_service import UsageTracker
from ui.pages.base_page import BasePage
from utils.formatting import format_datetime

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_ACTIVITY_LIMIT = 8

# How often the dashboard polls for new activity without any user action —
# matches the device-table poll interval used elsewhere (Phase 22/23) so
# every page feels equally "live".
_REFRESH_INTERVAL_MS = 2000


class DashboardPage(BasePage):
    """Landing page: live stat cards, a merged recent-activity feed, and
    quick navigation actions.
    """

    navigate_requested = Signal(str)

    def __init__(
        self,
        metadata_repository: Optional[MetadataRepository] = None,
        account_repository: Optional[AccountRepository] = None,
        deception_event_repository: Optional[DeceptionEventRepository] = None,
        usage_tracker: Optional[UsageTracker] = None,
        parent=None,
    ) -> None:
        super().__init__(
            "Dashboard",
            "Overview of A Cryptographic Security Layer for USB Storage.",
            parent,
        )

        self._metadata_repository = metadata_repository
        self._account_repository = account_repository
        self._deception_event_repository = deception_event_repository
        self._usage_tracker = usage_tracker
        self._last_snapshot: Optional[tuple] = None

        self.add_widget(self._build_toolbar())
        self.add_widget(self._build_stats_row())

        activity_heading = QLabel("Recent activity")
        activity_heading.setStyleSheet("font-weight: 600; font-size: 11pt;")
        self.add_widget(activity_heading)
        self.add_widget(self._build_activity_feed())

        actions_heading = QLabel("Quick actions")
        actions_heading.setStyleSheet("font-weight: 600; font-size: 11pt;")
        self.add_widget(actions_heading)
        self.add_widget(self._build_quick_actions())

        self.refresh()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(_REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start()

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addStretch(1)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_button)

        return bar

    def _build_stat_card(self, title: str, with_detail: bool = False):
        card = QFrame()
        card.setObjectName("statCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(2)

        value_label = QLabel("—")
        value_label.setObjectName("statValue")
        layout.addWidget(value_label)

        title_label = QLabel(title)
        title_label.setObjectName("statTitle")
        layout.addWidget(title_label)

        detail_label = None
        if with_detail:
            detail_label = QLabel("")
            detail_label.setObjectName("statDetail")
            detail_label.setWordWrap(True)
            layout.addWidget(detail_label)

        return card, value_label, detail_label

    def _build_stats_row(self) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        files_card, self.files_value_label, _ = self._build_stat_card("Protected Files")
        accounts_card, self.accounts_value_label, _ = self._build_stat_card("Registered Accounts")
        deception_card, self.deception_value_label, _ = self._build_stat_card("Deception Triggers")
        tracking_card, self.tracking_value_label, self.tracking_detail_label = self._build_stat_card(
            "Tracking Log Entries", with_detail=True
        )

        for card in (files_card, accounts_card, deception_card, tracking_card):
            layout.addWidget(card)

        return row

    def _build_activity_feed(self) -> QWidget:
        self.activity_list = QListWidget()
        self.activity_list.setObjectName("activityFeed")
        self.activity_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.activity_list.setFixedHeight(180)
        return self.activity_list

    def _build_quick_actions(self) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.setObjectName("primaryButton")
        self.encrypt_button.clicked.connect(lambda: self.navigate_requested.emit("encryption"))

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setObjectName("primaryButton")
        self.decrypt_button.clicked.connect(lambda: self.navigate_requested.emit("decryption"))

        self.validate_device_button = QPushButton("Validate Device")
        self.validate_device_button.setObjectName("primaryButton")
        self.validate_device_button.clicked.connect(lambda: self.navigate_requested.emit("devices"))

        for button in (self.encrypt_button, self.decrypt_button, self.validate_device_button):
            layout.addWidget(button)
        layout.addStretch(1)

        return row

    def refresh(self) -> None:
        records, tracking_tampered = self._read_tracking_records_safely()
        # The stat cards can change independently of the tracking log (e.g. a
        # file was just encrypted but never viewed, so no UsageRecord exists
        # yet) — the no-op snapshot must cover every value a stat card or the
        # activity feed reads, not just `records`, or a poll tick would skip
        # rendering a real change.
        file_count = (
            len(self._metadata_repository.list_file_ids()) if self._metadata_repository is not None else None
        )
        account_count = (
            len(self._account_repository.list_owner_ids()) if self._account_repository is not None else None
        )
        deception_count = (
            self._deception_event_repository.count() if self._deception_event_repository is not None else None
        )

        snapshot = (file_count, account_count, deception_count, tuple(records), tracking_tampered)
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        self._refresh_stats(records, tracking_tampered)
        self._refresh_activity(records)

    def _read_tracking_records_safely(self) -> tuple[list[UsageRecord], bool]:
        """`UsageTracker.read_all_records()` decrypts and HMAC-verifies every
        entry, raising `TrackingTamperError` on the first one that fails —
        exactly like `MetadataProtector.unprotect` does for a tampered
        metadata record (see `MetadataPage.refresh`). This page must survive
        that the same way: fall back to an empty list and let
        `verify_log_integrity()` (which never raises) report the failure.
        """
        if self._usage_tracker is None:
            return [], False
        try:
            return self._usage_tracker.read_all_records(), False
        except TrackingTamperError as exc:
            logger.warning("Usage log record(s) failed integrity check: %s", exc)
            return [], True

    def _refresh_stats(self, records: list[UsageRecord], tracking_tampered: bool) -> None:
        if self._metadata_repository is not None:
            self.files_value_label.setText(str(len(self._metadata_repository.list_file_ids())))
        else:
            self.files_value_label.setText("—")

        if self._account_repository is not None:
            self.accounts_value_label.setText(str(len(self._account_repository.list_owner_ids())))
        else:
            self.accounts_value_label.setText("—")

        if self._deception_event_repository is not None:
            self.deception_value_label.setText(str(self._deception_event_repository.count()))
        else:
            self.deception_value_label.setText("—")

        self._refresh_tracking_stat(records, tracking_tampered)

    def _refresh_tracking_stat(self, records: list[UsageRecord], tracking_tampered: bool) -> None:
        if self._usage_tracker is None:
            self.tracking_value_label.setText("—")
            self.tracking_detail_label.setText("No usage tracker available")
            self.tracking_detail_label.setStyleSheet(f"color: {_FAIL_COLOR.name()};")
            return

        self.tracking_value_label.setText("—" if tracking_tampered else str(len(records)))

        result = self._usage_tracker.verify_log_integrity()
        if result.ok:
            self.tracking_detail_label.setText(f"Integrity OK ({result.verified_count})")
            self.tracking_detail_label.setStyleSheet(f"color: {_OK_COLOR.name()};")
        else:
            self.tracking_detail_label.setText(f"Integrity FAILED: {result.reason}")
            self.tracking_detail_label.setStyleSheet(f"color: {_FAIL_COLOR.name()};")

    def _refresh_activity(self, records: list[UsageRecord]) -> None:
        self.activity_list.clear()
        entries: list[tuple[datetime, str]] = []

        for record in records:
            timestamp = record.close_time or record.open_time or record.login_time
            if timestamp is None:
                continue
            denied = record.authentication_result is False or record.validation_result is False
            outcome = "denied access to" if denied else "accessed"
            entries.append((timestamp, f"{record.user} {outcome} {record.file_id}"))

        if self._deception_event_repository is not None:
            for event in self._deception_event_repository.list_events():
                target = event.file_id or "unknown file"
                entries.append(
                    (event.generated_at, f"Deception triggered ({event.trigger.value}) on {target}")
                )

        entries.sort(key=lambda entry: entry[0], reverse=True)

        if not entries:
            self.activity_list.addItem(QListWidgetItem("No recent activity recorded yet."))
            return

        for timestamp, description in entries[:_ACTIVITY_LIMIT]:
            stamp = format_datetime(timestamp)
            self.activity_list.addItem(QListWidgetItem(f"{stamp}  ·  {description}"))
