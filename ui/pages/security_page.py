"""Access Security page: a read-only view over account lockout state.

Reads directly from the same `security.account_repository.AccountRepository`
`security.auth_controller.AuthController` already writes to on every
authentication attempt — no new write path. `security.lockout_policy.LockoutPolicy`
is the same policy object that decides lockouts at sign-in time; this page
only calls its read-only `is_locked`/`seconds_remaining` methods.
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
from security.account_repository import AccountRepository
from security.lockout_policy import LockoutPolicy
from security.models import UserAccount
from ui.pages.base_page import BasePage
from utils.formatting import format_datetime

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

# Matches the device-table poll interval used elsewhere (Phase 22/23) so
# every page feels equally "live".
_REFRESH_INTERVAL_MS = 2000

_COLUMN_TITLES = (
    "Owner",
    "Auth Method",
    "Failed Attempts",
    "Locked",
    "Unlocks In (s)",
    "Last Login",
)


class SecurityPage(BasePage):
    def __init__(
        self,
        account_repository: Optional[AccountRepository] = None,
        lockout_policy: Optional[LockoutPolicy] = None,
        parent=None,
    ) -> None:
        super().__init__(
            "Access Security",
            "Read-only view of brute-force lockout state for every local account: "
            "failed attempts so far, and whether the account is currently locked.",
            parent,
        )

        self._account_repository = account_repository
        self._lockout_policy = lockout_policy or LockoutPolicy()
        self._last_accounts: Optional[list[UserAccount]] = None

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
        self.table.setMinimumHeight(220)

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
        if self._account_repository is None:
            self.table.setRowCount(0)
            self.summary_label.setText("No account repository is available in this session.")
            return

        owner_ids = self._account_repository.list_owner_ids()
        accounts = [self._account_repository.load(owner_id) for owner_id in owner_ids]
        accounts = [account for account in accounts if account is not None]

        locked_count = sum(1 for account in accounts if self._lockout_policy.is_locked(account))

        # The "Unlocks In" countdown is a function of wall-clock time, not
        # just the stored account record — a locked account must always
        # rebuild so the countdown actually ticks down. Only skip the
        # rebuild (and preserve scroll position) when nothing is currently
        # locked and the account records themselves are unchanged.
        if locked_count == 0 and accounts == self._last_accounts:
            return
        self._last_accounts = accounts

        self.table.setRowCount(0)
        for account in accounts:
            self._append_row(account)

        summary = f"{len(accounts)} account(s)"
        if locked_count:
            summary += f" · {locked_count} currently locked"
        self.summary_label.setText(summary)

    def _append_row(self, account: UserAccount) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        locked = self._lockout_policy.is_locked(account)
        locked_item = QTableWidgetItem("Yes" if locked else "No")
        locked_item.setForeground(_FAIL_COLOR if locked else _OK_COLOR)

        remaining = self._lockout_policy.seconds_remaining(account) if locked else 0

        values = (
            QTableWidgetItem(account.owner_id),
            QTableWidgetItem(account.auth_method.value),
            QTableWidgetItem(str(account.failed_attempts)),
            locked_item,
            QTableWidgetItem(str(remaining) if locked else "—"),
            QTableWidgetItem(format_datetime(account.last_login_at)),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)
