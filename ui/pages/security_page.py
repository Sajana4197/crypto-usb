"""Access Security page: a read-only view over account lockout state.

Reads directly from the same `security.account_repository.AccountRepository`
`security.auth_controller.AuthController` already writes to on every
authentication attempt — no new write path. `security.lockout_policy.LockoutPolicy`
is the same policy object that decides lockouts at sign-in time; this page
only calls its read-only `is_locked`/`seconds_remaining` methods.
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
from security.account_repository import AccountRepository
from security.lockout_policy import LockoutPolicy
from security.models import UserAccount
from ui.pages.base_page import BasePage

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_COLUMN_TITLES = (
    "Owner",
    "Auth Method",
    "Failed Attempts",
    "Locked",
    "Unlocks In (s)",
    "Last Login",
)


def _fmt(value) -> str:
    return value.isoformat(sep=" ", timespec="seconds") if value is not None else "—"


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
        self.table.setRowCount(0)
        if self._account_repository is None:
            self.summary_label.setText("No account repository is available in this session.")
            return

        owner_ids = self._account_repository.list_owner_ids()
        locked_count = 0
        for owner_id in owner_ids:
            account = self._account_repository.load(owner_id)
            if account is None:
                continue
            if self._lockout_policy.is_locked(account):
                locked_count += 1
            self._append_row(account)

        summary = f"{len(owner_ids)} account(s)"
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
            QTableWidgetItem(_fmt(account.last_login_at)),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)
