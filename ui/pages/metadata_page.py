"""Metadata page: a read-only view over stored file metadata records.

Reads directly from the same `metadata.repository.MetadataRepository`
`ui.pages.encryption_page.EncryptionPage` writes to and
`ui.pages.decryption_page.DecryptionPage` validates against — no new
write path, and no new persistence: every record shown here already
exists because a file was written through the normal Encrypt File
flow.
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
from metadata.exceptions import MetadataTamperError
from metadata.models import FileMetadata
from metadata.protection import MetadataProtectionKeys, MetadataProtector
from metadata.repository import MetadataRepository
from ui.pages.base_page import BasePage

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_COLUMN_TITLES = (
    "File ID",
    "Owner",
    "Created At",
    "Access Count",
    "One-Time Access",
    "Device Bound",
    "Expires At",
)


def _fmt(value) -> str:
    return value.isoformat(sep=" ", timespec="seconds") if value is not None else "—"


class MetadataPage(BasePage):
    def __init__(
        self,
        metadata_repository: Optional[MetadataRepository] = None,
        protection_keys: Optional[MetadataProtectionKeys] = None,
        parent=None,
    ) -> None:
        super().__init__(
            "Metadata",
            "Read-only view of every protected file's metadata record: owner, "
            "access count, one-time-access policy, and device binding.",
            parent,
        )

        self._metadata_repository = metadata_repository
        self._protection_keys = protection_keys

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
        if self._metadata_repository is None or self._protection_keys is None:
            self.summary_label.setText("No metadata repository is available in this session.")
            return

        protector = MetadataProtector(self._protection_keys)
        file_ids = self._metadata_repository.list_file_ids()
        shown = 0
        tampered = 0
        for file_id in file_ids:
            protected = self._metadata_repository.load(file_id)
            if protected is None:
                continue
            try:
                metadata = protector.unprotect(protected)
            except MetadataTamperError:
                tampered += 1
                logger.warning("Metadata record for file_id=%s failed its integrity check", file_id)
                continue
            self._append_row(metadata)
            shown += 1

        summary = f"{shown} record(s)"
        if tampered:
            summary += f" · {tampered} failed integrity check"
        self.summary_label.setText(summary)

    def _append_row(self, metadata: FileMetadata) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = (
            QTableWidgetItem(metadata.file_id),
            QTableWidgetItem(metadata.owner_id),
            QTableWidgetItem(_fmt(metadata.created_at)),
            QTableWidgetItem(str(metadata.access_count)),
            QTableWidgetItem("Yes" if metadata.usage_policy.one_time_access else "No"),
            QTableWidgetItem("Yes" if metadata.device_binding.bound else "No"),
            QTableWidgetItem(_fmt(metadata.expiry_rules.expires_at)),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)
