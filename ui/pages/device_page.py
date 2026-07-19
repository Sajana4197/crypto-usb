"""Device Validation page: USB device detection and validation.

Detects removable devices automatically and lets the user validate one
against every independent check `usb.device_validator.USBDeviceValidator`
runs — still attached, genuinely removable, writable, and has enough
free space — with a specific, actionable reason recorded for any check
that fails, rather than a single opaque yes/no.

This page is standalone and has no write path of its own: writing a
plaintext file as an encrypted secure container is
`ui.pages.encryption_page.EncryptionPage`'s job. The two were
previously combined here, but validating a device and writing to one
are — and always were — independent operations (the write button was
never gated on the validation checklist's result), so splitting them
is a UI reorganization, not a behavior change.

The device table refreshes itself automatically on a timer (as well as
via the "Refresh Devices" button) so a device plugged in or removed
while this page is open shows up without the user having to ask for
it. A refresh is a no-op — it never rebuilds the table or disturbs the
current selection — whenever the detected device set hasn't actually
changed since the last check.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from core.logger import get_logger
from ui.pages.base_page import BasePage
from usb.device_detector import USBDevice, USBDeviceDetector
from usb.device_validator import USBDeviceValidator

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_COLUMN_TITLES = ("Mount", "Label", "Filesystem", "Free Space", "Total Size", "Removable")

# How often the device table polls for plugged-in/removed devices without
# any user action. Frequent enough to feel "automatic" during a demo,
# infrequent enough that the background psutil calls are never noticeable.
_DEVICE_POLL_INTERVAL_MS = 2000


class DevicePage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Device Validation",
            "Detects removable USB devices and validates them: attached, "
            "removable, writable, and has sufficient free space.",
            parent,
        )

        self._detector = USBDeviceDetector()
        self._validator = USBDeviceValidator()

        self._devices: Optional[list[USBDevice]] = None
        self._selected_device: USBDevice | None = None

        self.add_widget(self._build_device_toolbar())
        self.add_widget(self._build_device_table())
        self.add_widget(self._build_validation_panel())

        self._refresh_devices()

        self._device_poll_timer = QTimer(self)
        self._device_poll_timer.setInterval(_DEVICE_POLL_INTERVAL_MS)
        self._device_poll_timer.timeout.connect(self._refresh_devices)
        self._device_poll_timer.start()

    # -- UI construction -------------------------------------------------

    def _build_device_toolbar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)

        self.refresh_button = QPushButton("Refresh Devices")
        self.refresh_button.clicked.connect(self._refresh_devices)
        layout.addWidget(self.refresh_button)

        layout.addStretch(1)

        self.device_summary_label = QLabel()
        layout.addWidget(self.device_summary_label)

        return bar

    def _build_device_table(self) -> QWidget:
        self.table = QTableWidget(0, len(_COLUMN_TITLES))
        self.table.setHorizontalHeaderLabels(list(_COLUMN_TITLES))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(160)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(_COLUMN_TITLES)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_device_selected)
        return self.table

    def _build_validation_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailsPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 12)

        header = QHBoxLayout()
        self.validate_button = QPushButton("Validate Selected Device")
        self.validate_button.setEnabled(False)
        self.validate_button.clicked.connect(self._on_validate_clicked)
        header.addWidget(self.validate_button)
        header.addStretch(1)
        layout.addLayout(header)

        self.validation_label = QLabel("Select a device to validate it.")
        self.validation_label.setWordWrap(True)
        layout.addWidget(self.validation_label)

        return panel

    # -- Device detection & validation -----------------------------------

    def _refresh_devices(self) -> None:
        devices = self._detector.detect_devices()
        if devices == self._devices:
            # Nothing actually changed (same devices, same free space) —
            # skip the rebuild so a background poll never disturbs the
            # current selection or scroll position.
            return

        previously_selected_id = self._selected_device.device_id if self._selected_device else None
        self._devices = devices
        self._populate_table()
        self._update_device_summary()
        self._selected_device = None
        self.validate_button.setEnabled(False)
        self.validation_label.setText("Select a device to validate it.")
        self._reselect_device(previously_selected_id)

    def _reselect_device(self, device_id: Optional[str]) -> None:
        """Restore the previous selection after a rebuild, if that device
        is still present — e.g. a different device was plugged in or
        removed elsewhere on the system, but the one the user had
        selected here is unaffected."""
        if device_id is None:
            return
        for row, device in enumerate(self._devices):
            if device.device_id == device_id:
                self.table.selectRow(row)
                return

    def _populate_table(self) -> None:
        self.table.setRowCount(0)
        for device in self._devices:
            self._append_device_row(device)

    def _append_device_row(self, device: USBDevice) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        mount_item = QTableWidgetItem(device.mount_point)
        mount_item.setData(Qt.ItemDataRole.UserRole, device.device_id)

        values = (
            mount_item,
            QTableWidgetItem(device.label or "—"),
            QTableWidgetItem(device.filesystem or "—"),
            QTableWidgetItem(device.free_display),
            QTableWidgetItem(device.total_display),
            QTableWidgetItem("Yes" if device.is_removable else "No"),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)

    def _update_device_summary(self) -> None:
        count = len(self._devices)
        self.device_summary_label.setText(
            "No removable devices detected" if count == 0 else f"{count} device(s) detected"
        )

    def _on_device_selected(self) -> None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if len(rows) != 1:
            self._selected_device = None
            self.validate_button.setEnabled(False)
            return

        row = next(iter(rows))
        device_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self._selected_device = next((d for d in self._devices if d.device_id == device_id), None)
        self.validate_button.setEnabled(self._selected_device is not None)
        self.validation_label.setText("Click “Validate Selected Device” to check it.")

    def _on_validate_clicked(self) -> None:
        if self._selected_device is None:
            return

        result = self._validator.validate(self._selected_device)

        lines = []
        for name, passed in result.checks.items():
            mark = "✓" if passed else "✗"
            lines.append(f"{mark} {name.replace('_', ' ').title()}")
        if result.reasons:
            lines.append("")
            lines.extend(result.reasons)
        self.validation_label.setText("<br>".join(lines))
        self.validation_label.setStyleSheet(
            f"color: {(_OK_COLOR if result.ok else _FAIL_COLOR).name()};"
        )
