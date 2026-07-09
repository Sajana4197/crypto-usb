"""Device Validation page: USB device detection, validation, and secure
container storage (Secure Storage Layer).

Detects removable devices automatically, lets the user validate one and
write a plaintext file to it as an encrypted `.cusc` secure container —
protected by hybrid AES + RSA encryption and encrypted, HMAC'd metadata —
with overwrite protection and automatic post-write integrity verification.
No plaintext is ever written to the device.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from crypto import rsa_keypair
from crypto.key_wrapper import RSAOAEPKeyWrapper
from ui.pages.base_page import BasePage
from usb.device_detector import USBDevice, USBDeviceDetector
from usb.device_validator import USBDeviceValidator
from usb.exceptions import ContainerOverwriteError, USBError
from usb.secure_storage_service import SecureStorageService, SecureWriteResult

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_COLUMN_TITLES = ("Mount", "Label", "Filesystem", "Free Space", "Total Size", "Removable")

_OWNER_ID = "local-user"  # placeholder identity until the authentication phase exists


class DevicePage(BasePage):
    def __init__(self, parent=None) -> None:
        super().__init__(
            "Device Validation",
            "Detects removable USB devices, validates them, and stores files as "
            "encrypted secure containers — never in plaintext.",
            parent,
        )

        self._detector = USBDeviceDetector()
        self._validator = USBDeviceValidator()
        self._service = SecureStorageService()

        self._devices: list[USBDevice] = []
        self._selected_device: USBDevice | None = None
        self._source_path: Path | None = None
        self._key_wrapper: RSAOAEPKeyWrapper | None = None
        self._last_write: SecureWriteResult | None = None

        self.add_widget(self._build_device_toolbar())
        self.add_widget(self._build_device_table())
        self.add_widget(self._build_validation_panel())
        self.add_widget(self._build_write_panel())
        self.add_widget(self._build_status_label())

        self._refresh_devices()

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

    def _build_write_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailsPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 12)

        heading = QLabel("Store a file as a secure container")
        heading.setStyleSheet("font-weight: 600;")
        layout.addWidget(heading)

        row = QHBoxLayout()
        self.choose_file_button = QPushButton("Choose File...")
        self.choose_file_button.clicked.connect(self._on_choose_file_clicked)
        row.addWidget(self.choose_file_button)

        self.source_file_label = QLabel("No file selected.")
        self.source_file_label.setWordWrap(True)
        row.addWidget(self.source_file_label, 1)
        layout.addLayout(row)

        self.write_button = QPushButton("Write Secure Container")
        self.write_button.setObjectName("primaryButton")
        self.write_button.setEnabled(False)
        self.write_button.clicked.connect(self._on_write_clicked)
        layout.addWidget(self.write_button)

        return panel

    def _build_status_label(self) -> QWidget:
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("dropHint")
        return self.status_label

    # -- Device detection & validation -----------------------------------

    def _refresh_devices(self) -> None:
        self._devices = self._detector.detect_devices()
        self._populate_table()
        self._update_device_summary()
        self._selected_device = None
        self.validate_button.setEnabled(False)
        self.validation_label.setText("Select a device to validate it.")
        self._update_write_button_state()

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
            self._update_write_button_state()
            return

        row = next(iter(rows))
        device_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self._selected_device = next((d for d in self._devices if d.device_id == device_id), None)
        self.validate_button.setEnabled(self._selected_device is not None)
        self.validation_label.setText("Click “Validate Selected Device” to check it.")
        self._update_write_button_state()

    def _on_validate_clicked(self) -> None:
        if self._selected_device is None:
            return

        required_bytes = self._source_path.stat().st_size if self._source_path else 0
        result = self._validator.validate(self._selected_device, required_bytes=required_bytes)

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
        self._update_write_button_state()

    # -- Secure writing ----------------------------------------------------

    def _on_choose_file_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Store Securely")
        if path:
            self._source_path = Path(path)
            self.source_file_label.setText(str(self._source_path))
            self._update_write_button_state()

    def _update_write_button_state(self) -> None:
        self.write_button.setEnabled(
            self._selected_device is not None and self._source_path is not None
        )

    def _get_key_wrapper(self) -> RSAOAEPKeyWrapper:
        if self._key_wrapper is None:
            self._show_status("Generating session key pair (RSA-4096)...")
            keypair = rsa_keypair.generate_rsa_keypair()
            self._key_wrapper = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
        return self._key_wrapper

    def _on_write_clicked(self) -> None:
        if self._selected_device is None or self._source_path is None:
            return
        self._write_container(overwrite=False)

    def _write_container(self, overwrite: bool) -> None:
        assert self._selected_device is not None and self._source_path is not None
        key_wrapper = self._get_key_wrapper()

        try:
            result = self._service.store_file(
                source_path=self._source_path,
                device=self._selected_device,
                key_wrapper=key_wrapper,
                owner_id=_OWNER_ID,
                overwrite=overwrite,
            )
        except ContainerOverwriteError:
            if self._confirm_overwrite():
                self._write_container(overwrite=True)
            else:
                self._show_status("Write cancelled: a container already exists at the destination.")
            return
        except USBError as exc:
            logger.error("Secure write failed: %s", exc)
            self._show_status(f"Write failed: {exc}", ok=False)
            return

        self._last_write = result
        self._show_status(
            f"Wrote secure container {result.destination.name} "
            f"({result.container_size_bytes:,} bytes) to {self._selected_device.mount_point}. "
            f"Post-write integrity check passed."
        )
        self._deep_verify(result, key_wrapper)

    def _deep_verify(self, result: SecureWriteResult, key_wrapper: RSAOAEPKeyWrapper) -> None:
        try:
            self._service.verify_stored_file(
                container_path=result.destination,
                key_wrapper=key_wrapper,
                protection_keys=result.protection_keys,
            )
        except USBError as exc:
            logger.error("Deep verification failed for %s: %s", result.destination, exc)
            self._show_status(f"Deep verification FAILED: {exc}", ok=False)
            return

        self._show_status(
            f"Wrote and fully verified {result.destination.name} "
            f"(file_id={result.file_id}) — decryption round-trip and metadata "
            f"integrity confirmed in memory; no plaintext was written to disk."
        )

    def _confirm_overwrite(self) -> bool:
        answer = QMessageBox.question(
            self,
            "Container Already Exists",
            "A secure container with this name already exists on the device. "
            "Overwrite it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    # -- Status ------------------------------------------------------------

    def _show_status(self, message: str, ok: bool = True) -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {(_OK_COLOR if ok else _FAIL_COLOR).name()};")
        if ok:
            logger.info(message)
        else:
            logger.warning(message)
