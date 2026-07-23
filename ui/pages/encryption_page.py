"""Encrypt File page: the write side of the Secure Storage Layer (Sender
Module).

Detects removable USB devices, lets the user pick one and a plaintext
file, and stores it as an encrypted `.cusc` secure container —
protected by hybrid AES + RSA encryption and encrypted, HMAC'd
metadata — with overwrite protection and automatic post-write
integrity verification. No plaintext is ever written to the device.

When `metadata_repository`/`protection_keys` are supplied (see
`ui.main_window.MainWindow._build_shared_services`), each write's
metadata is also persisted there and bound to the presenting device —
the same repository `ui.pages.decryption_page.DecryptionPage` reads
from, which is what lets a file written here actually be validated and
opened there later. Without them (e.g. the standalone page constructed
in tests) writes still succeed exactly as before, just without a
locally queryable record.

The RSA keypair used to wrap each file's key is generated once per
page instance and, like `ui.dialogs.auth_dialog.AuthDialog`'s
authentication keypair, is never persisted by the application itself —
"Export Key Pair for Decryption..." lets the user save its encrypted
private key to a file of their choosing. Without doing this before
closing the app, a file written here can never be decrypted again by
anyone, including its owner — the private key would exist nowhere.

Each write also derives that file's own portable metadata protection
keys from this same session private key plus a passphrase (prompted
for fresh on every write — see `_prompt_passphrase`) and a fresh
random salt (`metadata.protection.derive_protection_keys_from_key_material`),
and embeds the resulting protected metadata directly in the `.cusc`
container as its portable-metadata section
(`usb.secure_container.SecureContainer`) — one file, not a separate
sibling. Because the same private key + passphrase always re-derive
the same keys, that metadata is recoverable on any machine holding
just this one file — no local database required. This is additive and
best-effort: if the passphrase prompt is cancelled or the passphrase
is too short, the write still proceeds exactly as before, just without
a portable-metadata section.

Every write prompts fresh, unconditionally — so two files written in
the same page session can be protected by two different passphrases.
"Export Key Pair..." only reuses a passphrase from the write that
*immediately* preceded it (so exporting right after writing a file
doesn't ask twice for the same file); it prompts independently if
nothing was just written (e.g. exporting before any write this
session, or a second export after a second, different write). Writing
a further file always overwrites this one-write-deep memory with its
own fresh prompt, never with the previous file's.

Mirrors `ui.pages.decryption_page.DecryptionPage`'s device-table ->
panel -> containers-table structure, so the file you just wrote here
shows up immediately in this page's own containers table — not just on
the read side.

The device table refreshes itself automatically on a timer (as well as
via the "Refresh Devices" button) so a device plugged in or removed
while this page is open shows up without the user having to ask for
it. A refresh is a no-op — it never rebuilds the table or disturbs the
current selection — whenever the detected device set hasn't actually
changed since the last check.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.constants import LOCAL_OWNER_ID
from core.logger import get_logger
from crypto import rsa_keypair
from crypto.exceptions import CryptoError
from crypto.key_wrapper import RSAOAEPKeyWrapper
from metadata.models import UsagePolicy
from metadata.protection import MetadataProtectionKeys, derive_protection_keys_from_key_material
from metadata.repository import MetadataRepository
from security.auth_session import SessionManager
from security.password_hasher import MIN_PASSWORD_LENGTH, SALT_LEN_BYTES
from ui.pages.base_page import BasePage
from ui.widgets.busy import busy_cursor, progress_dialog, show_result_popup
from usb.device_detector import USBDevice, USBDeviceDetector
from usb.exceptions import ContainerOverwriteError, USBError
from usb.secure_storage_service import SecureStorageService, SecureWriteResult

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_DEVICE_COLUMN_TITLES = ("Mount", "Label", "Filesystem", "Free Space", "Total Size", "Removable")
_CONTAINER_GLOB = "*.cusc"

# How often the device table polls for plugged-in/removed devices without
# any user action. Frequent enough to feel "automatic" during a demo,
# infrequent enough that the background psutil calls are never noticeable.
_DEVICE_POLL_INTERVAL_MS = 2000


class EncryptionPage(BasePage):
    def __init__(
        self,
        metadata_repository: Optional[MetadataRepository] = None,
        protection_keys: Optional[MetadataProtectionKeys] = None,
        session_manager: Optional[SessionManager] = None,
        parent=None,
    ) -> None:
        super().__init__(
            "Encrypt File",
            "Detects removable USB devices and stores files as encrypted secure "
            "containers — never in plaintext.",
            parent,
        )

        self._detector = USBDeviceDetector()
        self._service = SecureStorageService()
        self._metadata_repository = metadata_repository
        self._protection_keys = protection_keys
        self._session_manager = session_manager

        self._devices: Optional[list[USBDevice]] = None
        self._selected_device: USBDevice | None = None
        self._containers: list[Path] = []
        self._source_path: Path | None = None
        self._key_wrapper: RSAOAEPKeyWrapper | None = None
        self._last_write: SecureWriteResult | None = None
        self._last_write_passphrase: bytes | None = None

        self.add_widget(self._build_device_toolbar())
        self.add_widget(self._build_device_table())
        self.add_widget(self._build_write_panel())
        self.add_widget(self._build_container_table())
        self.add_widget(self._build_status_label())

        self._refresh_devices()

        self._device_poll_timer = QTimer(self)
        self._device_poll_timer.setInterval(_DEVICE_POLL_INTERVAL_MS)
        self._device_poll_timer.timeout.connect(self._refresh_devices)
        self._device_poll_timer.start()

    def _owner_id(self) -> str:
        if self._session_manager is not None and self._session_manager.current is not None:
            return self._session_manager.current.owner_id
        return LOCAL_OWNER_ID

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
        self.table = QTableWidget(0, len(_DEVICE_COLUMN_TITLES))
        self.table.setHorizontalHeaderLabels(list(_DEVICE_COLUMN_TITLES))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(160)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(_DEVICE_COLUMN_TITLES)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_device_selected)
        return self.table

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

        self.one_time_access_checkbox = QCheckBox("One-time access (file is destroyed after first successful view)")
        self.one_time_access_checkbox.setToolTip(
            "Once enabled, this file can only be viewed successfully once — any "
            "attempt after the first will silently receive fake content instead "
            "of an error, matching the app's deception design."
        )
        layout.addWidget(self.one_time_access_checkbox)

        self.write_button = QPushButton("Write Secure Container")
        self.write_button.setObjectName("primaryButton")
        self.write_button.setEnabled(False)
        self.write_button.clicked.connect(self._on_write_clicked)
        layout.addWidget(self.write_button)

        self.export_key_button = QPushButton("Export Key Pair for Decryption...")
        self.export_key_button.setToolTip(
            "Save this session's file-wrapping private key, encrypted with a "
            "passphrase you choose. The application never keeps a copy — "
            "without exporting it, files written this session can never be "
            "decrypted again by anyone."
        )
        self.export_key_button.clicked.connect(self._on_export_key_clicked)
        layout.addWidget(self.export_key_button)

        return panel

    def _build_container_table(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailsPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 12)

        heading = QLabel("Files encrypted on this device")
        heading.setStyleSheet("font-weight: 600;")
        layout.addWidget(heading)

        self.container_table = QTableWidget(0, 1)
        self.container_table.setHorizontalHeaderLabels(["File"])
        self.container_table.verticalHeader().setVisible(False)
        self.container_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.container_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.container_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.container_table.horizontalHeader().setStretchLastSection(True)
        self.container_table.setMinimumHeight(120)
        self.container_table.setMaximumHeight(220)
        layout.addWidget(self.container_table)

        return panel

    def _build_status_label(self) -> QWidget:
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("dropHint")
        return self.status_label

    # -- Device detection --------------------------------------------------

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
        self._update_write_button_state()
        self._reselect_device(previously_selected_id)
        if self._selected_device is None:
            # No previous selection to restore, or the previously selected
            # device is no longer present — `_reselect_device` only
            # refreshes containers (via `_on_device_selected`) when it
            # actually finds and reselects a row, so the container table
            # needs an explicit refresh here to reflect "nothing selected".
            self._refresh_containers()

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
        else:
            row = next(iter(rows))
            device_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            self._selected_device = next((d for d in self._devices if d.device_id == device_id), None)
        self._update_write_button_state()
        self._refresh_containers()

    # -- Containers already on the device -----------------------------------

    def _refresh_containers(self) -> None:
        containers = []
        if self._selected_device is not None:
            containers = sorted(Path(self._selected_device.mount_point).glob(_CONTAINER_GLOB))

        if containers == self._containers:
            # Nothing actually changed — skip the rebuild (a background
            # poll, see the module docstring, would otherwise redraw this
            # table every couple of seconds for no reason).
            return

        self._containers = containers
        self.container_table.setRowCount(0)
        for path in self._containers:
            row = self.container_table.rowCount()
            self.container_table.insertRow(row)
            item = QTableWidgetItem(path.name)
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            self.container_table.setItem(row, 0, item)

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
            with busy_cursor():
                keypair = rsa_keypair.generate_rsa_keypair()
            self._key_wrapper = RSAOAEPKeyWrapper(keypair.public_key, keypair.private_key)
        return self._key_wrapper

    def _prompt_passphrase(self, title: str, message: str) -> Optional[bytes]:
        """Prompt for a passphrase, unconditionally. Returns None if the
        prompt is cancelled or the passphrase is too short — callers
        must treat that as "skip the portable copy"/"export cancelled",
        not as an error.
        """
        passphrase, ok = QInputDialog.getText(self, title, message, QLineEdit.EchoMode.Password)
        if not ok or len(passphrase) < MIN_PASSWORD_LENGTH:
            return None
        return passphrase.encode("utf-8")

    def _derive_portable_metadata_keys(
        self, key_wrapper: RSAOAEPKeyWrapper
    ) -> tuple[Optional[MetadataProtectionKeys], Optional[bytes]]:
        """Always prompts fresh (see the module docstring) — every write
        gets its own passphrase, even a second file written in the same
        session. Remembers it in `_last_write_passphrase` purely so an
        export immediately after this write doesn't ask again for the
        same file; a failed/cancelled prompt clears that memory so a
        following export doesn't silently reuse an older, unrelated
        file's passphrase instead.
        """
        if key_wrapper.private_key is None:
            self._last_write_passphrase = None
            return None, None
        passphrase = self._prompt_passphrase(
            "Protect Portable Metadata",
            "Passphrase to protect this file's portable metadata "
            f"(minimum {MIN_PASSWORD_LENGTH} characters):",
        )
        self._last_write_passphrase = passphrase
        if passphrase is None:
            return None, None

        salt = os.urandom(SALT_LEN_BYTES)
        private_key_material = rsa_keypair.private_key_material(key_wrapper.private_key)
        keys = derive_protection_keys_from_key_material(private_key_material, passphrase, salt)
        return keys, salt

    def _on_export_key_clicked(self) -> None:
        key_wrapper = self._get_key_wrapper()
        if key_wrapper.private_key is None:
            self._show_status("No private key available to export.", ok=False)
            return

        # Reuses the passphrase from the write that just happened, if
        # any (see `_derive_portable_metadata_keys`) — so exporting right
        # after writing a file doesn't ask a second time for it. Prompts
        # fresh only when nothing was just written (e.g. export clicked
        # before any write this session).
        if self._last_write_passphrase is not None:
            passphrase_bytes = self._last_write_passphrase
        else:
            passphrase_bytes = self._prompt_passphrase(
                "Export Private Key",
                f"Passphrase to encrypt the exported key (minimum {MIN_PASSWORD_LENGTH} characters):",
            )
        if passphrase_bytes is None:
            self._show_status(
                f"Export cancelled: passphrase must be at least {MIN_PASSWORD_LENGTH} characters.", ok=False
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Encrypted Private Key", "file_wrapping_key.pem", "PEM Files (*.pem)"
        )
        if not path:
            return

        try:
            private_pem = rsa_keypair.serialize_private_key(key_wrapper.private_key, passphrase_bytes)
            Path(path).write_bytes(private_pem)
        except (CryptoError, OSError) as exc:
            logger.error("Failed to export private key to %s: %s", path, exc)
            self._show_status(f"Failed to export private key: {exc}", ok=False, important=True)
            return

        self._show_status(
            f"Exported encrypted private key to {path}. Keep it and its passphrase safe.", important=True
        )
        logger.info("Exported session file-wrapping private key to %s", path)

        self._source_path = None
        self.source_file_label.setText("No file selected.")
        self._update_write_button_state()

    def _on_write_clicked(self) -> None:
        if self._selected_device is None or self._source_path is None:
            return
        self._write_container(self._selected_device, self._source_path, overwrite=False)

    def _write_container(self, device: USBDevice, source_path: Path, overwrite: bool) -> None:
        """`device`/`source_path` are snapshotted by the caller rather than
        re-read from `self._selected_device`/`self._source_path` here —
        `_get_key_wrapper()` and `progress_dialog` below both pump the Qt
        event loop (to keep the UI responsive during RSA-4096 keygen and
        the write itself), which gives the background device-poll timer
        (see the module docstring) a chance to run and rebuild the device
        table out from under an in-progress write. `USBDevice` is a
        frozen dataclass, so holding a reference to the one the user
        actually selected is safe no matter what `self._selected_device`
        becomes in the meantime.
        """
        key_wrapper = self._get_key_wrapper()
        portable_metadata_keys, portable_metadata_salt = self._derive_portable_metadata_keys(key_wrapper)

        try:
            with progress_dialog(self, "Encrypting and writing secure container..."):
                result = self._service.store_file(
                    source_path=source_path,
                    device=device,
                    key_wrapper=key_wrapper,
                    owner_id=self._owner_id(),
                    overwrite=overwrite,
                    protection_keys=self._protection_keys,
                    metadata_repository=self._metadata_repository,
                    bind_to_device=True,
                    usage_policy=UsagePolicy(one_time_access=self.one_time_access_checkbox.isChecked()),
                    portable_metadata_keys=portable_metadata_keys,
                    portable_metadata_salt=portable_metadata_salt,
                )
        except ContainerOverwriteError:
            if self._confirm_overwrite():
                self._write_container(device, source_path, overwrite=True)
            else:
                self._show_status("Write cancelled: a container already exists at the destination.")
            return
        except USBError as exc:
            logger.error("Secure write failed: %s", exc)
            self._show_status(f"Write failed: {exc}", ok=False, important=True)
            return

        self._last_write = result
        self.one_time_access_checkbox.setChecked(False)
        self._show_status(
            f"Wrote secure container {result.destination.name} "
            f"({result.container_size_bytes:,} bytes) to {device.mount_point}. "
            f"Post-write integrity check passed.",
            important=True,
        )
        # Refresh the container table for the device just written to — not
        # necessarily whatever `self._selected_device` is *now*, in the rare
        # case a background poll (or the user) changed the selection while
        # the write was in flight.
        if self._selected_device is not None and self._selected_device.device_id == device.device_id:
            self._refresh_containers()
        else:
            self._reselect_device(device.device_id)
        self._deep_verify(result, key_wrapper)

    def _deep_verify(self, result: SecureWriteResult, key_wrapper: RSAOAEPKeyWrapper) -> None:
        try:
            with progress_dialog(self, "Verifying secure container..."):
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

    def _show_status(self, message: str, ok: bool = True, important: bool = False) -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {(_OK_COLOR if ok else _FAIL_COLOR).name()};")
        if ok:
            logger.info(message)
        else:
            logger.warning(message)
        if important:
            show_result_popup(self, message, ok=ok)
