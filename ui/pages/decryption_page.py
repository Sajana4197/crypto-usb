"""Decryption page: the read side of the Secure Storage Layer.

Mirrors `ui.pages.device_page.DevicePage`'s completeness on the write
side: detects a USB device, lists the `.cusc` secure containers on it,
loads the file-wrapping private key the user exported when the file
was written, and hands everything to
`usb.secure_access_service.SecureAccessService` — which runs every
access-time check (Validation), decrypts strictly in RAM (RAM
Decryption), burns a one-time-access file immediately after its single
legitimate view (One-Time Access), and records the attempt in the
tamper-evident usage log (Usage Tracking).

Whatever `SecureAccessService.attempt_access` hands back — the real
plaintext, or the Deception Engine's fabricated stand-in — is rendered
identically through `viewer.secure_viewer_widget.SecureViewerWidget`.
This is deliberate, not an oversight: the Deception Engine's entire
purpose is to be indistinguishable from a genuine denial-free view, so
this page never brands one outcome as "denied" and the other as
"granted" anywhere the user (or an attacker) can see. Only the log
(`core.logger`) ever records which one actually happened.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from crypto import rsa_keypair
from crypto.exceptions import CryptoError
from crypto.key_wrapper import RSAOAEPKeyWrapper
from deception.deception_engine import DeceptionEngine
from deception.event_repository import DeceptionEventRepository
from metadata.protection import MetadataProtectionKeys
from metadata.repository import MetadataRepository
from security.auth_session import SessionManager
from tracking.tracking_service import UsageTracker
from ui.pages.base_page import BasePage
from ui.widgets.busy import progress_dialog
from usb.device_detector import USBDevice, USBDeviceDetector
from usb.exceptions import USBError
from usb.secure_access_service import SecureAccessService
from usb.secure_storage_service import SecureStorageService
from validation.machine_fingerprint import compute_machine_fingerprint
from validation.usb_identifier import compute_usb_identifier
from viewer.secure_viewer_widget import SecureViewerWidget

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_DEVICE_COLUMN_TITLES = ("Mount", "Label", "Filesystem", "Free Space", "Removable")
_CONTAINER_GLOB = "*.cusc"


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8"
_GIF_MAGICS = (b"GIF87a", b"GIF89a")
_PDF_MAGIC = b"%PDF-"


def _sniff_content_type(content: bytes) -> str:
    """Guess a `viewer.secure_viewer_widget.SecureViewerWidget`-recognized
    content type by inspecting the decrypted bytes themselves.

    `metadata.models.FileMetadata` deliberately records nothing about the
    original file's name or type (that information isn't needed for any
    cryptographic or access-control purpose, and keeping it out avoids
    ever having to trust a caller-supplied string) — so this is the only
    signal available at view time, and it never touches disk.
    """
    if content.startswith(_PDF_MAGIC):
        return "application/pdf"
    if content.startswith(_PNG_MAGIC):
        return "image/png"
    if content.startswith(_JPEG_MAGIC):
        return "image/jpeg"
    if content[:6] in _GIF_MAGICS:
        return "image/gif"
    try:
        content.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


class DecryptionPage(BasePage):
    def __init__(
        self,
        metadata_repository: Optional[MetadataRepository] = None,
        protection_keys: Optional[MetadataProtectionKeys] = None,
        session_manager: Optional[SessionManager] = None,
        usage_tracker: Optional[UsageTracker] = None,
        deception_event_repository: Optional[DeceptionEventRepository] = None,
        parent=None,
    ) -> None:
        super().__init__(
            "Decrypt & View",
            "RAM-only decryption of a secure container, subject to every access-time "
            "check, one-time-access enforcement, and usage tracking. Never writes "
            "decrypted content to disk.",
            parent,
        )

        self._detector = USBDeviceDetector()
        self._metadata_repository = metadata_repository
        self._protection_keys = protection_keys or _fallback_protection_keys()
        self._session_manager = session_manager
        self._usage_tracker = usage_tracker
        self._storage_service = SecureStorageService()
        # A single DeceptionEngine instance per page, so every denied attempt
        # in this session is recorded through the same (optional) audit
        # trail — see ui.pages.deception_page.DeceptionPage for the read-only
        # view over it. `deception_event_repository=None` is fully supported:
        # the engine still fabricates decoy content, it just has nowhere to
        # log the activation, exactly as before this repository existed.
        self._deception_engine = DeceptionEngine(event_repository=deception_event_repository)

        self._devices: list[USBDevice] = []
        self._selected_device: USBDevice | None = None
        self._containers: list[Path] = []
        self._selected_container: Path | None = None
        self._key_wrapper: RSAOAEPKeyWrapper | None = None
        self._active_viewer: Optional[SecureViewerWidget] = None

        self.add_widget(self._build_device_toolbar())
        self.add_widget(self._build_device_table())
        self.add_widget(self._build_key_panel())
        self.add_widget(self._build_container_panel())
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
        self.table = QTableWidget(0, len(_DEVICE_COLUMN_TITLES))
        self.table.setHorizontalHeaderLabels(list(_DEVICE_COLUMN_TITLES))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(140)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(_DEVICE_COLUMN_TITLES)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_device_selected)
        return self.table

    def _build_key_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailsPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 12)

        heading = QLabel("Load the private key used to encrypt the file")
        heading.setStyleSheet("font-weight: 600;")
        layout.addWidget(heading)

        row = QHBoxLayout()
        self.choose_key_button = QPushButton("Browse Private Key File...")
        self.choose_key_button.clicked.connect(self._on_choose_key_clicked)
        row.addWidget(self.choose_key_button)

        self.key_path_label = QLabel("No private key loaded.")
        self.key_path_label.setWordWrap(True)
        row.addWidget(self.key_path_label, 1)
        layout.addLayout(row)

        layout.addWidget(QLabel("Passphrase:"))
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.passphrase_edit)

        self.load_key_button = QPushButton("Load Key")
        self.load_key_button.clicked.connect(self._on_load_key_clicked)
        layout.addWidget(self.load_key_button)

        return panel

    def _build_container_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("detailsPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 12)

        heading = QLabel("Secure containers on the selected device")
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
        self.container_table.itemSelectionChanged.connect(self._on_container_selected)
        layout.addWidget(self.container_table)

        self.view_button = QPushButton("View Selected File")
        self.view_button.setObjectName("primaryButton")
        self.view_button.setEnabled(False)
        self.view_button.clicked.connect(self._on_view_clicked)
        layout.addWidget(self.view_button)

        return panel

    def _build_status_label(self) -> QWidget:
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("dropHint")
        return self.status_label

    # -- Device & container listing ---------------------------------------

    def _refresh_devices(self) -> None:
        self._devices = self._detector.detect_devices()
        self.table.setRowCount(0)
        for device in self._devices:
            self._append_device_row(device)
        count = len(self._devices)
        self.device_summary_label.setText(
            "No removable devices detected" if count == 0 else f"{count} device(s) detected"
        )
        self._selected_device = None
        self._refresh_containers()

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
            QTableWidgetItem("Yes" if device.is_removable else "No"),
        )
        for column, cell in enumerate(values):
            self.table.setItem(row, column, cell)

    def _on_device_selected(self) -> None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if len(rows) != 1:
            self._selected_device = None
        else:
            row = next(iter(rows))
            device_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            self._selected_device = next((d for d in self._devices if d.device_id == device_id), None)
        self._refresh_containers()

    def _refresh_containers(self) -> None:
        self._containers = []
        if self._selected_device is not None:
            self._containers = sorted(Path(self._selected_device.mount_point).glob(_CONTAINER_GLOB))

        self.container_table.setRowCount(0)
        for path in self._containers:
            row = self.container_table.rowCount()
            self.container_table.insertRow(row)
            item = QTableWidgetItem(path.name)
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            self.container_table.setItem(row, 0, item)

        self._selected_container = None
        self._update_view_button_state()

    def _on_container_selected(self) -> None:
        rows = {index.row() for index in self.container_table.selectedIndexes()}
        if len(rows) != 1:
            self._selected_container = None
        else:
            row = next(iter(rows))
            self._selected_container = Path(self.container_table.item(row, 0).data(Qt.ItemDataRole.UserRole))
        self._update_view_button_state()

    def _update_view_button_state(self) -> None:
        self.view_button.setEnabled(
            self._selected_container is not None and self._key_wrapper is not None
        )

    # -- Private key loading -------------------------------------------------

    def _on_choose_key_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Private Key File", "", "PEM Files (*.pem)")
        if path:
            self.key_path_label.setText(path)

    def _on_load_key_clicked(self) -> None:
        path_text = self.key_path_label.text()
        if not path_text or path_text == "No private key loaded.":
            self._show_status("Choose a private key file first.", ok=False)
            return

        try:
            private_pem = Path(path_text).read_bytes()
            private_key = rsa_keypair.load_private_key(private_pem, self.passphrase_edit.text().encode("utf-8"))
        except (CryptoError, OSError) as exc:
            self._show_status(f"Failed to load private key: {exc}", ok=False)
            return

        self._key_wrapper = RSAOAEPKeyWrapper(private_key.public_key(), private_key)
        self._show_status("Private key loaded.")
        self._update_view_button_state()

    # -- Viewing --------------------------------------------------------------

    def _on_view_clicked(self) -> None:
        if self._selected_container is None or self._key_wrapper is None:
            return
        if self._session_manager is None or not self._session_manager.is_authenticated:
            logger.warning("Decryption attempted without an authenticated session; refusing.")
            self._show_status("You must be signed in to view a file.", ok=False)
            return
        if self._metadata_repository is None:
            self._show_status("No metadata repository is available in this session.", ok=False)
            return

        owner_id = self._session_manager.current.owner_id
        try:
            file_id, encrypted_bytes = self._storage_service.read_encrypted_file_bytes(self._selected_container)
        except (USBError, OSError) as exc:
            logger.error("Failed to read secure container %s: %s", self._selected_container, exc)
            self._show_status(f"Could not read {self._selected_container.name}: {exc}", ok=False)
            return

        access_service = SecureAccessService(
            self._metadata_repository, usage_tracker=self._usage_tracker, deception_engine=self._deception_engine
        )

        viewer = SecureViewerWidget()
        viewer.setWindowTitle(self._selected_container.name)
        # Keep a strong Python reference for as long as the window is open —
        # a parentless top-level `QWidget` has nothing else keeping its
        # Python wrapper alive once this method returns.
        self._active_viewer = viewer

        def _on_granted(buffer, metadata) -> None:
            content = bytes(buffer)
            viewer.display(content, _sniff_content_type(content))

        with progress_dialog(self, "Validating and decrypting..."):
            outcome = access_service.attempt_access(
                file_id,
                encrypted_bytes,
                self._key_wrapper,
                self._protection_keys,
                _on_granted,
                current_device=self._selected_device,
                current_usb_identifier=(
                    compute_usb_identifier(self._selected_device) if self._selected_device else None
                ),
                current_machine_fingerprint=compute_machine_fingerprint(),
                user=owner_id,
            )

        if not outcome.granted:
            assert outcome.deception is not None
            viewer.display(outcome.deception.content, outcome.deception.mime_type)
            logger.warning(
                "Access attempt for file_id=%s did not pass every check; a deceptive view was shown instead "
                "of a denial (trigger=%s, never surfaced to the user)",
                file_id,
                outcome.deception.trigger.value,
            )

        viewer.show()
        self._show_status(f"Opened {self._selected_container.name} in the secure viewer.")

    # -- Status ------------------------------------------------------------

    def _show_status(self, message: str, ok: bool = True) -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {(_OK_COLOR if ok else _FAIL_COLOR).name()};")
        if ok:
            logger.info(message)
        else:
            logger.warning(message)


def _fallback_protection_keys() -> MetadataProtectionKeys:
    """Standalone fallback so this page still constructs (e.g. in tests
    or without `MainWindow`'s shared services) — useless for reading
    metadata protected under a different key, but never `None`."""
    from metadata.protection import generate_protection_keys

    return generate_protection_keys()
