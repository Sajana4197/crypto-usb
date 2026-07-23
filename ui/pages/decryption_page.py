"""Decryption page: the read side of the Secure Storage Layer.

Mirrors `ui.pages.encryption_page.EncryptionPage`'s completeness on the
write side: detects a USB device, lists the `.cusc` secure containers on it,
loads the file-wrapping private key the user exported when the file
was written, and hands everything to
`usb.secure_access_service.SecureAccessService` — which runs every
access-time check (Validation), decrypts strictly in RAM (RAM
Decryption), burns a one-time-access file immediately after its single
legitimate view and then deletes its `.cusc` file from the device
(One-Time Access — this page always passes `container_path`, so a
consumed file is both cryptographically dead and physically gone, not
just crypto-shredded in place), and records the attempt in the
tamper-evident usage log (Usage Tracking).

Whatever `SecureAccessService.attempt_access` hands back — the real
plaintext, or the Deception Engine's fabricated stand-in — is rendered
identically through `viewer.secure_viewer_widget.SecureViewerWidget`.
This is deliberate, not an oversight: the Deception Engine's entire
purpose is to be indistinguishable from a genuine denial-free view, so
this page never brands one outcome as "denied" and the other as
"granted" anywhere the user (or an attacker) can see. Only the log
(`core.logger`) ever records which one actually happened.

The device table refreshes itself automatically on a timer (as well as
via the "Refresh Devices" button) so a device plugged in or removed
while this page is open shows up without the user having to ask for
it. A refresh is a no-op — it never rebuilds the table or disturbs the
current selection — whenever the detected device set hasn't actually
changed since the last check.

Before falling back to `metadata_repository` (this machine's local
SQLite copy), a view attempt first checks whether the selected `.cusc`
container itself has an embedded portable-metadata section (see
`ui.pages.encryption_page.EncryptionPage`/`usb.secure_storage_service`,
which write it, and `usb.secure_container.SecureContainer`, which
carries it). If present, this file's protection keys are re-derived
from the just-loaded private key + its passphrase + that section's own
stored salt (`metadata.protection.derive_protection_keys_from_key_material`)
and validation/decryption proceeds entirely against that USB-resident
copy — in RAM, never touching or requiring the local database at all.
This is what lets a file written on one machine be opened on a
completely different one that has never seen its `metadata_repository`,
given only the single `.cusc` file and the correct private key +
passphrase.

A file written and read back on the *same* machine typically has both
copies at once: the local `metadata_repository` record `EncryptionPage`
always saves, and the container's own embedded portable section this
page then prefers. For a one-time-access file, burning only the copy
actually validated against would leave the other one looking untouched
— see `usb.secure_access_service.SecureAccessService`'s
`mirror_repositories`, which this page supplies whenever both copies
genuinely exist for the file being viewed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer
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
from deception.triggers import DeceptionTrigger
from metadata.portable_repository import PortableMetadataRepository
from metadata.protection import MetadataProtectionKeys, derive_protection_keys_from_key_material
from metadata.repository import MetadataRepository
from security.auth_session import SessionManager
from tracking.tracking_service import UsageTracker
from ui.pages.base_page import BasePage
from ui.widgets.busy import progress_dialog, show_info_popup, show_result_popup
from usb.device_detector import USBDevice, USBDeviceDetector
from usb.exceptions import USBError
from usb.secure_access_service import SecureAccessService
from usb.secure_storage_service import SecureStorageService
from usb.storage_writer import SecureStorageWriter
from validation.machine_fingerprint import compute_machine_fingerprint
from validation.usb_identifier import compute_usb_identifier
from viewer.secure_viewer_widget import SecureViewerWidget

logger = get_logger(__name__)

_OK_COLOR = QColor("#3ecf8e")
_FAIL_COLOR = QColor("#e5484d")

_DEVICE_COLUMN_TITLES = ("Mount", "Label", "Filesystem", "Free Space", "Removable")
_CONTAINER_GLOB = "*.cusc"

# How often the device table polls for plugged-in/removed devices without
# any user action. Frequent enough to feel "automatic" during a demo,
# infrequent enough that the background psutil calls are never noticeable.
_DEVICE_POLL_INTERVAL_MS = 2000


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
        self._portable_writer = SecureStorageWriter()
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
        # The passphrase used to load `_key_wrapper`'s private key —
        # cached alongside it (real or fabricated, see
        # `_on_load_key_clicked`) so a view attempt can re-derive a
        # file's portable metadata keys (see
        # `_load_portable_metadata_source`) without asking the user
        # again. A fabricated key/passphrase pair re-derives to the
        # wrong protection keys there, which fails
        # `MetadataProtector.unprotect`'s own HMAC check exactly like
        # tampered metadata would — no separate flag is needed to route
        # it through the Deception Engine. Cleared together with
        # `_key_wrapper` when the viewer closes.
        self._loaded_key_passphrase: bytes | None = None
        self._active_viewer: Optional[SecureViewerWidget] = None

        self.add_widget(self._build_device_toolbar())
        self.add_widget(self._build_device_table())
        self.add_widget(self._build_key_panel())
        self.add_widget(self._build_container_panel())
        self.add_widget(self._build_status_label())

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
        self.passphrase_edit.setMaximumWidth(320)
        layout.addWidget(self.passphrase_edit)

        self.load_key_button = QPushButton("Load Key")
        self.load_key_button.clicked.connect(self._on_load_key_clicked)
        self.load_key_button.setMaximumWidth(180)
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
        self.container_table.setMaximumHeight(220)
        self.container_table.itemSelectionChanged.connect(self._on_container_selected)
        layout.addWidget(self.container_table)

        layout.addSpacing(10)

        self.view_button = QPushButton("View Selected File")
        self.view_button.setObjectName("primaryButton")
        self.view_button.setEnabled(False)
        self.view_button.clicked.connect(self._on_view_clicked)
        self.view_button.setMaximumWidth(220)
        layout.addWidget(self.view_button)

        return panel

    def _build_status_label(self) -> QWidget:
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("dropHint")
        return self.status_label

    # -- Device & container listing ---------------------------------------

    def _refresh_devices(self) -> None:
        devices = self._detector.detect_devices()
        if devices == self._devices:
            # Nothing actually changed (same devices, same free space) —
            # skip the rebuild so a background poll never disturbs the
            # current selection or scroll position.
            return

        previously_selected_id = self._selected_device.device_id if self._selected_device else None
        self._devices = devices
        self.table.setRowCount(0)
        for device in self._devices:
            self._append_device_row(device)
        count = len(self._devices)
        self.device_summary_label.setText(
            "No removable devices detected" if count == 0 else f"{count} device(s) detected"
        )
        self._selected_device = None
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
        containers = []
        if self._selected_device is not None:
            containers = sorted(Path(self._selected_device.mount_point).glob(_CONTAINER_GLOB))

        if containers == self._containers:
            # Nothing actually changed — skip the rebuild so a background
            # poll (see the module docstring) never disturbs the file the
            # user currently has selected in this table.
            return

        previously_selected_path = self._selected_container
        self._containers = containers

        self.container_table.setRowCount(0)
        for path in self._containers:
            row = self.container_table.rowCount()
            self.container_table.insertRow(row)
            item = QTableWidgetItem(path.name)
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            self.container_table.setItem(row, 0, item)

        self._selected_container = None
        self._update_view_button_state()

        if previously_selected_path is not None:
            for row, path in enumerate(self._containers):
                if path == previously_selected_path:
                    self.container_table.selectRow(row)
                    break

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

        passphrase_text = self.passphrase_edit.text()
        try:
            private_pem = Path(path_text).read_bytes()
            private_key = rsa_keypair.load_private_key(private_pem, passphrase_text.encode("utf-8"))
        except (CryptoError, OSError) as exc:
            # Matching the proposal's Deceptive Protection Mechanism (see
            # security.auth_controller.authenticate_private_key): a wrong
            # key file or passphrase must never be reported as an error —
            # that would confirm to an attacker that they guessed wrong.
            # Instead, fabricate a decoy key pair that "loads" with the
            # same inline status text as a real one (just without the
            # "Success"-titled popup a real load gets). Nothing has to
            # force a later view attempt into deception on this key's
            # behalf: it's cryptographically unrelated to whatever the
            # user actually meant to load, so it fails on its own when
            # used for real — either `MetadataProtector.unprotect`'s HMAC
            # check (a container's embedded portable section re-derives
            # the wrong protection keys from this key + passphrase, see
            # `_load_portable_metadata_source`) or the real decrypt
            # attempt itself (`RSAOAEPKeyWrapper.unwrap` can't recover a
            # FEK it never wrapped) — both already routed to the
            # Deception Engine by `usb.secure_access_service`.
            logger.warning("Private key load failed (%s); activating deception instead of reporting an error", exc)
            self._deception_engine.activate(DeceptionTrigger.WRONG_CREDENTIALS)
            decoy_keypair = rsa_keypair.generate_rsa_keypair()
            self._key_wrapper = RSAOAEPKeyWrapper(decoy_keypair.public_key, decoy_keypair.private_key)
            self._loaded_key_passphrase = passphrase_text.encode("utf-8")
            self._show_status("Private key loaded.")
            show_info_popup(self, "Private key loaded.")
            self._update_view_button_state()
            return

        self._key_wrapper = RSAOAEPKeyWrapper(private_key.public_key(), private_key)
        self._loaded_key_passphrase = passphrase_text.encode("utf-8")
        self._show_status("Private key loaded.")
        show_result_popup(self, "Private key loaded.", ok=True)
        self._update_view_button_state()

    # -- Viewing --------------------------------------------------------------

    def _load_portable_metadata_source(
        self, container_path: Path, key_wrapper: RSAOAEPKeyWrapper
    ) -> Optional[tuple[PortableMetadataRepository, MetadataProtectionKeys]]:
        """If `container_path`'s `.cusc` file has an embedded portable
        metadata section (see the module docstring), derive this file's
        protection keys from the loaded private key + its passphrase +
        the section's own stored salt — entirely in RAM. The returned
        repository is a drop-in for `self._metadata_repository`, so
        validation, decryption, and one-time-access burning all work
        exactly as they do against the local database, but only ever
        touch this one container file.

        Returns None (the caller falls back to the local repository) if
        the container has no portable-metadata section, or the loaded
        key/passphrase aren't usable to derive from — `getattr` rather
        than a direct `.private_key` access since some tests stub
        `_key_wrapper` with a bare sentinel object once
        `SecureAccessService` itself is mocked out, same as a missing
        private key: nothing to derive from.
        """
        private_key = getattr(key_wrapper, "private_key", None)
        if private_key is None or self._loaded_key_passphrase is None:
            return None

        try:
            container = self._portable_writer.read_container(container_path)
        except (USBError, OSError) as exc:
            logger.warning(
                "Container at %s could not be read for portable metadata, falling back to the local "
                "repository: %s",
                container_path,
                exc,
            )
            return None

        if container.portable_metadata is None:
            return None

        material = rsa_keypair.private_key_material(private_key)
        keys = derive_protection_keys_from_key_material(
            material, self._loaded_key_passphrase, container.portable_metadata.salt
        )
        repository = PortableMetadataRepository(container, container_path, writer=self._portable_writer)
        return repository, keys

    def _on_view_clicked(self) -> None:
        if self._selected_container is None or self._key_wrapper is None:
            return
        if self._session_manager is None or not self._session_manager.is_authenticated:
            logger.warning("Decryption attempted without an authenticated session; refusing.")
            self._show_status("You must be signed in to view a file.", ok=False)
            return
        is_decoy = self._session_manager.current.is_decoy

        # Snapshotted into locals rather than re-read from `self.` further
        # down: `progress_dialog` below pumps the Qt event loop (to keep
        # the UI responsive during validation/decryption), which gives the
        # background device-poll timer (see the module docstring) a
        # chance to run and rebuild the device/container tables out from
        # under an in-progress view. `USBDevice`/`Path` are both safe to
        # hold a reference to regardless of what `self._selected_device`/
        # `self._selected_container` become in the meantime.
        selected_container = self._selected_container
        selected_device = self._selected_device
        key_wrapper = self._key_wrapper
        owner_id = self._session_manager.current.owner_id

        # A decoy session (a wrong login password — see
        # security.auth_controller.authenticate_password) always takes
        # the `force_deception` path below, which never touches any
        # metadata source: skip deriving portable keys (a deliberately
        # expensive scrypt call) and re-reading the container for
        # nothing. A bad private key/passphrase is not special-cased
        # here (see `_on_load_key_clicked`) — it runs through the exact
        # same derivation and validation as a genuine key and fails on
        # its own, so it never needs `force_deception`.
        metadata_repository = self._metadata_repository
        protection_keys = self._protection_keys
        used_portable_metadata = False
        if not is_decoy:
            portable_source = self._load_portable_metadata_source(selected_container, key_wrapper)
            if portable_source is not None:
                metadata_repository, protection_keys = portable_source
                used_portable_metadata = True
                logger.info(
                    "Using USB-resident portable metadata for %s — no local database involved",
                    selected_container.name,
                )
        if metadata_repository is None and not is_decoy:
            self._show_status("No metadata repository is available in this session.", ok=False)
            return

        try:
            file_id, encrypted_bytes = self._storage_service.read_encrypted_file_bytes(selected_container)
        except (USBError, OSError) as exc:
            logger.error("Failed to read secure container %s: %s", selected_container, exc)
            self._show_status(f"Could not read {selected_container.name}: {exc}", ok=False)
            return

        # This file has a separate local-database record in addition to the
        # container's own embedded portable section just used above — a
        # one-time-access burn must not leave that other copy looking
        # untouched (see
        # `metadata.one_time_access.OneTimeAccessEnforcer`'s
        # `mirror_repositories`), or it could be legitimately decrypted
        # again through the local copy alone.
        mirror_repositories = []
        if (
            used_portable_metadata
            and self._metadata_repository is not None
            and self._metadata_repository.load(file_id) is not None
        ):
            mirror_repositories.append(self._metadata_repository)

        access_service = SecureAccessService(
            metadata_repository,
            usage_tracker=self._usage_tracker,
            deception_engine=self._deception_engine,
            mirror_repositories=mirror_repositories,
        )

        viewer = SecureViewerWidget()
        viewer.setWindowTitle(selected_container.name)
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
                key_wrapper,
                protection_keys,
                _on_granted,
                current_device=selected_device,
                current_usb_identifier=(
                    compute_usb_identifier(selected_device) if selected_device else None
                ),
                current_machine_fingerprint=compute_machine_fingerprint(),
                user=owner_id,
                force_deception=is_decoy,
                container_path=selected_container,
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
        else:
            # A granted one-time-access view may have just deleted
            # `selected_container` from the device (see `container_path`
            # on `SecureAccessService.attempt_access`) — refresh
            # immediately rather than waiting for the next device-poll
            # tick, so the container table reflects that right away.
            self._refresh_containers()

        # A local flag, not a widget attribute: `_on_capture_detected` and
        # `_on_viewer_closed` are both connected to signals the viewer
        # fires, and their relative firing order is not guaranteed, so
        # the flag is what lets the close handler show the right message
        # regardless of which one runs first.
        capture_state = {"detected": False}

        def _on_capture_detected() -> None:
            capture_state["detected"] = True
            if outcome.on_screen_capture_detected is not None:
                outcome.on_screen_capture_detected()

        def _on_viewer_closed() -> None:
            if capture_state["detected"]:
                self._show_status("Secure viewer closed: a screen capture attempt was detected.", ok=False)
            else:
                self._show_status("Secure viewer closed.")
            # The loaded private key was scoped to this viewing session —
            # require the user to deliberately reload it (and re-confirm
            # its passphrase) before it can be used to view another file,
            # even a different container off the same device.
            self._key_wrapper = None
            self.key_path_label.setText("No private key loaded.")
            self.passphrase_edit.clear()
            self._update_view_button_state()

        viewer.set_screen_capture_handler(_on_capture_detected)
        if outcome.on_view_closed is not None:
            viewer.closed.connect(outcome.on_view_closed)
        viewer.closed.connect(_on_viewer_closed)

        viewer.show()
        self._show_status(f"Opened {selected_container.name} in the secure viewer.")

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


def _fallback_protection_keys() -> MetadataProtectionKeys:
    """Standalone fallback so this page still constructs (e.g. in tests
    or without `MainWindow`'s shared services) — useless for reading
    metadata protected under a different key, but never `None`."""
    from metadata.protection import generate_protection_keys

    return generate_protection_keys()
