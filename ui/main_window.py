"""Main application window: wires the navigation sidebar to a page stack.

Also the composition root that hands every page the shared, persisted
dependencies the integrated workflow needs to connect the write side
(`DevicePage`) to the read side (`DecryptionPage`) — the same
`MetadataRepository`/`MetadataProtectionKeys` (so a file written by one
page can actually be validated and read back by the other) and the
same `UsageTracker` (so both sides append to one tamper-evident log).
See `app.protection_keys` for where the persisted keys come from.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QStackedWidget, QWidget

from app.config import ConfigManager
from app.protection_keys import load_or_create_metadata_protection_keys, load_or_create_tracking_protection_keys
from core.constants import APP_NAME, APP_VERSION
from core.logger import get_logger
from crypto.secure_cleanup import CleanupReason, cleanup
from database.db_manager import DatabaseManager
from deception.event_repository import DeceptionEventRepository
from metadata.protection import MetadataProtectionKeys
from metadata.repository import MetadataRepository
from security.account_repository import AccountRepository
from security.auth_controller import AuthController
from security.auth_session import SessionManager
from tracking.repository import TrackingRepository
from tracking.tracking_service import UsageTracker
from ui.navigation.navigation_panel import DEFAULT_NAV_ITEMS, NavigationPanel
from ui.pages.dashboard_page import DashboardPage
from ui.pages.deception_page import DeceptionPage
from ui.pages.decryption_page import DecryptionPage
from ui.pages.device_page import DevicePage
from ui.pages.encryption_page import EncryptionPage
from ui.pages.metadata_page import MetadataPage
from ui.pages.security_page import SecurityPage
from ui.pages.settings_page import SettingsPage
from ui.pages.tracking_page import TrackingPage
from ui.theme.theme_manager import ThemeManager

logger = get_logger(__name__)


class MainWindow(QMainWindow):
    def __init__(
        self,
        config_manager: ConfigManager,
        theme_manager: ThemeManager,
        db_manager: Optional[DatabaseManager] = None,
        session_manager: Optional[SessionManager] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._config_manager = config_manager
        self._theme_manager = theme_manager
        self.db_manager = db_manager
        self.session_manager = session_manager

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(960, 600)
        self.resize(config_manager.config.window_width, config_manager.config.window_height)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setCentralWidget(central)

        self.navigation = NavigationPanel(DEFAULT_NAV_ITEMS)
        layout.addWidget(self.navigation)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        services = self._build_shared_services()
        metadata_repository, protection_keys, usage_tracker, account_repository, deception_event_repository = services

        current_session = self.session_manager.current if self.session_manager else None
        current_owner_id = current_session.owner_id if current_session else None
        auth_controller = AuthController(account_repository) if account_repository is not None else None

        self.settings_page = SettingsPage(
            current_theme=theme_manager.current_theme,
            auth_controller=auth_controller,
            owner_id=current_owner_id,
        )
        self.settings_page.theme_changed.connect(self._on_theme_changed)

        self._pages = {
            "dashboard": DashboardPage(),
            "encryption": EncryptionPage(),
            "decryption": DecryptionPage(
                metadata_repository=metadata_repository,
                protection_keys=protection_keys,
                session_manager=self.session_manager,
                usage_tracker=usage_tracker,
                deception_event_repository=deception_event_repository,
            ),
            "devices": DevicePage(
                metadata_repository=metadata_repository,
                protection_keys=protection_keys,
                session_manager=self.session_manager,
            ),
            "metadata": MetadataPage(metadata_repository=metadata_repository, protection_keys=protection_keys),
            "security": SecurityPage(account_repository=account_repository),
            "deception": DeceptionPage(event_repository=deception_event_repository),
            "tracking": TrackingPage(usage_tracker=usage_tracker),
            "settings": self.settings_page,
        }
        self._page_index: dict[str, int] = {}
        for item in DEFAULT_NAV_ITEMS:
            widget = self._pages[item.page_id]
            self._page_index[item.page_id] = self.stack.addWidget(widget)

        self.navigation.page_selected.connect(self._navigate_to)

        self._build_menu_bar()
        self.statusBar().showMessage("Ready")

        last_page = config_manager.config.last_page
        if last_page not in self._page_index:
            last_page = "dashboard"
        self.navigation.set_active(last_page)
        self._navigate_to(last_page)

    def _build_shared_services(
        self,
    ) -> tuple[
        Optional[MetadataRepository],
        Optional[MetadataProtectionKeys],
        Optional[UsageTracker],
        Optional[AccountRepository],
        Optional[DeceptionEventRepository],
    ]:
        """Build the shared, persisted services every page that touches
        protected data must share, backed by `self.db_manager`: the
        `MetadataRepository`/`MetadataProtectionKeys` and `UsageTracker`
        the write/read pages already shared (Phase 14), plus the
        `AccountRepository` and `DeceptionEventRepository` the read-only
        Access Security / Deception Module dashboards need (Phase 16).
        Returns all-`None` when no `db_manager` was supplied (e.g. a test
        constructing a bare `MainWindow`) — every page tolerates that by
        falling back to its own standalone, non-persisted defaults.
        """
        if self.db_manager is None:
            return None, None, None, None, None

        metadata_repository = MetadataRepository(self.db_manager.connect())
        protection_keys = load_or_create_metadata_protection_keys(self.db_manager)
        tracking_repository = TrackingRepository(self.db_manager.connect())
        tracking_keys = load_or_create_tracking_protection_keys(self.db_manager)
        usage_tracker = UsageTracker(tracking_keys, tracking_repository)
        account_repository = AccountRepository(self.db_manager.connect())
        deception_event_repository = DeceptionEventRepository(self.db_manager.connect())
        return (
            metadata_repository,
            protection_keys,
            usage_tracker,
            account_repository,
            deception_event_repository,
        )

    def _build_menu_bar(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")
        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menu_bar.addMenu("&View")
        toggle_theme_action = QAction("Toggle &Theme", self)
        toggle_theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(toggle_theme_action)

    def _navigate_to(self, page_id: str) -> None:
        index = self._page_index.get(page_id)
        if index is None:
            logger.warning("Unknown page id requested: %s", page_id)
            return
        self.stack.setCurrentIndex(index)
        self.navigation.set_active(page_id)
        self._config_manager.update(last_page=page_id)

    def _toggle_theme(self) -> None:
        new_theme = self._theme_manager.toggle()
        self.settings_page.set_theme(new_theme)
        self._config_manager.update(theme=new_theme)

    def _on_theme_changed(self, theme: str) -> None:
        self._theme_manager.apply(theme)
        self._config_manager.update(theme=theme)

    def closeEvent(self, event) -> None:
        self._config_manager.update(
            window_width=self.width(),
            window_height=self.height(),
        )
        self._perform_exit_cleanup()
        super().closeEvent(event)

    def _perform_exit_cleanup(self) -> None:
        """Drop the authenticated session (the in-memory "Session Key")
        and run the guaranteed application-exit secure cleanup pass.
        `session_manager` is only present once `app.main.bootstrap` has
        attached it (see that module's docstring); tests that construct
        a bare `MainWindow` are unaffected.
        """
        session_manager = getattr(self, "session_manager", None)
        if session_manager is not None:
            session_manager.clear()
        cleanup(CleanupReason.APPLICATION_EXIT)
