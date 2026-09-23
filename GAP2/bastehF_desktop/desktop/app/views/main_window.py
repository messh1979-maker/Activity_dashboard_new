import sys
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QMenuBar, QStatusBar, QMessageBox, QAction
)
from PySide6.QtCore import Qt, QSize, Slot
from PySide6.QtGui import QIcon, QAction

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus, reset_event_bus
from desktop.app.views.dashboard.dashboard_view import DashboardView


class MainWindow(QMainWindow):
    """Main application window after successful login."""
    
    def __init__(self, user_info: dict, auth_manager: AuthManager, parent: QWidget = None):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = get_event_bus()
        
        # Set up window properties
        self.setWindowTitle(f"سامانه مدیریت اهداف - {user_info.get('display_name', 'کاربر')}")
        self.setMinimumSize(1024, 768)
        self.resize(1400, 900)
        
        # Enable RTL
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Set up UI
        self._setup_menu_bar()
        self._setup_central_widget()
        self._setup_status_bar()
        
        # Connect event bus signals
        self._connect_signals()
        
        # Load dashboard view
        self._load_dashboard()
    
    def _setup_menu_bar(self):
        """Set up the application menubar."""
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)  # Keep consistent across platforms
        
        # Profile menu
        profile_menu = menubar.addMenu("پروفایل")
        
        logout_action = QAction("خروج", self)
        logout_action.setShortcut("Ctrl+Q")
        logout_action.triggered.connect(self._handle_logout)
        profile_menu.addAction(logout_action)
        
        # View menu - theme toggle
        view_menu = menubar.addMenu("نمایش")
        
        # Theme action (simplified - would toggle between dark/light)
        self._theme_action = QAction("تم آفتاب", self)
        self._theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(self._theme_action)
    
    def _setup_central_widget(self):
        """Set up the central widget with the main content area."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # TODO: Add sidebar/navigation here in full implementation
        # For now, we just have the dashboard
        
        self._dashboard_view = None
    
    def _setup_status_bar(self):
        """Set up the status bar."""
        status_bar = self.statusBar()
        status_bar.showMessage("آماده است")
        
        # Show user info on status bar
        user_name = self._user_info.get("display_name", "کاربر")
        status_bar.showMessage(f"کاربر: {user_name}  |  فعال")
    
    def _connect_signals(self):
        """Connect internal signals and slots."""
        # Connect auth manager signals
        self._auth_manager.logout_completed.connect(self._on_logout)
        self._auth_manager.authentication_state_changed.connect(self._on_auth_state_changed)
    
    def _load_dashboard(self):
        """Load the dashboard view as the main content."""
        from desktop.app.views.dashboard.dashboard_view import DashboardView
        
        if self._dashboard_view:
            self.centralWidget().layout().removeWidget(self._dashboard_view)
            self._dashboard_view.deleteLater()
        
        self._dashboard_view = DashboardView(
            user_info=self._user_info,
            auth_manager=self._auth_manager,
            event_bus=self._event_bus
        )
        
        # Set dashboard as central content
        central_layout = self.centralWidget().layout()
        if central_layout is None:
            central_layout = QVBoxLayout(self.centralWidget())
            self.centralWidget().setLayout(central_layout)
        
        central_layout.addWidget(self._dashboard_view)
        central_layout.setStretch(0, 1)
    
    @Slot()
    def _handle_logout(self):
        """Handle logout action."""
        reply = QMessageBox.question(
            self,
            "تأیید خروج",
            " آیا از خروج از سیستم اطمینان دارید؟",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self._auth_manager.logout()
    
    @Slot(bool)
    def _on_auth_state_changed(self, logged_in: bool):
        """Handle authentication state changes."""
        if logged_in:
            self._load_dashboard()
            self.statusBar().showMessage(
                f"کاربر: {self._user_info.get('display_name', 'کاربر')}  |  فعال",
                0
            )
        else:
            # Switch back to login
            self.close()
            # Emit signal to show login window
    
    @Slot()
    def _on_logout(self):
        """Handle completed logout."""
        # Close main window, show login
        self.close()
    
    def _toggle_theme(self):
        """Toggle between light and dark theme."""
        # This would typically switch the QSS stylesheet
        # For now, just show a message
        QMessageBox.information(self, "تم", "تغییر تم در پیاده‌سازی pending")