import logging
from typing import Dict, List, Optional, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt, QSize, QTimer, Slot, QPropertyAnimation, QEasingCurve
from PySide6.QtGui = QColor

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus
from desktop.app.core.permissions import PermissionCache
from desktop.app.widgets.clock_widget import ClockWidget
from desktop.app.widgets.tag_chip import TagChip


logger = logging.getLogger(__name__)


class DashboardView(QWidget):
    """Main dashboard view showing personalized widgets and goals progress."""
    
    def __init__(
        self,
        user_info: dict,
        auth_manager: AuthManager,
        event_bus: Optional[Any] = None,
        parent: QWidget = None
    ):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = event_bus or get_event_bus()
        
        # Initialize permission cache
        self._permission_cache = PermissionCache(
            user_id=str(user_info.get("id", "")),
            api_client=self._auth_manager._api_client if hasattr(self._auth_manager, '_api_client') else None,
            token_store=self._auth_manager._token_store
        )
        
        # Dashboard state
        self._widgets: Dict[str, QWidget] = {}
        self._layout_config: Optional[dict] = None
        self._is_rtl = True
        
        # Set up UI
        self.setLayoutDirection(Qt.RightToLeft)
        self._setup_ui()
        
        # Load user-specific dashboard configuration
        self._load_dashboard_config()
        
        # Connect signals
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the dashboard user interface."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header bar
        self._create_header(main_layout)
        
        # Main content area - grid layout for widgets
        self._widget_area = QWidget()
        self._widget_area.setLayout(QGridLayout())
        self._widget_area.layout().setHorizontalSpacing(10)
        self._widget_area.layout().setVerticalSpacing(10)
        self._widget_area.layout().setContentsMargins(10, 10, 10, 10)
        
        main_layout.addWidget(self._widget_area, 1)  # Stretch factor 1
        
        # Initialize default dashboard
        self._reload_widgets()
    
    def _create_header(self, parent_layout: QVBoxLayout):
        """Create the dashboard header with user info and settings."""
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet("""
            QWidget {
                background-color: #F7F9FA;
                border-bottom: 1px solid #E2E8F0;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(15, 0, 15, 0)
        header_layout.setSpacing(15)
        
        # User avatar/profile
        user_name = QLabel(self._user_info.get("display_name", "کاربر"))
        user_name.setFont(QFont("Vazirmatn", 14, QFont.Bold))
        user_name.setStyleSheet("color: #1A202C;")
        
        # Simple avatar placeholder
        avatar_label = QLabel("ا")
        avatar_label.setFixedSize(40, 40)
        avatar_label.setAlignment(Qt.AlignCenter)
        avatar_label.setStyleSheet("""
            QLabel {
                background-color: #EDF2F7;
                border-radius: 20px;
                font-weight: bold;
                color: #4A5568;
            }
        """)
        
        header_layout.addWidget(avatar_label)
        header_layout.addWidget(user_name)
        header_layout.addStretch()
        
        # Notifications indicator (simplified)
        notif_indicator = QLabel("✉")
        notif_indicator.setStyleSheet("""
            QLabel {
                background-color: #EDF2F7;
                border: 2px solid #ED8936;
                border-radius: 10px;
                min-width: 20px;
                min-height: 20px;
            }
        """)
        notif_indicator.setFixedSize(24, 24)
        
        header_layout.addWidget(notif_indicator)
        
        parent_layout.addWidget(header)
    
    def _load_dashboard_config(self):
        """Load dashboard layout configuration for the user."""
        # In a full implementation, this would fetch from API
        # For now, use a default configuration
        self._layout_config = {
            "blocks": [
                {"key": "clock", "x": 0, "y": 0, "w": 2, "h": 2, "config": {}},
                {"key": "goals_progress", "x": 2, "y": 0, "w": 6, "h": 4, "config": {}},
                {"key": "quick_actions", "x": 8, "y": 0, "w": 4, "h": 3, "config": {}},
                {"key": "recent_activity", "x": 0, "y": 4, "w": 12, "h": 3, "config": {}},
            ]
        }
    
    def _reload_widgets(self):
        """Reload widgets based on configuration."""
        # Clear existing widgets
        self._clear_widgets()
        
        if not self._layout_config:
            return
        
        config = self._layout_config.get("blocks", [])
        grid = self._widget_area.layout()
        
        for block_config in config:
            self._add_widget_block(block_config, grid)
    
    def _clear_widgets(self):
        """Remove all widgets from the grid."""
        grid = self._widget_area.layout()
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        
        self._widgets.clear()
    
    def _add_widget_block(self, config: dict, grid_layout):
        """Add a widget block to the dashboard grid."""
        block_key = config.get("key", "clock")
        position_x = config.get("x", 0)
        position_y = config.get("y", 0)
        width = config.get("w", 4)
        height = config.get("h", 4)
        block_config = config.get("config", {})
        
        # Create widget based on key
        widget = self._create_widget(block_key, block_config)
        if widget is None:
            return
        
        # Set widget size in grid (grid is 12 columns max)
        grid_layout.addWidget(widget, position_y, position_x, height, width)
        
        # Store reference
        self._widgets[block_key] = widget
    
    def _create_widget(self, block_key: str, config: dict) -> Optional[QWidget]:
        """Factory method to create widget instances."""
        from desktop.app.widgets.clock_widget import ClockWidget
        from desktop.app.widgets.tag_chip import TagChip
        
        if block_key == "clock":
            return ClockWidget(
                cfg=config.get("cfg", {
                    "show_jalali": True,
                    "show_gregorian": True,
                    "show_seconds": True,
                    "opacity": 0.95
                }),
                style=config.get("style", {
                    "bg": "#1A202C",
                    "fg": "#EDF2F7",
                    "font_family": "Vazirmatn",
                    "font_size": 14,
                    "opacity": 0.95
                })
            )
        elif block_key == "goals_progress":
            from desktop.app.views.dashboard.goals_widget import GoalsProgressWidget
            return GoalsProgressWidget(
                user_info=self._user_info,
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "quick_actions":
            from desktop.app.widgets.quick_actions import QuickActionsWidget
            return QuickActionsWidget(
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "recent_activity":
            from desktop.app.widgets.recent_activity import RecentActivityWidget
            return RecentActivityWidget(
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "tags":
            from desktop.app.widgets.tag_cloud import TagCloudWidget
            return TagCloudWidget(
                config=config
            )
        
        # Default: clock widget
        return ClockWidget(
            cfg=config.get("cfg", {
                "show_jalali": True,
                "show_gregorian": True,
                "show_seconds": True,
                "opacity": 0.95
            }),
            style=config.get("style", {
                "bg": "#1A202C",
                "fg": "#EDF2F7",
                "font_family": "Vazirmatn",
                "font_size": 14,
                "opacity": 0.95
            })
        )
    
    def _connect_signals(self):
        """Connect event bus and other signals."""
        # Connect to event bus for dashboard updates
        # e.g., goal completed -> update progress widget
        pass
    
    def update_widget(self, widget_key: str, data: dict):
        """Update a specific widget with new data."""
        if widget_key in self._widgets:
            widget = self._widgets[widget_key]
            # Dispatch update based on widget type
            if hasattr(widget, 'update_data'):
                widget.update_data(data)