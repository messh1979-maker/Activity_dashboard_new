import logging
from typing import Dict, List, Optional, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QProgressBar, QLabel, QPushButton, QGridLayout
)
from PySide6.QtCore import Qt, QSize, pyqtSignal, pyqtSlot
from PySide6.QtGui = QFont, QColor

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus


logger = logging.getLogger(__name__)


class GoalsProgressWidget(QWidget):
    """Widget showing user's goals progress with privacy-aware display.
    
    Displays goals owned by the user or shared with them,
    respecting privacy settings (team_only, fully_private, etc.).
    """
    
    def __init__(self, user_info: dict, auth_manager: AuthManager,
                 config: dict = None, parent: QWidget = None):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = get_event_bus()
        
        # Setup UI
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Preferred)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        # Header
        self._create_header(main_layout)
        
        # Progress area
        self._create_progress_area(main_layout)
        
        # Connect signals
        self._connect_signals()
    
    def _create_header(self, parent_layout: QVBoxLayout):
        """Create the widget header with title and add goal button."""
        header_layout = QHBoxLayout()
        header_layout.setSpacing(10)
        
        title = QLabel("پیشرفت اهداف من")
        title_font = QFont("Vazirmatn", 13, QFont.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #1A202C;")
        
        # Add goal button (simplified - would open dialog)
        add_button = QPushButton("+ افزودن هدف")
        add_button.setFixedHeight(28)
        add_button.setStyleSheet("""
            QPushButton {
                background-color: #48BB78;
                color: white;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #38A569;
            }
        """)
        add_button.clicked.connect(self._add_goal_placeholder)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(add_button)
        
        parent_layout.addLayout(header_layout)
    
    def _create_progress_area(self, parent_layout: QVBoxLayout):
        """Create the progress display area."""
        # Overall progress bar
        self.overall_progress = QProgressBar()
        self.overall_progress.setFixedHeight(8)
        self.overall_progress.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #EDF2F7;
                border-radius: 4px;
                margin: 4px 0;
            }
            QProgressBar::chunk {
                background-color: #48BB78;
                border-radius: 4px;
            }
        """)
        
        # Goal count label
        self.goal_count_label = QLabel("0 اهداف")
        self.goal_count_label.setStyleSheet("""
           QLabel {
                font-size: 12px;
                color: #787878;
            }
        """)
        
        # Individual goals container (simplified - would show cards)
        self.goals_container = QWidget()
        self.goals_layout = QVBoxLayout(self.goals_container)
        self.goals_layout.setContentsMargins(0, 0, 0, 0)
        self.goals_layout.setSpacing(8)
        
        # Add widgets to main layout
        parent_layout.addWidget(self.overall_progress)
        parent_layout.addWidget(self.goal_count_label)
        parent_layout.addWidget(self.goals_container, 1)  # Stretch
    
    @pyqtSlot(dict)
    def update_goals(self, goals_data: dict):
        """Update the widget with goals data from the API.
        
        Args:
            goals_data: Dict with goals information from the server.
        """
        try:
            goals = goals_data.get("goals", [])
            total_progress = goals_data.get("total_progress", 0)
            completed_count = goals_data.get("completed_count", 0)
            
            # Update overall progress bar
            self.overall_progress.setValue(int(total_progress))
            
            # Update goal count
            total = len(goals)
            self.goal_count_label.setText(f"{total} هدف")
            
            # Clear existing goal cards
            while self.goals_layout.count():
                item = self.goals_layout.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()
            
            # Create goal cards for each goal
            for goal in goals:
                card = self._create_goal_card(goal)
                self.goals_layout.addWidget(card)
            
        except Exception as e:
            logger.error(f"Error updating goals widget: {e}")
    
    def _create_goal_card(self, goal: dict) -> QWidget:
        """Create a single goal progress card."""
        card = QFrame()
        card.setFrameStyle(QFrame.StyledPanel)
        card.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 8px;
                margin: 4px;
                min-height: 60px;
            }
        """)
        
        card_layout = QHBoxLayout(card)
        card_layout.setContentsMargins(12, 8, 12, 8)
        card_layout.setSpacing(10)
        
        # Goal title (truncated)
        title_label = QLabel(goal.get("title", "هدف بدون عنوان")[:40])
        title_label.setFont(QFont("Vazirmatn", 11))
        title_label.setWordWrap(True)
        title_label.setMaximumWidth(200)
        
        # Progress bar
        progress = goal.get("progress_pct", 0)
        progress_bar = QProgressBar()
        progress_bar.setFixedHeight(8)
        progress_bar.setFixedWidth(100)
        progress_bar.setValue(int(progress))
        progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #EDF2F7;
                border-radius: 4px;
                min-width: 100px;
            }
            QProgressBar::chunk {
                background-color: #48BB78;
                border-radius: 4px;
            }
        """)
        
        # Progress percentage
        pct_label = QLabel(f"{progress}%")
        pct_label.setFont(QFont("Vazirmatn", 11))
        pct_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        
        card_layout.addWidget(title_label)
        card_layout.addStretch()
        card_layout.addWidget(progress_bar)
        card_layout.addWidget(pct_label)
        
        return card
    
    def _add_goal_placeholder(self):
        """Placeholder for adding a new goal."""
        # In full implementation, would open dialog
        pass
    
    def _connect_signals(self):
        """Connect relevant signals."""
        # Connect to event bus for goal changes
        # e.g., goal_completed -> update this widget
        pass
    
    def get_progress_value(self) -> int:
        """Return the overall progress percentage."""
        return self.overall_progress.value()