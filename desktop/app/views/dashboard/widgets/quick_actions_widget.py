import logging
from typing import Dict, List, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLabel, QSizePolicy
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui = QFont

from desktop.app.core.auth_manager import AuthManager


logger = logging.getLogger(__name__)


class QuickActionsWidget(QWidget):
    """Widget with quick action buttons for common tasks."""
    
    # Signal emitted when an action is triggered
    action_triggered = pyqtSignal(str)  # action_id
    
    def __init__(self, auth_manager: AuthManager, config: dict = None, parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        
        # Setup
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Preferred)
        self.setLayoutDirection(Qt.RightToLeft)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)
        
        # Title
        title = QLabel("عملیات سریع")
        title_font = QFont("Vazirmatn", 13, QFont.Bold)
        title.setFont(title_font)
        main_layout.addWidget(title)
        
        # Action buttons grid
        self._create_action_buttons(main_layout)
        
        # Connect auth manager signals
        self._connect_signals()
    
    def _create_action_buttons(self, parent_layout: QVBoxLayout):
        """Create the action buttons layout."""
        # buttons_frame = QFrame()
        # buttons_frame.setLayout(QGridLayout())
        # buttons_frame.layout().setHorizontalSpacing(10)
        # buttons_frame.layout().setVerticalSpacing(10)
        
        # Define quick actions available
        actions = [
            ("dashboard", "داشبورد"),
            ("goals", "اهداف"),
            ("calendar", "تقویم"),
            ("inbox", "کارتابل"),
            ("reports", "گزارش‌ها"),
        ]
        
        # Create button group
        button_group = QWidget()
        button_layout = QGridLayout(button_group)
        button_layout.setHorizontalSpacing(10)
        button_layout.setVerticalSpacing(10)
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        for idx, (action_id, label_text) in enumerate(actions):
            btn = QPushButton(label_text)
            btn.setFixedSize(80, 35)
            btn.setFont(QFont("Vazirmatn", 10))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #EDF2F7;
                    border: 1px solid #CBD5E0;
                    border-radius: 6px;
                    font-family: 'Vazirmatn';
                    font-size: 10pt;
                }
                QPushButton:hover {
                    background-color: #EDF2F7;
                    border-color: #A0AEC0;
                }
                QPushButton:pressed {
                    background-color: #EDF2F7;
                    border-color: #718096;
                }
                QPushButton:default {
                    border: 2px solid #4299E1;
                }
            """)
            btn.clicked.connect(lambda checked, aid=action_id: self._on_action_triggered(aid))
            row = idx // 3
            col = idx % 3
            button_layout.addWidget(btn, row, col)
        
        main_layout.addWidget(button_group)
    
    @pyqtSlot(str)
    def _on_action_triggered(self, action_id: str):
        """Handle action button click."""
        self.action_triggered.emit(action_id)
    
    def _connect_signals(self):
        """Connect signals."""
        pass