import sys
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QCheckBox, QFrame, QApplication
)
from PySide6.QtCore import Qt, QSize, Slot, Signal, QObject
from PySide6.QtGui import QFont, QPixmap, QIcon

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.token_store import TokenStore


class LoginWindow(QWidget):
    """Login window for user authentication."""
    
    # Signal emitted when login is successful with user data
    login_successful = Signal(dict)
    
    # Signal emitted when login fails with error message
    login_failed = Signal(str)
    
    def __init__(self, auth_manager: AuthManager, parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        self._token_store = self._auth_manager._token_store
        
        # Set up window
        self.setWindowTitle("ورود به سیستم")
        self.setFixedSize(400, 520)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Apply application font
        font = QFont("Vazirmatn", 11)
        self.setFont(font)
        
        # Setup UI
        self._setup_ui()
        
        # Connect auth manager signals
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the login form UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 60, 40, 60)
        
        # Title
        title_label = QLabel("ورود به سامانه")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Vazirmatn", 24, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle = QLabel("شماره ملی و رمز عبور وارد کنید")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666; margin-bottom: 30px;")
        main_layout.addWidget(subtitle)
        
        # Form layout
        form_layout = QFormLayout()
        form_layout.setHorizontalSpacing(15)
        form_layout.setVerticalSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignRight)  # RTL: labels right-aligned
        
        # Username/National ID field
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("شماره ملی یا نام کاربری")
        self.username_input.setMinimumHeight(40)
        self.username_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form_layout.setWidget(0, QForm.Label, QLabel("شماره ملی / نام کاربری:"))
        form_layout.setWidget(0, QForm.FieldRole, self.username_input)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("رمز عبور")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form_layout.setWidget(1, QForm.Label, QLabel("رمز عبور:"))
        form_layout.setWidget(1, QForm.FieldRole, self.password_input)
        
        # Remember me checkbox
        self.remember_checkbox = QCheckBox("مرا به خاطر بسپار")
        self.remember_checkbox.setChecked(True)  # Default remembered
        self.remember_checkbox.setAlignment(Qt.AlignRight)
        form_layout.setWidget(2, QForm.Label, QWidget())  # Empty label
        form_layout.setWidget(2, QForm.FieldRole, self.remember_checkbox)
        
        main_layout.addLayout(form_layout)
        
        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        divider.setStyleSheet("margin: 20px 0;")
        main_layout.addWidget(divider)
        
        # MFA note (initially hidden)
        self.mfa_note = QLabel()
        self.mfa_note.setAlignment(Qt.AlignCenter)
        self.mfa_note.setStyleSheet("color: #666; font-size: 11px; margin: 10px 0;")
        self.mfa_note.hide()
        main_layout.addWidget(self.mfa_note)
        
        # Login button
        self.login_button = QPushButton("وارد شوید")
        self.login_button.setMinimumHeight(48)
        self.login_button.setMinimumWidth(150)
        self.login_button.setDefault(True)  # Default button (Enter key)
        self.login_button.setStyleSheet("""
            QPushButton {
                font-size: 14pt;
                font-weight: bold;
                background-color: #2D3748;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4A5568;
            }
            QPushButton:pressed {
                background-color: #2D3748;
            }
        """)
        main_layout.addWidget(self.login_button, 0, Qt.AlignCenter)
        
        # Divider
        divider2 = QFrame()
        divider2.setFrameShape(QFrame.HLine)
        divider2.setFrameShadow(QFrame.Sunken)
        divider2.setStyleSheet("margin: 20px 0;")
        main_layout.addWidget(divider2)
        
        # SSO note
        sso_note = QLabel(
            "یا با حسابcompany وارد شوید:\n"
            "<a href='#'> ورود SSO/kerberos</a>"
        )
        sso_note.setAlignment(Qt.AlignCenter)
        sso_note.setOpenExternalLinks(True)
        sso_note.setStyleSheet("color: #666; font-size: 11px; margin: 10px 0;")
        main_layout.addWidget(sso_note)
        
        # Register new user link
        register_link = QLabel(
            '<a href="#">حساب کاربری ندارید؟ ثبت‌نام</a>'
        )
        register_link.setAlignment(Qt.AlignCenter)
        register_link.setOpenExternalLinks(True)
        register_link.setStyleSheet("color: #666; font-size: 11px; margin: 5px 0;")
        main_layout.addWidget(register_link)
        
        # Connect signals
        self.login_button.clicked.connect(self._on_login_clicked)
    
    @Slot()
    def _on_login_clicked(self):
        """Handle login button click."""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            self.login_failed.emit("لطفاً همه فیلدها را پر کنید.")
            return
        
        # Attempt login via auth manager
        self._auth_manager.login({
            "username": username,
            "password": password,
            "remember_me": self.remember_checkbox.isChecked()
        })
    
    @Slot(dict)
    def _handle_login_success(self, user_data: dict):
        """Handle successful login."""
        # Emit signal with user data
        self.login_successful.emit(user_data)
    
    @Slot(str)
    def _handle_login_failed(self, error_message: str):
        """Handle login failure."""
        self.login_failed.emit(error_message)
    
    @Slot(str)
    def _show_mfa_challenge(self, mfa_info: str):
        """Show MFA challenge when required."""
        self.mfa_note.setText(mfa_info)
        self.mfa_note.show()
    
    def keyPressEvent(self, event):
        """Handle keyboard events (Enter to login)."""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Raise:
            self._on_login_clicked()
        super().keyPressEvent(event)