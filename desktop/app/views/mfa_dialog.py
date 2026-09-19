import sys
from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QDialogButtonBox, QProgressBar, QWidget
)
from PySide6.QtCore import Qt, Qt, QTimer, Slot, Signal
from PySide6.QtGui import QFont

from desktop.app.core.auth_manager import AuthManager


class MfaDialog(QDialog):
    """MFA (Multi-Factor Authentication) challenge dialog."""
    
    def __init__(self, auth_manager: AuthManager, mfa_method: str,
                 parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        self._mfa_method = mfa_method
        
        # Set up dialog
        self.setWindowTitle("اعتبارسنجی امنیتی")
        self.setFixedSize(400, 220)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Apply font
        font = QFont("Vazirmatn", 11)
        self.setFont(font)
        
        self._setup_ui()
        self._setup_mfa_specific_ui()
    
    def _setup_ui(self):
        """Set up the basic dialog UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 60, 40, 60)
        
        # Title
        title = QLabel("اعتبارسنجی امنیتی")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Vazirmatn", 18, QFont.Bold)
        title.setFont(title_font)
        main_layout.addWidget(title)
        
        # Description
        if self._mfa_method == "totp":
            desc = QLabel(
                "برای ادامه ورود، کد MFA خود را وارد کنید.\n"
                "می‌توانید از تطبيق authenticator استفاده کنید."
            )
        elif self._mfa_method == "sms":
            desc = QLabel(
                "کد MFA به شماره موبایل شما ارسال شده است."
            )
        else:  # email
            desc = QLabel(
                "کد MFA به ایمیل شما ارسال شده است."
            )
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        main_layout.addWidget(desc)
        
        # Code input
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("کد MFA را وارد کنید")
        self.code_input.setEchoMode(QLineEdit.Password)
        self.code_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.code_input.setMinimumHeight(45)
        main_layout.addWidget(self.code_input)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.setAlignment(Qt.AlignCenter)
        button_box.accepted.connect(self._on_accepted)
        button_box.rejected.connect(self.reject)
        
        # Set button text
        ok_button = button_box.button(QDialogButtonBox.Ok)
        if ok_button:
            ok_button.setText("اعتبارسنجی")
        
        main_layout.addWidget(button_box)
        
        # Set focus to code input
        self.code_input.setFocus()
        self.code_input.selectAll()
        
        # Connect signals
        self.code_input.returnPressed.connect(self._on_accepted)
    
    def _setup_mfa_specific_ui(self):
        """Method-specific setup (can be overridden)."""
        pass
    
    @Slot()
    def _on_accepted(self):
        """Handle OK button press."""
        code = self.code_input.text().strip()
        if not code:
            QMessageBox.warning(self, "هشدار", "لطفاً کد MFA را وارد کنید.")
            return
        
        # Verify MFA via auth manager
        self._auth_manager.verify_mfa(code, self._mfa_method)
    
    def set_code(self, code: str):
        """Pre-fill the code (for testing or auto-fill)."""
        self.code_input.setText(code)
        self.code_input.setSelection(0, len(code))