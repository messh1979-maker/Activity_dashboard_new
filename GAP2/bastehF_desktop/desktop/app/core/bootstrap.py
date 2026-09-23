import os
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QColor

from desktop.app.core.device_identity import get_device_identity
from desktop.app.core.token_store import TokenStore
from desktop.app.core.auth_manager import AuthManager


def bootstrap() -> QApplication:
    """Initialize the application with fonts, themes, and settings."""
    app = QApplication(sys.argv)

    # --- Font Setup (Vazirmatn for Persian RTL) ---
    fonts_dir = Path(__file__).parent.parent / "resources" / "fonts"
    font_regular = str(fonts_dir / "Vazirmatn-Regular.ttf")
    font_medium = str(fonts_dir / "Vazirmatn-Medium.ttf")
    font_bold = str(fonts_dir / "Vazirmatn-Bold.ttf")

    QFontDatabase.addApplicationFont(font_regular)
    QFontDatabase.addApplicationFont(font_medium)
    QFontDatabase.addApplicationFont(font_bold)

    # Set default application font
    app_font = QFont("Vazirmatn", 11)
    app_font.setHintingPreference(QFont.PreferNoHinting)
    app.setFont(app_font)

    # --- Theme Setup ---
    # Default to light theme, can be toggled
    apply_theme(app, "light")

    # --- Device Identity (MAC + Fingerprint) ---
    # Initialize once at startup; stored in token store for API headers
    identity = get_device_identity()
    # Identity is accessible via AuthManager later

    return app


def apply_theme(app: QApplication, theme_name: str = "light"):
    """Apply QSS theme stylesheet."""
    themes_dir = Path(__file__).parent.parent / "resources" / "themes"
    qss_file = themes_dir / f"{theme_name}.qss"

    if qss_file.exists():
        with open(qss_file, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    else:
        # Fallback minimal theme if file missing
        app.setStyleSheet("""
            QWidget {
                font-family: 'Vazirmatn', sans-serif;
                font-size: 11pt;
                color: #212529;
                background-color: #f8f9fa;
            }
        """)


if __name__ == "__main__":
    main()