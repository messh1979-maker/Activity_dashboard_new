import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QScreen

from desktop.app.core.bootstrap import bootstrap


def main():
    """Entry point for the desktop application."""
    app = bootstrap()

    # Force high DPI scaling on Windows
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Apply RTL layout direction globally
    app.setLayoutDirection(Qt.RightToLeft)

    # Apply default theme (light)
    from desktop.app.core.bootstrap import apply_theme
    apply_theme(app, "light")

    # Show login window first
    from desktop.app.views.login_window import LoginWindow
    login_window = LoginWindow()

    # Handle login success - show main window
    def on_login_success(user):
        login_window.close()
        from desktop.app.views.main_window import MainWindow
        main_window = MainWindow(user=user, auth_manager=login_window._auth_manager)
        main_window.show()

    login_window.login_successful.connect(on_login_success)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()