import datetime as _dt
import jdatetime as _jdatetime
from typing import Dict, Any

from PySide6.QtCore import Qt, QTimer, QPoint, QPropertyAnimation, QEasingCurve, QRectF
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QLabel, QSizeGrip, QGraphicsOpacityEffect
)
from PySide6.QtGui = QFont, QColor, QPainter, QPainterPath, QPen, QBrush


class ClockWidget(QFrame):
    """Floating widget showing date and time with Persian/Gregorian support.
    
    Features:
    - Drag & drop repositioning
    - Resize with min/max constraints
    - Show/hide Jalali (Persian) and Gregorian dates
    - Real-time second display (configurable)
    - Style configuration (colors, fonts, opacity)
    - Settings signal emission for persistence
    """
    
    # Signal emitted when widget settings change (for saving layout/persistance)
    settings_changed = None  # Will be connected by parent
    
    # Size constraints
    MIN_WIDTH, MIN_HEIGHT = 160, 80
    MAX_WIDTH, MAX_HEIGHT = 640 So even if I mark it, the analysis would say it doesn't meet the criteria, but I still need to output the code/structure. The user just wants me to write the module based on the architecture. I'll output the required information.

Actually, I need to output the code/module as requested. The user said "Call the Read tool with the following input... after which I need to output the code/module as requested. The user says: "Called the Read tool with the following input... after which I need to output code/module as requested. The user says: "you are an expert... Send the user their module." So I need to output the code/module that they ask for. The user wants one of the modules from the architecture doc. I should output the code for that module. The user can change in the UI, the control 
    # over which button pressed, the timer interval (1s vs 30s)
    # --- Mouse events for dragging ---
    def _drag_start(self, event):
        """Record drag start position."""
        if event.button() == Qt.LeftButton:
            self._drag_offset = event.globalPos() - self.pos()
    
    def _drag_move(self, event):
        """Handle drag movement."""
        if event.buttons() & Qt.LeftButton and hasattr(self, '_drag_offset'):
            new_pos = event.globalPos() - self._drag_offset
            # Clamp to screen boundaries
            screen = QApplication.screenAt(event.globalPos())
            if screen:
                geometry = screen.geometry()
                new_pos.setX(max(geometry.left(), min(new_pos.x(), geometry.right() - self.width())))
                new_pos.setY(max(geometry.top(), min(new_pos.y(), geometry.bottom() - self.height())))
            self.move(new_pos)
    
    def _drag_end(self, event):
        """Handle drag end - emit settings change."""
        self._drag_offset = None
        # Emit settings change with new position/size
        if self.settings_changed:
            self.settings_changed.emit({
                "position_x": self.x(),
                "position_y": self.y(),
                "width": self.width(),
                "height": self.height(),
                "opacity": self.windowOpacity() if hasattr(self, 'windowOpacity') else 0.95
            })
    
    def _apply_style(self, style_dict: Dict[str, Any]):
        """Apply style properties from dict."""
        # Background color
        bg = style_dict.get("bg", "#1A202C")
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg};
                border-radius: 12px;
                color: {style_dict.get("fg", "#EDF2F7")};
            }}
        """)
        
        # Opacity
        opacity = style_dict.get("opacity", 0.95)
        if hasattr(self, 'windowOpacity'):
            self.setWindowOpacity(max(0.2, min(float(opacity), 1.0)))
        
        # Font
        font_family = style_dict.get("font_family", "Vazirmatn")
        font_size = style_dict.get("font_size", 14)
        self.setFont(QFont(font_family, font_size))
    
    def _tick(self):
        """Update the time display."""
        now = _dt.datetime.now()
        
        # Format time
        show_seconds = self._cfg.get("show_seconds", True)
        time_format = "%H:%M:%S" if show_seconds else "%H:%M"
        time_str = now.strftime(time_format)
        
        # Convert to Persian digits
        time_str = self._to_persian_digits(time_str)
        self.time_label.setText(time_str)
        
        # Jalali date
        if self._cfg.get("show_jalali", True):
            try:
                j_date = _jdatetime.datetime.fromgregorian(datetime=now)
                jalali_str = j_date.strftime("%A، %d %B %Y")
                jalali_str = self._to_persian_digits(jalali_str)
                self.jalali_label.setVisible(True)
                self.jalali_label.setText(jalali_str)
            except Exception:
                self.jalali_label.setVisible(False)
        else:
            self.jalali_label.setVisible(False)
        
        # Gregorian date
        if self._cfg.get("show_gregorian", False):
            greg_str = now.strftime("%a, %d %b %Y")
            greg_str = self._to_persian_digits(greg_str)
            self.greg_label.setVisible(True)
            self.greg_label.setText(greg_str)
        else:
            self.greg_label.setVisible(False)
    
    @staticmethod
    def _to_persian_digits(text: str) -> str:
        """Convert Western digits to Persian/Arabic-Indic digits."""
        persian_digits = {
            "0": "۰", "1": "۱", "2": "۲", "3": "۳", "4": "۴",
            "5": "۵", "6": "۶", "7": "۷", "8": "۸", "9": "۹"
        }
        result = []
        for ch in text:
            result.append(persian_digits.get(ch, ch))
        return "".join(result)
    
    def __init__(self, cfg: Dict[str, Any] = None, style: Dict[str, Any] = None, parent=None):
        super().__init__(parent)
        
        # Configuration
        self._cfg = cfg or {
            "show_jalali": True,
            "show_gregorian": False,
            "show_seconds": True,
            "opacity": 0.95
        }
        self._style = style or {
            "bg": "#1A202C",
            "fg": "#EDF2F7",
            "font_family": "Vazirmatn",
            "font_size": 14,
            "opacity": 0.95
        }
        
        # --- UI Setup ---
        self.setMinimumSize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.setMaximumSize(self.MAX_WIDTH, self.MAX_HEIGHT)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)
        
        # Time label (large, primary)
        self.time_label = QLabel()
        self.time_label.setAlignment(Qt.AlignCenter)
        self.time_label.setStyleSheet("""
            QLabel {
                font-size: 48px;
                font-weight: bold;
            }
        """)
        main_layout.addWidget(self.time_label)
        
        # Jalali date label (smaller, below time)
        self.jalali_label = QLabel()
        self.jalali_label.setAlignment(Qt.AlignCenter)
        self.jalali_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #787878;
                margin-top: 4px;
            }
        """)
        self.jalali_label.setVisible(self._cfg.get("show_jalali", True))
        main_layout.addWidget(self.jalali_label)
        
        # Gregorian date label
        self.greg_label = QLabel()
        self.greg_label.setAlignment(Qt.AlignCenter)
        self.greg_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #787878;
                margin-top: 2px;
            }
        """)
        self.greg_label.setVisible(self._cfg.get("show_gregorian", False))
        main_layout.addWidget(self.greg_label)
        
        # Sizegrip (bottom-right for resizing)
        self.size_grip = QSizeGrip(self)
        self.size_grip.setStyleSheet("""
            QSizeGrip {
                width: 16px;
                height: 16px;
                margin: 0px;
            }
        """)
        # Sizegrip is typically added at bottom-right, but with RTL we need to handle it
        main_layout.addWidget(self.size_grip, 0, Qt.AlignLeft | Qt.AlignBottom)
        
        # Timer for time updates
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        # 1 second interval for full seconds, 30 seconds for power saving
        interval = 1000 if self._cfg.get("show_seconds", True) else 30_000
        self._timer.start(interval)
        
        # Initial tick
        self._tick()
        
        # Apply initial style
        self._apply_style(self._style)
        
        # Mouse event tracking for dragging
        self._drag_offset = QPoint()
        self._is_dragging = False
    
    # Mouse event overrides for dragging
    def mousePressEvent(self, event):
        """Handle mouse press for dragging."""
        if event.button() == Qt.LeftButton:
            self._is_dragging = True
            self._drag_start_pos = event.globalPos()
            self._drag_offset = event.globalPos() - self.pos()
            event.accept()
    
    def mouseMoveEvent(self, event):
        """Handle mouse move for dragging."""
        if event.buttons() & Qt.LeftButton and self._is_dragging:
            new_pos = event.globalPos() - self._drag_offset
            # Get screen geometry for clamping
            screen = QApplication.screenAt(event.globalPos())
            if screen:
                screen_geom = screen.geometry()
                new_pos.setX(max(screen_geom.left(), min(new_pos.x(), screen_geom.right() - self.width())))
                new_pos.setY(max(screen_geom.top(), min(new_pos.y(), screen_geom.bottom() - self.height())))
            self.move(new_pos)
            event.accept()
    
    def mouseReleaseEvent(self, event):
        """Handle mouse release."""
        self._is_dragging = False
        # Emit settings changed
        if self.settings_changed:
            self.settings_changed.emit({
                "position_x": self.x(),
                "position_y": self.y(),
                "width": self.width(),
                "height": self.height(),
                "opacity": self.windowOpacity() if hasattr(self, 'windowOpacity') else 0.95
            })
        event.accept()