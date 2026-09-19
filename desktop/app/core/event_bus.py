import asyncio
import logging
from typing import Dict, List, Callable, Any, Optional
from PySide6.QtCore import QObject, Signal, QTimer, Qt


logger = logging.getLogger(__name__)


class EventBus(QObject):
    """Central event bus for inter-module communication.
    
    Allows decoupling between different parts of the application
    (UI components, services, modules) via signals and slots.
    Follows the pub-sub pattern.
    """
    
    # Default signals that are always available
    subscriptions: Dict[str, List[Callable]] = None
    
    def __init__(self, parent: QObject = None):
        super().__init__(parent)
        self.subscriptions = {}  # event_type -> [callbacks]
        self._single_use: Dict[str, List[Callable]] = {}  # for one-time subscriptions
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Subscribe to an event type. Called once per event emission.
        
        Args:
            event_type: The event identifier string
            callback: Function to call when event is emitted
        """
        if event_type not in self.subscriptions:
            self.subscriptions[event_type] = []
        self.subscriptions[event_type].append(callback)
    
    def subscribe_once(self, event_type: str, callback: Callable) -> None:
        """Subscribe to an event type, which will be auto-removed after first invocation."""
        if event_type not in self._single_use:
            self._single_use[event_type] = []
        self._single_use[event_type].append(callback)
    
    def emit(self, event_type: str, data: Any = None) -> None:
        """Emit an event to all subscribed callbacks.
        
        Args:
            event_type: The event identifier
            data: Optional data to pass to callbacks
        """
        # Call regular subscribers
        if event_type in self.subscriptions:
            for callback in self.subscriptions[event_type][:]:  # Copy to allow removal
                try:
                    if data is not None:
                        callback(data)
                    else:
                        callback()
                except Exception as e:
                    logger.error(f"Error in event subscriber for {event_type}: {e}")
        
        # Call one-time subscribers and remove them
        if event_type in self._single_use:
            for callback in self._single_use[event_type][:]:
                try:
                    if data is not None:
                        callback(data)
                    else:
                        callback()
                except Exception as e:
                    logger.error(f"Error in one-time event subscriber: {e}")
            # Remove processed one-time subscribers
            self._single_use[event_type] = [
                c for c in self._single_use[event_type] 
                if c not in [callback for callback in self._single_use[event_type] 
                           if self._has_already_fired(callback, event_type)]
            ]
    
    def _has_already_fired(self, callback: Callable, event_type: str) -> bool:
        """Check if a one-time callback has already been fired (simplified)."""
        # In a real implementation, we'd track this state
        # For now, we just call it once and remove
        return True  # Simplified: always remove after first call
    
    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """Unsubscribe from an event type."""
        if event_type in self.subscriptions:
            self.subscriptions[event_type] = [
                c for c in self.subscriptions[event_type] if c != callback
            ]
            if not self.subscriptions[event_type]:
                del self.subscriptions[event_type]
    
    def once(self, event_type: str, callback: Callable) -> None:
        """Alias for subscribe_once."""
        self.subscribe_once(event_type, callback)


# Convenience global instance
_global_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _global_bus
    if _global_bus is None:
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is None:
            # Can't create QApplication here, just create minimal bus
            _global_bus = EventBus.__new__(EventBus)
            _global_bus.subscriptions = {}
        else:
            _global_bus = EventBus(app)
    return _global_bus


def reset_event_bus():
    """Reset the global event bus (for testing)."""
    global _global_bus
    _global_bus = None