"""Event bus for cross-module communication."""
from typing import Dict, List, Callable, Any
from concurrent.futures import ThreadPoolExecutor


class EventBus:
    """Simple event bus for inter-module communication."""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._executor = ThreadPoolExecutor(max_workers=4)
    
    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Subscribe to an event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
    
    def publish(self, event_type: str, data: Any = None) -> None:
        """Publish an event to all subscribers."""
        handlers = self._subscribers.get(event_type, [])
        # Run handlers in thread pool to avoid blocking
        for handler in handlers:
            try:
                self._executor.submit(handler, data)
            except Exception:
                pass


# Global event bus instance
event_bus = EventBus()