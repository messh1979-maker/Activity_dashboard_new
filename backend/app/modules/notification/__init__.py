"""Notification module public interface (real DDL).

Subscribes to auth login / role-change events and writes a
notification row for the affected user (inbox channel).
"""

from app.modules.notification.api.routes import router
from app.modules.notification.events import register_event_handlers

__all__ = ["router", "register_event_handlers"]