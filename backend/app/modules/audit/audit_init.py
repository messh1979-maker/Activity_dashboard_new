"""Audit module public interface (stub — full implementation per Architecture v2.0 Section M11)."""
from app.modules.audit.api.routes import router
from app.modules.audit.events import register_event_handlers

__all__ = ["router", "register_event_handlers"]
