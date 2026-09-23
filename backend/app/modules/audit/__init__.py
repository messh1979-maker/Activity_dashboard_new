"""Audit module public interface (real DDL-backed audit, section M11)."""
from app.modules.audit.api.routes import router
from app.modules.audit.events import register_event_handlers


__all__ = ["router", "register_event_handlers"]
