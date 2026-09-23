"""SSO/LDAP module public interface (stub — full implementation per Architecture v2.0 Section M12)."""
from app.modules.ssoldap.api.routes import router


def register_event_handlers(event_bus) -> None:
    """Subscribe to cross-module events (no-op stub)."""


__all__ = ["router", "register_event_handlers"]
