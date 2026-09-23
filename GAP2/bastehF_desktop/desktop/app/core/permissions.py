import logging
from typing import Set, Dict, Any, Optional, FrozenSet
from PySide6.QtCore import QObject, QLocale, QTranslator


logger = logging.getLogger(__name__)


class PermissionCache(QObject):
    """Caches user permissions for UI visibility decisions.
    
    This prevents repeated API calls to check permissions
    and provides a consistent interface for UI components.
    """
    
    def __init__(self, user_id: str, api_client, token_store):
        super().__init__()
        self._user_id = user_id
        self._api_client = api_client
        self._token_store = token_store
        self._cached_permissions: Optional[FrozenSet[str]] = None
        self._cache_timestamp: float = 0.0
        self._cache_ttl = 300  # 5 minutes cache
        self._is_loading = False
        
        # Load initial permissions if user is authenticated
        if token_store.is_authenticated:
            self._reload()
    
    def _reload(self):
        """Reload permissions from the API."""
        if self._is_loading:
            return
        
        self._is_loading = True
        try:
            # Fire-and-forget: don't block UI
            import asyncio
            loop = asyncio.get_event_loop()
            # In a real QApplication, we'd use async properly
            # Here we just call the sync endpoint
            response = self._api_client.get(
                f"/rbac/permissions?user_id={self._user_id}"
            )
            if response.status_code == 200:
                data = response.json()
                self._cached_permissions = frozenset(data.get("permissions", []))
                self._cache_timestamp = time.time()
        except Exception as e:
            logger.error(f"Failed to reload permissions: {e}")
        finally:
            self._is_loading = False
    
    def has_permission(self, permission_code: str) -> bool:
        """Check if the user has a specific permission."""
        # Check cache validity
        if (time.time() - self._cache_timestamp) > self._cache_ttl:
            self._reload()
        
        if self._cached_permissions is None:
            # If no cache, do a quick check
            # In production, this would trigger a reload
            return False
        
        return permission_code in self._cached_permissions
    
    def has_any_permission(self, permission_codes: list) -> bool:
        """Check if the user has any of the specified permissions."""
        for code in permission_codes:
            if self.has_permission(code):
                return True
        return False
    
    def has_all_permissions(self, permission_codes: list) -> bool:
        """Check if the user has all of the specified permissions."""
        return all(self.has_permission(code) for code in permission_codes)
    
    def get_visible_sections(self, allowed_sections: Dict[str, str]) -> Dict[str, bool]:
        """Get visibility status for UI sections.
        
        Args:
            allowed_sections: Dict of section_name -> required_permission
                e.g., {"admin_panel": "admin.manage", "reports": "report.view"}
        
        Returns:
            Dict of section_name -> bool (visible or not)
        """
        result = {}
        for section, required_perm in allowed_sections.items():
            result[section] = self.has_permission(required_perm)
        return result
    
    def is_admin(self) -> bool:
        """Check if user has administrative privileges."""
        return self.has_permission("admin.manage") or self.has_permission("super_admin")
    
    def can_manage_users(self) -> bool:
        """Check if user can manage other users."""
        return self.has_permission("user.manage")
    
    def can_export_data(self) -> bool:
        """Check if user can export data."""
        return self.has_permission("audit.export")
    
    def can_manage_roles(self) -> bool:
        """Check if user can manage RBAC roles."""
        return self.has_permission("rbac.manage")