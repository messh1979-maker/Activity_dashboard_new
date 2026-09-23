# PART 11/12 of GAP PACK

## FILE: bastehF_desktop/desktop/app/core/auth_manager.py
## SIZE: 10360 bytes
==========================================================================================

```python
import json
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Union

from PySide6.QtCore import QObject, Signal, QTimer, Slot
from PySide6.QtNetwork import QNetworkCookie

from desktop.app.core.api_client import ApiClient, TokenStore, quick_get, quick_post
from desktop.app.core.device_identity import get_device_identity, _normalize_mac


logger = logging.getLogger(__name__)


class AuthManager(QObject):
    """Manages authentication state: login, MFA, refresh, logout."""
    
    # Signals
    login_requested = Signal(dict)  # Emitted when login is attempted
    login_successful = Signal(dict)  # user info
    login_failed = Signal(str)  # error message
    mfa_challenged = Signal(str)  # mfa_token or method
    mfa_verified = Signal()  # MFA successfully verified
    logout_completed = Signal()
    token_refreshed = Signal(str)  # new access token
    authentication_state_changed = Signal(bool)  # logged in/out
    
    def __init__(self, token_store: Optional["TokenStore"] = None,
                 api_client: Optional[ApiClient] = None):
        super().__init__()
        self._token_store = token_store or TokenStore()
        self._api_client = api_client or ApiClient(token_store=self._token_store)
        self._login_in_progress = False
        self._mfa_pending = False
        
        # Connect api client signals if needed
        # The api client's auto-refresh is handled internally
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user has a valid access token."""
        return self._token_store.is_authenticated
    
    @property
    def user_info(self) -> Optional[dict]:
        """Get current user information from token payload."""
        if not self.is_authenticated:
            return None
        # In a real implementation, decode JWT payload
        # For now, return basic info
        return getattr(self, "_user_info", None)
    
    @user_info.setter
    def user_info(self, info: dict):
        self._user_info = info
    
    def login(self, credentials: dict):
        """Attempt to login with given credentials."""
        if self._login_in_progress:
            logger.warning("Login already in progress")
            return
        
        self._login_in_progress = True
        try:
            # Send login request
            response = quick_post(
                "/auth/login",
                {"identifier": credentials.get("username"),
                 "password": credentials.get("password"),
                 "remember_me": credentials.get("remember_me", False)},
                self._token_store
            )
            
            if response.status_code == 200:
                data = response.json()
                self._handle_login_success(data)
            elif response.status_code == 401:
                self.login_failed.emit("نام کاربری یا رمز عبور اشتباه است.")
            else:
                self.login_failed.emit(
                    f"خطای سرور: {response.status_code}"
                )
        except Exception as e:
            logger.error(f"Login error: {e}")
            self.login_failed.emit(str(e))
        finally:
            self._login_in_progress = False
    
    def _handle_login_success(self, data: dict):
        """Process successful login response."""
        # Store tokens
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        expires_in = data.get("expires_in", 900)  # default 15 min
        
        self._token_store.access_token = access_token
        self._token_store.refresh_token = refresh_token
        self._token_store._token_expires_at = time.time() + expires_in
        
        # Store user info
        user_info = data.get("user", {})
        self.user_info = user_info
        
        # Device tracking - register device if new
        # The API will handle device registration, but we note it here
        
        # Emit success signal
        self.login_successful.emit(user_info)
        self.authentication_state_changed.emit(True)
        
        # Start token refresh timer
        self._start_token_refresh_timer(expires_in)
    
    def _start_token_refresh_timer(self, expires_in: int):
        """Start timer to refresh token before expiry."""
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._refresh_access_token)
        # Refresh 30 seconds before expiry
        self._refresh_timer.start(max(1000, (expires_in - 30) * 1000))
    
    def _refresh_access_token(self):
        """Refresh the access token using refresh token."""
        if not self._token_store.refresh_token:
            logger.warning("No refresh token available")
            self.logout_completed.emit()
            return
        
        try:
            response = quick_post(
                "/auth/refresh",
                {"refresh_token": self._token_store.refresh_token},
                self._token_store
            )
            
            if response.status_code == 200:
                data = response.json()
                new_access = data.get("access_token")
                new_refresh = data.get("refresh_token", self._token_store.refresh_token)
                new_expires = data.get("expires_in", 900)
                
                self._token_store.access_token = new_access
                self._token_store.refresh_token = new_refresh
                self._token_store._token_expires_at = time.time() + new_expires
                
                self.token_refreshed.emit(new_access)
            else:
                # Refresh failed - user must re-login
                self.logout_completed.emit()
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            self.logout_completed.emit()
    
    def verify_mfa(self, mfa_token: str, mfa_method: str = "totp"):
        """Verify MFA code."""
        if self._mfa_pending:
            return
        
        self._mfa_pending = True
        try:
            response = quick_post(
                "/auth/mfa/verify",
                {"mfa_token": mfa_token, "mfa_method": mfa_method},
                self._token_store
            )
            
            if response.status_code == 200:
                data = response.json()
                # If login completes after MFA
                if data.get("access_token"):
                    self._handle_login_success(data)
                self.mfa_verified.emit()
            else:
                self.login_failed.emit("کد MFA نامعتبر است.")
        except Exception as e:
            logger.error(f"MFA verification error: {e}")
            self.login_failed.emit(str(e))
        finally:
            self._mfa_pending = False
    
    def enroll_mfa(self, secret: str, code: str) -> Optional[dict]:
        """
        Enroll TOTP MFA.
        
        Returns dict with QR code URL and secret if this is initial enrollment,
        or verification result if resuming.
        """
        try:
            response = quick_post(
                "/auth/mfa/enroll",
                {"secret": secret, "code": code},
                self._token_store
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.login_failed.emit("خطا در ثبت MFA.")
                return None
        except Exception as e:
            logger.error(f"MFA enrollment error: {e}")
            self.login_failed.emit(str(e))
            return None
    
    def logout(self):
        """Log out the current user."""
        try:
            # Revoke all sessions or just the current one
            if self._token_store.access_token:
                quick_post(
                    "/auth/logout-all",
                    {},
                    self._token_store
                )
        except Exception as e:
            logger.warning(f"Logout error (non-critical): {e}")
        finally:
            self._token_store.clear_tokens()
            self._user_info = None
            self.authentication_state_changed.emit(False)
            self.logout_completed.emit()
    
    def request_password_reset(self, identifier: str):
        """Send password reset link."""
        try:
            quick_post(
                "/auth/password/forgot",
                {"identifier": identifier},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Password reset request error: {e}")
    
    def change_password(self, current: str, new: str):
        """Change user password."""
        try:
            quick_post(
                "/auth/password/change",
                {"current_password": current, "new_password": new},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Change password error: {e}")
    
    def get_devices(self) -> list:
        """Get list of registered devices."""
        try:
            response = quick_get("/auth/devices", self._token_store)
            if response.status_code == 200:
                return response.json().get("items", [])
        except Exception as e:
            logger.error(f"Get devices error: {e}")
        return []
    
    def trust_device(self, device_id: str, label: str = ""):
        """Mark a device as trusted (requires MFA)."""
        try:
            quick_post(
                f"/auth/devices/{device_id}/trust",
                {"label": label},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Trust device error: {e}")
    
    def untrust_device(self, device_id: str):
        """Mark a device as untrusted."""
        try:
            quick_post(
                f"/auth/devices/{device_id}/untrust",
                {},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Untrust device error: {e}")
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/bootstrap.py
## SIZE: 2158 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/device_identity.py
## SIZE: 4498 bytes
==========================================================================================

```python
import hashlib
import platform
import re
import socket
import uuid

import psutil


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with colon separator."""
    return mac.upper().replace("-", ":").replace(".", ":").strip()


def get_primary_mac() -> tuple(str | None, str):
    """
    Get the primary MAC address of the system.
    
    Returns:
        tuple of (mac_address, source) where source is one of:
        - 'psutil': from psutil net_if_addrs (preferred)
        - 'uuid_getnode': from uuid.getnode() fallback
        - 'unavailable': if no MAC could be determined
    """
    # Try to find a non-virtual, active network interface with a local IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
    except (OSError, socket.error):
        local_ip = None

    stats = psutil.net_if_stats()
    # First pass: find interface that has the local IP and is up
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        if local_ip and any(a.address == local_ip for a in addrs):
            mac = next(
                (a.address for a in addrs if a.family == psutil.AF_LINK),
                None
            )
            if mac and mac != "00:00:00:00:00:00":
                return _normalize_mac(mac), "psutil"

    # Second pass: fallback to any up interface (avoiding virtual ones)
    for name, addrs in psutil.net_if_addrs().items():
        if name.lower() in ("loopback", "vmware", "virtualbox",
                           "hyper-v", "docker", "vethernet"):
            continue
        st = stats.get(name)
        if not st or not st.isup:
            continue
        mac = next(
            (a.address for a in addrs if a.family == psutil.AF_LINK),
            None
        )
        if mac and mac != "00:00:00:00:00:00":
            return _normalize_mac(mac), "psutil"

    # Fallback: uuid.getnode()
    node = uuid.getnode()
    # Check that the MAC bit is global/unicast (bit 40 = 0)
    if (node >> 40) % 2 == 0:
        mac = ":".join(f"{(node >> e) & 0xFF:02X}" for e in range(40, -8, -8))
        return _normalize_mac(mac), "uuid_getnode"

    # Last resort: return None (MAC randomization or VM environment)
    return None, "unavailable"


def get_system_fingerprint() -> str:
    """
    Generate a stable system fingerprint based on multiple hardware/software attributes.
    
    This fingerprint is more stable than MAC alone (which can change with
    network randomization) and is used as the primary device identity.
    
    Returns:
        SHA-256 hex digest string representing the system fingerprint.
    """
    mac, _ = get_primary_mac()
    parts = [
        platform.node(),
        platform.machine(),
        platform.system(),
        platform.processor(),
        str(psutil.cpu_count(logical=False)),
        _machine_guid(),
        (mac or "no-mac"),
    ]
    normalized = "|".join(filter(None, parts))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _machine_guid() -> str:
    """
    Read the Machine GUID from Windows registry (HKLM\Software\Microsoft\Cryptography).
    
    This is a more stable identifier than MAC as it persists across
    network changes and VM snapshots.
    """
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        return machine_guid
    except (WindowsError, ImportError, FileNotFoundError):
        # Fallback to a hash of system info if registry not accessible
        import hashlib
        import platform
        data = f"{platform.node()}|{platform.machine()}|{platform.system()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:8]


def is_valid_mac_format(mac: str) -> bool:
    """
    Validate that a MAC address string has the correct format.
    
    Accepted formats: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
    """
    pattern = r'^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$'
    return bool(re.match(pattern, mac.upper())) and mac.upper() not in (
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
    )
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/event_bus.py
## SIZE: 4727 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/permissions.py
## SIZE: 4110 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/token_store.py
## SIZE: 3932 bytes
==========================================================================================

```python
import keyring
import time
from typing import Optional


class TokenStore:
    """Secure token storage using platform keyring.
    
    Stores:
    - access_token: Current JWT access token
    - refresh_token: Refresh token for obtaining new access tokens
    - token_expires_at: Expiration timestamp (float, seconds since epoch)
    
    All values are stored in the platform's secure credential storage
    (Windows: DPAVA, macOS: Keychain, Linux: libsecret).
    """
    
    def __init__(self):
        self._service_name = "planner_desktop"
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0.0
    
    @property
    def access_token(self) -> Optional[str]:
        """Get the current access token, if still valid."""
        if self.is_valid(self._access_token):
            return self._access_token
        self._access_token = None
        return None
    
    @access_token.setter
    def access_token(self, token: Optional[str]):
        """Set the access token and store it securely."""
        self._access_token = token
        if token:
            try:
                keyring.set_password(self._service_name, "access_token", token)
            except Exception as e:
                logger.warning(f"Failed to store access token in keyring: {e}")
        else:
            try:
                keyring.delete_password(self._service_name, "access_token")
            except Exception:
                pass
    
    @property
    def refresh_token(self) -> Optional[str]:
        """Get the refresh token."""
        if self.is_valid(self._refresh_token):
            return self._refresh_token
        self._refresh_token = None
        return None
    
    @refresh_token.setter
    def refresh_token(self, token: Optional[str]):
        """Set the refresh token and store it securely."""
        self._refresh_token = token
        if token:
            try:
                keyring.set_password(self._service_name, "refresh_token", token)
            except Exception as e:
                logger.warning(f"Failed to store refresh token in keyring: {e}")
        else:
            try:
                keyring.delete_password(self._service_name, "refresh_token")
            except Exception:
                pass
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user has valid authentication."""
        return self.access_token is not None
    
    def is_valid(self, token: Optional[str]) -> bool:
        """Check if a token exists and is not expired.
        
        Note: This basic check doesn't decode JWT to get expiration.
        For full validation, the API should validate the token.
        """
        return token is not None and not token.startswith("expired_")
    
    def set_expiry(self, expires_at: float):
        """Set the token expiry timestamp."""
        self._token_expires_at = expires_at
    
    def get_expiry(self) -> float:
        """Get the token expiry timestamp."""
        return self._token_expires_at
    
    def clear(self):
        """Clear all stored tokens."""
        self.access_token = None
        self.refresh_token = None
        self.set_expiry(0.0)
    
    def clear_all(self):
        """Clear all tokens from secure storage."""
        self.clear()
        try:
            keyring.delete_password(self._service_name, "access_token")
            keyring.delete_password(self._service_name, "refresh_token")
        except Exception:
            pass


# Helper logger (will be configured by the application)
import logging
logger = logging.getLogger(__name__)


# Convenience function for quick access
def create_token_store() -> TokenStore:
    """Create and initialize a TokenStore instance."""
    return TokenStore()
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/ws_client.py
## SIZE: 8823 bytes
==========================================================================================

```python
import asyncio
import json
import logging
import time
from typing import Optional, Dict, Any, Set, Callable, Union

from PySide6.QtCore import QObject, Signal, QTimer, Qt, QWaitCondition, QMutex
from PySide6.QtWebSockets import QWebSocket, QWebSocketProtocol
from PySide6.QtCore import QUrl

from desktop.app.core.api_client import TokenStore

logger = logging.getLogger(__name__)


class WsClient(QObject):
    """WebSocket client for real-time features (chat, notifications).
    
    Runs on a separate QThread to avoid blocking the UI.
    Handles connection, message passing, and automatic reconnection.
    """
    
    # Connection signals
    connected = Signal(str)  # room_id or "general"
    disconnected = Signal(str)  # reason
    connection_error = Signal(str)  # error message
    
    # Message signals
    message_received = Signal(dict)  # parsed message
    chat_message = Signal(dict)  # chat-specific message
    notification = Signal(dict)  # system notification
    
    # Presence/signals
    member_joined = Signal(str, str)  # user_id, room_id
    member_left = Signal(str, str)  # user_id, room_id
    typing_indicator = Signal(str, str, bool)  # user_id, room_id, is_typing
    
    # Authentication
    auth_required = Signal()  # Sent when session expires on WS
    
    def __init__(self, token_store: TokenStore, parent: QObject = None):
        super().__init__(parent)
        self._token_store = token_store
        self._ws: Optional[QWebSocket] = None
        self._current_room: Optional[str] = None
        self._rooms: Set[str] = set()  # Track joined rooms
        self._message_handlers: Dict[str, Callable] = {}
        _ reconnect_attempts = 0
        _ max_reconnect = 5
        _ reconnect_delay = 2000  # ms
        
        # Connect Qt signals to internal slots
        self._ws.textMessageReceived.connect(self._on_text_message)
        self._ws.error.connect(self._on_ws_error)
        self._ws.disconnected.connect(self._on_ws_disconnected)
    
    def connect_to_room(self, room_id: str, access_token: str):
        """Connect to a specific chat room."""
        if self._ws and self._ws.state() == QWebSocketProtocol.WebSocketConnected:
            # Already connected, just join the room
            self._join_room(room_id)
            return
        
        # Set up WebSocket
        self._ws = QWebSocket()
        
        # Set up headers with device identity and token
        # The QWebSocket doesn't easily allow custom headers on connect,
        # so we'll send auth as first message after connection
        
        # Connect to the chat endpoint
        ws_url = f"wss://api.corp.local/ws/chat?token={access_token}"
        self._ws.open(QUrl(ws_url))
        
        # Set timeout for connection
        self._connect_timer = QTimer()
        self._connect_timer.timeout.connect(self._on_connection_timeout)
        self._connect_timer.start(10000)  # 10 seconds timeout
    
    def _join_room(self, room_id: str):
        """Join a chat room (send join message)."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        join_msg = json.dumps({
            "type": "join",
            "room_id": room_id
        })
        self._ws.sendTextMessage(join_msg)
        self._current_room = room_id
        self._rooms.add(room_id)
    
    def send_message(self, room_id: str, message: str, 
                     reply_to: Optional[str] = None):
        """Send a message to a chat room."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        msg = {
            "type": "message",
            "room_id": room_id,
            "body": message
        }
        if reply_to:
            msg["reply_to"] = reply_to
        
        self._ws.sendTextMessage(json.dumps(msg))
    
    def send_typing(self, room_id: str, is_typing: bool):
        """Send typing indicator."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        msg = json.dumps({
            "type": "typing",
            "room_id": room_id,
            "is_typing": is_typing
        })
        self._ws.sendTextMessage(msg)
    
    def leave_room(self, room_id: str):
        """Leave a chat room."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        msg = json.dumps({
            "type": "leave",
            "room_id": room_id
        })
        self._ws.sendTextMessage(msg)
        
        self._rooms.discard(room_id)
        if room_id in self._rooms:
            self._current_room = None
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a handler for a specific message type."""
        self._message_handlers[message_type] = handler
    
    # Internal slots for WebSocket events
    
    @Slot(str)
    def _on_text_message(self, message: str):
        """Handle incoming text messages from WebSocket."""
        try:
            msg = json.loads(message)
            msg_type = msg.get("type", "")
            
            # Dispatch to type-specific handler
            if msg_type in self._message_handlers:
                self._message_handlers[msg_type](msg)
            elif msg_type == "message":
                self.chat_message.emit(msg)
            elif msg_type == "notification":
                self.notification.emit(msg)
            elif msg_type == "member_joined":
                self.member_joined.emit(msg.get("user_id", ""), msg.get("room_id", ""))
            elif msg_type == "member_left":
                self.member_left.emit(msg.get("user_id", ""), msg.get("room_id", ""))
            elif msg_type == "typing":
                self.typing_indicator.emit(
                    msg.get("user_id", ""),
                    msg.get("room_id", ""),
                    msg.get("is_typing", False)
                )
            else:
                self.message_received.emit(msg)
                
        except json.JSONDecodeError:
            logger.error(f"Failed to parse WebSocket message: {message}")
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
    
    @Slot(QWebSocketProtocol.QAbstractSocket.WebSocketError)
    def _on_ws_error(self, error: QWebSocketProtocol.QAbstractSocket.WebSocketError):
        """Handle WebSocket errors."""
        error_str = str(self._ws.error())
        logger.error(f"WebSocket error: {error_str}")
        self.connection_error.emit(error_str)
    
    @Slot()
    def _on_ws_disconnected(self):
        """Handle WebSocket disconnection."""
        reason = "Network loss" if self._ws else "Client closed"
        logger.info(f"WebSocket disconnected: {reason}")
        self.disconnected.emit(reason)
        
        # Attempt reconnection
        self._schedule_reconnect()
    
    def _on_connection_timeout(self):
        """Handle connection timeout."""
        logger.warning("WebSocket connection timed out")
        self.connection_error.emit("اتصال به سرور چت timed out")
        if self._ws:
            self._ws.close()
        self._schedule_reconnect()
    
    def _schedule_reconnect(self):
        """Schedule automatic reconnection."""
        self._reconnect_attempts += 1
        if self._reconnect_attempts >= self._max_reconnect:
            logger.error("Max reconnection attempts reached")
            self.disconnected.emit("تعداد تلاش‌های اتصال به حد raggi")
            return
        
        delay = self._reconnect_delay * self._reconnect_attempts
        logger.info(f"Scheduling reconnection in {delay}ms (attempt {self._reconnect_attempts})")
        
        self._reconnect_timer = QTimer()
        self._reconnect_timer.timeout.connect(self._attempt_reconnect)
        self._reconnect_timer.start(delay)
    
    def _attempt_reconnect(self):
        """Attempt to reconnect to WebSocket."""
        if not self._token_store.access_token:
            logger.warning("No access token for reconnection")
            return
        
        # Re-open connection
        # We need to know which room we were in
        if self._current_room:
            self.connect_to_room(self._current_room, self._token_store.access_token)
        else:
            # Just reconnect without a specific room
            self._ws = QWebSocket()
            self._ws.open(QUrl(f"wss://api.corp.local/ws/chat?token={self._token_store.access_token}"))
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/main.py
## SIZE: 1159 bytes
==========================================================================================

```python
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

    # Show login window first
    from desktop.app.views.login_window import LoginWindow
    login_window = LoginWindow()

    # Handle login success - show main window
    def on_login_success(user):
        login_window.close()
        from desktop.app.views.main_window import MainWindow
        main_window = MainWindow(user=user)
        main_window.show()

    login_window.login_successful.connect(on_login_success)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/services/jalali_service.py
## SIZE: 8720 bytes
==========================================================================================

```python
import jdatetime
import datetime as _dt
from typing import Optional, Tuple, Union


class JalaliService:
    """Persian (Jalali) calendar and date utilities.
    
    Provides conversion between Gregorian (Miladi) and Jalali (Persian) dates,
    Persian digit conversion, and Jalali calendar-aware operations.
    """
    
    # Solar Hijri calendar constants
    # Nowruz (Iranian New Year) is approximately March 20-21
    NOWROUZ_MONTH = 1
    NOWROUZ_DAY = 1
    
    @staticmethod
    def gregorian_to_jalali(gy: int, gm: int, gd: int) -> Tuple[int, int, int]:
        """Convert Gregorian date to Jalali (Persian).
        
        Args:
            gy: Gregorian year
            gm: Gregorian month (1-12)
            gd: Gregorian day (1-31)
        
        Returns:
            Tuple of (jalali_year, jalali_month, jalali_day)
        """
        # Algorithm from http://algorithmic.optimate.de/
        # Based on 33-year cycle and month lengths
        
        # Convert to total days from a reference point
        # Persian start = Julian day 1948320.5 (March 20, 1925 Gregorian)
        # Gregorian start = Julian day 1721425.5 (January 1, 1970)
        
        # Simpler: use jdatetime library
        try:
            gd_date = _dt.date(gy, gm, gd)
            j_date = jdatetime.date.fromgregorian(date=gd_date)
            return (j_date.year, j_date.month, j_date.day)
        except Exception:
            # Fallback calculation
            return _JalaliService._fallback_jalali(gy, gm, gd)
    
    @staticmethod
    def _fallback_jalali(gy: int, gm: int, gd: int) -> Tuple[int, int, int]:
        """Fallback Jalali conversion algorithm."""
        # Based on 33-year cycle
        gy = gy - 1600
        g_days = 365 * gy + ((gy + 3) // 4) - ((gy + 99) // 100) + ((gy + 399) // 400) + gd - 719532
        
        # Determine Jalali year (33-year cycle)
        j_n = (g_days - 79) // 1461
        g_days = g_days - 1461 * j_n + 79
        j_y = 4 * g_days // 1461
        g_days = g_days - 1461 * j_y // 4 + 79
        j_m = (80 * g_days) // 2447
        j_d = g_days - (2447 * j_m) // 80
        g_days = (j_m + 16 + 1194) // 30  # Simplified
        j_m = (200 * g_days) / 3675  # Rough
        j_d = g_days - (33 * j_m + 4) / 5  # Rough
        
        # Return reasonable values
        return (2000 + j_y, min(max(j_m, 1), 12), max(j_d, 1))
    
    @staticmethod
    def jalali_to_gregorian(jy: int, jm: int, jd: int) -> Tuple[int, int, int]:
        """Convert Jalali (Persian) date to Gregorian.
        
        Args:
            jy: Jalali year
            jm: Jalali month (1-12)
            jd: Jalali day (1-31)
        
        Returns:
            Tuple of (gregorian_year, gregorian_month, gregorian_day)
        """
        try:
            j_date = jdatetime.date(jy, jm, jd)
            gd_date = j_date.to_gregorian()
            return (gd_date.year, gd_date.month, gd_date.day)
        except Exception:
            return _JalaliService._fallback_gregorian(jy, jm, jd)
    
    @staticmethod
    def _fallback_gregorian(jy: int, jm: int, jd: int) -> Tuple[int, int, int]:
        """Fallback Gregorian conversion."""
        # Simplified: Jalali year 1970 ≈ Gregorian 1970
        # Actual conversion would use the 33-year cycle algorithm
        return (jy + 78, jm, jd)  # Rough estimate
    
    @staticmethod
    def get_current_jalali() -> Tuple[int, int, int]:
        """Get the current date in Jalali format."""
        now = _dt.datetime.now()
        return JalaliService.gregorian_to_jalali(now.year, now.month, now.day)
    
    @staticmethod
    def get_current_gregorian() -> Tuple[int, int, int]:
        """Get the current date in Gregorian format."""
        now = _dt.datetime.now()
        return (now.year, now.month, now.day)
    
    @staticmethod
    def format_jalali_date(
        year: int, month: int, day: int,
        include_day_name: bool = True,
        digit_style: str = "persian"
    ) -> str:
        """Format a Jalali date as a string.
        
        Args:
            year: Jalali year
            month: Jalali month (1-12)
            day: Jalali day (1-31)
            include_day_name: Whether to include day name (e.g., "سه‌شنبه")
            digit_style: "persian" for Arabic-Indic digits, "western" for 0-9
        
        Returns:
            Formatted date string
        """
        # Month names in Persian
        month_names = [
            "",  # 0 index unused
            "فروردین",
            "اردیبهشت",
            "خرداد",
            "تیر",
            "مرداد",
            "شهریور",
            "مهر",
            "آبان",
            "Azar",
            "دی",
            "بهمن",
            "اسفند"
        ]
        
        day_names = [
            "یک‌شنبه",
            "دوشنبه",
            "سه‌شنبه",
            "چهارشنبه",
            "پنج‌شنبه",
            "جمعه",
            "شنبه"
        ]
        
        # Validate
        month = max(1, min(month, 12))
        day = max(1, min(day, 31))
        
        # Day name
        day_name = ""
        if include_day_name:
            # Simple calculation: known that 1 Farvardin 1401 = Wednesday
            # For simplicity, just return without day name or use fixed
            day_name = day_names[0]  # placeholder
        
        # Format: "سه‌شنبه ۳ فروردین ۱۴۰۱" or "۳ فروردین ۱۴۰۱"
        result = f"{day} {month_names[month]} {year}"
        
        # Convert digits
        if digit_style == "persian":
            result = JalaliService._to_persian_digits(result)
        
        return result
    
    @staticmethod
    def _to_persian_digits(text: str) -> str:
        """Convert Western digits to Persian."""
        digit_map = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
        return text.translate(digit_map)
    
    @staticmethod
    def parse_jalali_date(date_str: str) -> Optional[Tuple[int, int, int]]:
        """Parse a Jalali date string into (year, month, day).
        
        Supports formats like:
        - "۱۴۰۱/۳/۱۵" or "1401/3/15"
        - "۳ فروردین ۱۴۰۱"
        - "1401/03/15"
        """
        try:
            # Try standard format first
            parts = date_str.replace("/", "/").split("/")
            if len(parts) == 3:
                # y/m/d format
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                return (year, month, day)
        except (ValueError, IndexError):
            pass
        
        # Try named month format
        # ... (simplified, would need full parsing)
        return None
    
    @staticmethod
    def get_days_in_jalali_month(jy: int, jm: int) -> int:
        """Get the number of days in a Jalali month."""
        # Jalali month lengths: 31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29/30
        month_lengths = [31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29]
        
        # Leap year check: every 33 years has 6 leap years with extra day in last month
        # Jalali leap years: years where (year % 33) in [1, 5, 9, 13, 17, 22, 26, 30]
        remainder = jy % 33
        is_leap = remainder in [1, 5, 9, 13, 17, 22, 26, 30]
        
        if jm == 12:  # Last month (Esfand)
            return 30 if is_leap else 29
        
        return month_lengths[jm - 1]  # jm is 1-indexed
    
    @staticmethod
    def is_jalali_leap_year(jy: int) -> bool:
        """Check if a Jalali year is a leap year."""
        remainder = jy % 33
        return remainder in [1, 5, 9, 13, 17, 22, 26, 30]
    
    @staticmethod
    def get_jalali_new_year(year: int = None) -> Tuple[int, int, int]:
        """Get the Nowruz (New Year) date for a Jalali year.
        
        Returns (year, month, day) - typically year, 1, 1 (Farvardin 1)
        but the actual Nowruz day varies (around March 20-21 Gregorian).
        """
        if year is None:
            year = JalaliService.get_current_jalali()[0]
        return (year, 1, 1)  # Farvardin 1


# Convenience function
def get_jalali_now() -> Tuple[int, int, int]:
    """Get current date in Jalali (year, month, day)."""
    return JalaliService.get_current_jalali()


def format_jalali_simple(year: int, month: int, day: int) -> str:
    """Simple Jalali date formatting."""
    return f"{year}/{month}/{day}"
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/dashboard/dashboard_view.py
## SIZE: 9691 bytes
==========================================================================================

```python
import logging
from typing import Dict, List, Optional, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt, QSize, QTimer, Slot, QPropertyAnimation, QEasingCurve
from PySide6.QtGui = QColor

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus
from desktop.app.core.permissions import PermissionCache
from desktop.app.widgets.clock_widget import ClockWidget
from desktop.app.widgets.tag_chip import TagChip


logger = logging.getLogger(__name__)


class DashboardView(QWidget):
    """Main dashboard view showing personalized widgets and goals progress."""
    
    def __init__(
        self,
        user_info: dict,
        auth_manager: AuthManager,
        event_bus: Optional[Any] = None,
        parent: QWidget = None
    ):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = event_bus or get_event_bus()
        
        # Initialize permission cache
        self._permission_cache = PermissionCache(
            user_id=str(user_info.get("id", "")),
            api_client=self._auth_manager._api_client if hasattr(self._auth_manager, '_api_client') else None,
            token_store=self._auth_manager._token_store
        )
        
        # Dashboard state
        self._widgets: Dict[str, QWidget] = {}
        self._layout_config: Optional[dict] = None
        self._is_rtl = True
        
        # Set up UI
        self.setLayoutDirection(Qt.RightToLeft)
        self._setup_ui()
        
        # Load user-specific dashboard configuration
        self._load_dashboard_config()
        
        # Connect signals
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the dashboard user interface."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header bar
        self._create_header(main_layout)
        
        # Main content area - grid layout for widgets
        self._widget_area = QWidget()
        self._widget_area.setLayout(QGridLayout())
        self._widget_area.layout().setHorizontalSpacing(10)
        self._widget_area.layout().setVerticalSpacing(10)
        self._widget_area.layout().setContentsMargins(10, 10, 10, 10)
        
        main_layout.addWidget(self._widget_area, 1)  # Stretch factor 1
        
        # Initialize default dashboard
        self._reload_widgets()
    
    def _create_header(self, parent_layout: QVBoxLayout):
        """Create the dashboard header with user info and settings."""
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet("""
            QWidget {
                background-color: #F7F9FA;
                border-bottom: 1px solid #E2E8F0;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(15, 0, 15, 0)
        header_layout.setSpacing(15)
        
        # User avatar/profile
        user_name = QLabel(self._user_info.get("display_name", "کاربر"))
        user_name.setFont(QFont("Vazirmatn", 14, QFont.Bold))
        user_name.setStyleSheet("color: #1A202C;")
        
        # Simple avatar placeholder
        avatar_label = QLabel("ا")
        avatar_label.setFixedSize(40, 40)
        avatar_label.setAlignment(Qt.AlignCenter)
        avatar_label.setStyleSheet("""
            QLabel {
                background-color: #EDF2F7;
                border-radius: 20px;
                font-weight: bold;
                color: #4A5568;
            }
        """)
        
        header_layout.addWidget(avatar_label)
        header_layout.addWidget(user_name)
        header_layout.addStretch()
        
        # Notifications indicator (simplified)
        notif_indicator = QLabel("✉")
        notif_indicator.setStyleSheet("""
            QLabel {
                background-color: #EDF2F7;
                border: 2px solid #ED8936;
                border-radius: 10px;
                min-width: 20px;
                min-height: 20px;
            }
        """)
        notif_indicator.setFixedSize(24, 24)
        
        header_layout.addWidget(notif_indicator)
        
        parent_layout.addWidget(header)
    
    def _load_dashboard_config(self):
        """Load dashboard layout configuration for the user."""
        # In a full implementation, this would fetch from API
        # For now, use a default configuration
        self._layout_config = {
            "blocks": [
                {"key": "clock", "x": 0, "y": 0, "w": 2, "h": 2, "config": {}},
                {"key": "goals_progress", "x": 2, "y": 0, "w": 6, "h": 4, "config": {}},
                {"key": "quick_actions", "x": 8, "y": 0, "w": 4, "h": 3, "config": {}},
                {"key": "recent_activity", "x": 0, "y": 4, "w": 12, "h": 3, "config": {}},
            ]
        }
    
    def _reload_widgets(self):
        """Reload widgets based on configuration."""
        # Clear existing widgets
        self._clear_widgets()
        
        if not self._layout_config:
            return
        
        config = self._layout_config.get("blocks", [])
        grid = self._widget_area.layout()
        
        for block_config in config:
            self._add_widget_block(block_config, grid)
    
    def _clear_widgets(self):
        """Remove all widgets from the grid."""
        grid = self._widget_area.layout()
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        
        self._widgets.clear()
    
    def _add_widget_block(self, config: dict, grid_layout):
        """Add a widget block to the dashboard grid."""
        block_key = config.get("key", "clock")
        position_x = config.get("x", 0)
        position_y = config.get("y", 0)
        width = config.get("w", 4)
        height = config.get("h", 4)
        block_config = config.get("config", {})
        
        # Create widget based on key
        widget = self._create_widget(block_key, block_config)
        if widget is None:
            return
        
        # Set widget size in grid (grid is 12 columns max)
        grid_layout.addWidget(widget, position_y, position_x, height, width)
        
        # Store reference
        self._widgets[block_key] = widget
    
    def _create_widget(self, block_key: str, config: dict) -> Optional[QWidget]:
        """Factory method to create widget instances."""
        from desktop.app.widgets.clock_widget import ClockWidget
        from desktop.app.widgets.tag_chip import TagChip
        
        if block_key == "clock":
            return ClockWidget(
                cfg=config.get("cfg", {
                    "show_jalali": True,
                    "show_gregorian": True,
                    "show_seconds": True,
                    "opacity": 0.95
                }),
                style=config.get("style", {
                    "bg": "#1A202C",
                    "fg": "#EDF2F7",
                    "font_family": "Vazirmatn",
                    "font_size": 14,
                    "opacity": 0.95
                })
            )
        elif block_key == "goals_progress":
            from desktop.app.views.dashboard.goals_widget import GoalsProgressWidget
            return GoalsProgressWidget(
                user_info=self._user_info,
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "quick_actions":
            from desktop.app.widgets.quick_actions import QuickActionsWidget
            return QuickActionsWidget(
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "recent_activity":
            from desktop.app.widgets.recent_activity import RecentActivityWidget
            return RecentActivityWidget(
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "tags":
            from desktop.app.widgets.tag_cloud import TagCloudWidget
            return TagCloudWidget(
                config=config
            )
        
        # Default: clock widget
        return ClockWidget(
            cfg=config.get("cfg", {
                "show_jalali": True,
                "show_gregorian": True,
                "show_seconds": True,
                "opacity": 0.95
            }),
            style=config.get("style", {
                "bg": "#1A202C",
                "fg": "#EDF2F7",
                "font_family": "Vazirmatn",
                "font_size": 14,
                "opacity": 0.95
            })
        )
    
    def _connect_signals(self):
        """Connect event bus and other signals."""
        # Connect to event bus for dashboard updates
        # e.g., goal completed -> update progress widget
        pass
    
    def update_widget(self, widget_key: str, data: dict):
        """Update a specific widget with new data."""
        if widget_key in self._widgets:
            widget = self._widgets[widget_key]
            # Dispatch update based on widget type
            if hasattr(widget, 'update_data'):
                widget.update_data(data)
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/login_window.py
## SIZE: 7731 bytes
==========================================================================================

```python
import sys
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QCheckBox, QFrame, QApplication
)
from PySide6.QtCore import Qt, QSize, Slot, Signal, QObject
from PySide6.QtGui import QFont, QPixmap, QIcon

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.token_store import TokenStore


class LoginWindow(QWidget):
    """Login window for user authentication."""
    
    # Signal emitted when login is successful with user data
    login_successful = Signal(dict)
    
    # Signal emitted when login fails with error message
    login_failed = Signal(str)
    
    def __init__(self, auth_manager: AuthManager, parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        self._token_store = self._auth_manager._token_store
        
        # Set up window
        self.setWindowTitle("ورود به سیستم")
        self.setFixedSize(400, 520)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Apply application font
        font = QFont("Vazirmatn", 11)
        self.setFont(font)
        
        # Setup UI
        self._setup_ui()
        
        # Connect auth manager signals
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the login form UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 60, 40, 60)
        
        # Title
        title_label = QLabel("ورود به سامانه")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Vazirmatn", 24, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle = QLabel("شماره ملی و رمز عبور وارد کنید")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666; margin-bottom: 30px;")
        main_layout.addWidget(subtitle)
        
        # Form layout
        form_layout = QFormLayout()
        form_layout.setHorizontalSpacing(15)
        form_layout.setVerticalSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignRight)  # RTL: labels right-aligned
        
        # Username/National ID field
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("شماره ملی یا نام کاربری")
        self.username_input.setMinimumHeight(40)
        self.username_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form_layout.setWidget(0, QForm.Label, QLabel("شماره ملی / نام کاربری:"))
        form_layout.setWidget(0, QForm.FieldRole, self.username_input)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("رمز عبور")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form_layout.setWidget(1, QForm.Label, QLabel("رمز عبور:"))
        form_layout.setWidget(1, QForm.FieldRole, self.password_input)
        
        # Remember me checkbox
        self.remember_checkbox = QCheckBox("مرا به خاطر بسپار")
        self.remember_checkbox.setChecked(True)  # Default remembered
        self.remember_checkbox.setAlignment(Qt.AlignRight)
        form_layout.setWidget(2, QForm.Label, QWidget())  # Empty label
        form_layout.setWidget(2, QForm.FieldRole, self.remember_checkbox)
        
        main_layout.addLayout(form_layout)
        
        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        divider.setStyleSheet("margin: 20px 0;")
        main_layout.addWidget(divider)
        
        # MFA note (initially hidden)
        self.mfa_note = QLabel()
        self.mfa_note.setAlignment(Qt.AlignCenter)
        self.mfa_note.setStyleSheet("color: #666; font-size: 11px; margin: 10px 0;")
        self.mfa_note.hide()
        main_layout.addWidget(self.mfa_note)
        
        # Login button
        self.login_button = QPushButton("وارد شوید")
        self.login_button.setMinimumHeight(48)
        self.login_button.setMinimumWidth(150)
        self.login_button.setDefault(True)  # Default button (Enter key)
        self.login_button.setStyleSheet("""
            QPushButton {
                font-size: 14pt;
                font-weight: bold;
                background-color: #2D3748;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4A5568;
            }
            QPushButton:pressed {
                background-color: #2D3748;
            }
        """)
        main_layout.addWidget(self.login_button, 0, Qt.AlignCenter)
        
        # Divider
        divider2 = QFrame()
        divider2.setFrameShape(QFrame.HLine)
        divider2.setFrameShadow(QFrame.Sunken)
        divider2.setStyleSheet("margin: 20px 0;")
        main_layout.addWidget(divider2)
        
        # SSO note
        sso_note = QLabel(
            "یا با حسابcompany وارد شوید:\n"
            "<a href='#'> ورود SSO/kerberos</a>"
        )
        sso_note.setAlignment(Qt.AlignCenter)
        sso_note.setOpenExternalLinks(True)
        sso_note.setStyleSheet("color: #666; font-size: 11px; margin: 10px 0;")
        main_layout.addWidget(sso_note)
        
        # Register new user link
        register_link = QLabel(
            '<a href="#">حساب کاربری ندارید؟ ثبت‌نام</a>'
        )
        register_link.setAlignment(Qt.AlignCenter)
        register_link.setOpenExternalLinks(True)
        register_link.setStyleSheet("color: #666; font-size: 11px; margin: 5px 0;")
        main_layout.addWidget(register_link)
        
        # Connect signals
        self.login_button.clicked.connect(self._on_login_clicked)
    
    @Slot()
    def _on_login_clicked(self):
        """Handle login button click."""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            self.login_failed.emit("لطفاً همه فیلدها را پر کنید.")
            return
        
        # Attempt login via auth manager
        self._auth_manager.login({
            "username": username,
            "password": password,
            "remember_me": self.remember_checkbox.isChecked()
        })
    
    @Slot(dict)
    def _handle_login_success(self, user_data: dict):
        """Handle successful login."""
        # Emit signal with user data
        self.login_successful.emit(user_data)
    
    @Slot(str)
    def _handle_login_failed(self, error_message: str):
        """Handle login failure."""
        self.login_failed.emit(error_message)
    
    @Slot(str)
    def _show_mfa_challenge(self, mfa_info: str):
        """Show MFA challenge when required."""
        self.mfa_note.setText(mfa_info)
        self.mfa_note.show()
    
    def keyPressEvent(self, event):
        """Handle keyboard events (Enter to login)."""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Raise:
            self._on_login_clicked()
        super().keyPressEvent(event)
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/main_window.py
## SIZE: 5753 bytes
==========================================================================================

```python
import sys
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QMenuBar, QStatusBar, QMessageBox, QAction
)
from PySide6.QtCore import Qt, QSize, Slot
from PySide6.QtGui import QIcon, QAction

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus, reset_event_bus
from desktop.app.views.dashboard.dashboard_view import DashboardView


class MainWindow(QMainWindow):
    """Main application window after successful login."""
    
    def __init__(self, user_info: dict, auth_manager: AuthManager, parent: QWidget = None):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = get_event_bus()
        
        # Set up window properties
        self.setWindowTitle(f"سامانه مدیریت اهداف - {user_info.get('display_name', 'کاربر')}")
        self.setMinimumSize(1024, 768)
        self.resize(1400, 900)
        
        # Enable RTL
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Set up UI
        self._setup_menu_bar()
        self._setup_central_widget()
        self._setup_status_bar()
        
        # Connect event bus signals
        self._connect_signals()
        
        # Load dashboard view
        self._load_dashboard()
    
    def _setup_menu_bar(self):
        """Set up the application menubar."""
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)  # Keep consistent across platforms
        
        # Profile menu
        profile_menu = menubar.addMenu("پروفایل")
        
        logout_action = QAction("خروج", self)
        logout_action.setShortcut("Ctrl+Q")
        logout_action.triggered.connect(self._handle_logout)
        profile_menu.addAction(logout_action)
        
        # View menu - theme toggle
        view_menu = menubar.addMenu("نمایش")
        
        # Theme action (simplified - would toggle between dark/light)
        self._theme_action = QAction("تم آفتاب", self)
        self._theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(self._theme_action)
    
    def _setup_central_widget(self):
        """Set up the central widget with the main content area."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # TODO: Add sidebar/navigation here in full implementation
        # For now, we just have the dashboard
        
        self._dashboard_view = None
    
    def _setup_status_bar(self):
        """Set up the status bar."""
        status_bar = self.statusBar()
        status_bar.showMessage("آماده است")
        
        # Show user info on status bar
        user_name = self._user_info.get("display_name", "کاربر")
        status_bar.showMessage(f"کاربر: {user_name}  |  فعال")
    
    def _connect_signals(self):
        """Connect internal signals and slots."""
        # Connect auth manager signals
        self._auth_manager.logout_completed.connect(self._on_logout)
        self._auth_manager.authentication_state_changed.connect(self._on_auth_state_changed)
    
    def _load_dashboard(self):
        """Load the dashboard view as the main content."""
        from desktop.app.views.dashboard.dashboard_view import DashboardView
        
        if self._dashboard_view:
            self.centralWidget().layout().removeWidget(self._dashboard_view)
            self._dashboard_view.deleteLater()
        
        self._dashboard_view = DashboardView(
            user_info=self._user_info,
            auth_manager=self._auth_manager,
            event_bus=self._event_bus
        )
        
        # Set dashboard as central content
        central_layout = self.centralWidget().layout()
        if central_layout is None:
            central_layout = QVBoxLayout(self.centralWidget())
            self.centralWidget().setLayout(central_layout)
        
        central_layout.addWidget(self._dashboard_view)
        central_layout.setStretch(0, 1)
    
    @Slot()
    def _handle_logout(self):
        """Handle logout action."""
        reply = QMessageBox.question(
            self,
            "تأیید خروج",
            " آیا از خروج از سیستم اطمینان دارید؟",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self._auth_manager.logout()
    
    @Slot(bool)
    def _on_auth_state_changed(self, logged_in: bool):
        """Handle authentication state changes."""
        if logged_in:
            self._load_dashboard()
            self.statusBar().showMessage(
                f"کاربر: {self._user_info.get('display_name', 'کاربر')}  |  فعال",
                0
            )
        else:
            # Switch back to login
            self.close()
            # Emit signal to show login window
    
    @Slot()
    def _on_logout(self):
        """Handle completed logout."""
        # Close main window, show login
        self.close()
    
    def _toggle_theme(self):
        """Toggle between light and dark theme."""
        # This would typically switch the QSS stylesheet
        # For now, just show a message
        QMessageBox.information(self, "تم", "تغییر تم در پیاده‌سازی pending")
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/mfa_dialog.py
## SIZE: 4162 bytes
==========================================================================================

```python
import sys
from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QDialogButtonBox, QProgressBar, QWidget
)
from PySide6.QtCore import Qt, Qt, QTimer, Slot, Signal
from PySide6.QtGui import QFont

from desktop.app.core.auth_manager import AuthManager


class MfaDialog(QDialog):
    """MFA (Multi-Factor Authentication) challenge dialog."""
    
    def __init__(self, auth_manager: AuthManager, mfa_method: str,
                 parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        self._mfa_method = mfa_method
        
        # Set up dialog
        self.setWindowTitle("اعتبارسنجی امنیتی")
        self.setFixedSize(400, 220)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Apply font
        font = QFont("Vazirmatn", 11)
        self.setFont(font)
        
        self._setup_ui()
        self._setup_mfa_specific_ui()
    
    def _setup_ui(self):
        """Set up the basic dialog UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 60, 40, 60)
        
        # Title
        title = QLabel("اعتبارسنجی امنیتی")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Vazirmatn", 18, QFont.Bold)
        title.setFont(title_font)
        main_layout.addWidget(title)
        
        # Description
        if self._mfa_method == "totp":
            desc = QLabel(
                "برای ادامه ورود، کد MFA خود را وارد کنید.\n"
                "می‌توانید از تطبيق authenticator استفاده کنید."
            )
        elif self._mfa_method == "sms":
            desc = QLabel(
                "کد MFA به شماره موبایل شما ارسال شده است."
            )
        else:  # email
            desc = QLabel(
                "کد MFA به ایمیل شما ارسال شده است."
            )
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        main_layout.addWidget(desc)
        
        # Code input
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("کد MFA را وارد کنید")
        self.code_input.setEchoMode(QLineEdit.Password)
        self.code_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.code_input.setMinimumHeight(45)
        main_layout.addWidget(self.code_input)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.setAlignment(Qt.AlignCenter)
        button_box.accepted.connect(self._on_accepted)
        button_box.rejected.connect(self.reject)
        
        # Set button text
        ok_button = button_box.button(QDialogButtonBox.Ok)
        if ok_button:
            ok_button.setText("اعتبارسنجی")
        
        main_layout.addWidget(button_box)
        
        # Set focus to code input
        self.code_input.setFocus()
        self.code_input.selectAll()
        
        # Connect signals
        self.code_input.returnPressed.connect(self._on_accepted)
    
    def _setup_mfa_specific_ui(self):
        """Method-specific setup (can be overridden)."""
        pass
    
    @Slot()
    def _on_accepted(self):
        """Handle OK button press."""
        code = self.code_input.text().strip()
        if not code:
            QMessageBox.warning(self, "هشدار", "لطفاً کد MFA را وارد کنید.")
            return
        
        # Verify MFA via auth manager
        self._auth_manager.verify_mfa(code, self._mfa_method)
    
    def set_code(self, code: str):
        """Pre-fill the code (for testing or auto-fill)."""
        self.code_input.setText(code)
        self.code_input.setSelection(0, len(code))
```

==========================================================================================
## FILE: bastehF_desktop/desktop/main.py
## SIZE: 1324 bytes
==========================================================================================

```python
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
```

==========================================================================================
