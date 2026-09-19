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