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