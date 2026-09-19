import json
import time
import hashlib
import hmac
import uuid as uuid_mod
from pathlib import Path
from typing import Optional, Dict, Any, Callable

import httpx

from desktop.app.core.device_identity import get_device_identity, _normalize_mac


class DeviceIdentity:
    """Holds the device's identity information for API headers."""
    
    def __init__(self):
        self.mac_address: str | None = None
        self.mac_source: str | None = None
        self.fingerprint: str = ""
        self.hmac_key: bytes | None = None
        self.platform: str = "desktop"
        self.os_info: str = platform.system() + " " + platform.release()
    
    def refresh(self):
        """Refresh the device identity (MAC, fingerprint, HMAC key)."""
        mac, source = get_primary_mac()
        self.mac_address = mac
        self.mac_source = source
        self.fingerprint = get_system_fingerprint()
        
        # Generate a per-device HMAC key (derived from fingerprint)
        # In a real implementation, this would be securely stored/exchanged
        self.hmac_key = hashlib.sha256(
            (self.fingerprint + mac if mac else self.fingerprint).encode()
        ).digest()


class TokenStore:
    """Secure token storage using platform-specific keyring."""
    
    def __init__(self):
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expires_at: float = 0.0
        self._device_identity = DeviceIdentity()
        self._device_identity.refresh()
    
    @property
    def access_token(self) -> str | None:
        return self._access_token
    
    @access_token.setter
    def access_token(self, token: str):
        self._access_token = token
        # Save to platform keyring
        try:
            import keyring
            keyring.set_password("planner_desktop", "access_token", token)
        except Exception:
            pass  # keyring not available, in-memory only
    
    @property
    def refresh_token(self) -> str | None:
        return self._refresh_token
    
    @refresh_token.setter
    def refresh_token(self, token: str):
        self._refresh_token = token
        try:
            import keyring
            keyring.set_password("planner_desktop", "refresh_token", token)
        except Exception:
            pass
    
    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None and time.time() < self._token_expires_at
    
    def clear_tokens(self):
        """Clear all tokens and notify auth manager."""
        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = 0.0
        try:
            import keyring
            keyring.delete_password("planner_desktop", "access_token")
            keyring.delete_password("planner_desktop", "refresh_token")
        except Exception:
            pass


class ApiClient(httpx.Client):
    """HTTP client with automatic device header injection and auth support."""
    
    def __init__(self, base_url: str = "https://api.corp.local/api/v1",
                 token_store: Optional[TokenStore] = None):
        super().__init__(
            base_url=base_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=True,  # Verify TLS certificates
            http2=True,
        )
        self._token_store = token_store or TokenStore()
        self._identity = self._token_store._device_identity
        # Register response hook for auth handling
        self._hooks = {"response": [self._on_response]}
        # Replace hooks - need to merge
        original_hooks = self._hooks
        self._hooks = {"response": []}
        for hook_list in original_hooks.values():
            for h in hook_list:
                self._hooks["response"].append(h)
        # Actually, httpx hooks work differently - let's use __enter__ hook pattern
        # We'll set headers per-request instead
    
    def _get_device_headers(self, method: str, path: str, body: bytes = b"") -> Dict[str, str]:
        """Generate device authentication headers for the request."""
        identity = self._identity
        fp = identity.fingerprint
        mac = identity.mac_address
        mac_source = identity.mac_source
        ts = str(int(time.time() * 1000))
        nonce = str(uuid_mod.uuid4())
        
        # Body hash for signature
        body_hash = hashlib.sha256(body).hexdigest()
        
        # Build the signature payload
        # Note: For desktop, we use HMAC with the device's key
        # For web, this would use the device token from cookie
        payload = "|".join([
            method.upper(),
            path,
            body_hash,
            fp,
            mac or "",
            nonce,
            ts,
        ])
        
        # Compute HMAC signature
        key = identity.hmac_key or hashlib.sha256(fp.encode()).digest()
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        
        headers = {
            "X-Device-Fingerprint": fp,
            "X-Device-Nonce": nonce,
            "X-Device-Timestamp": ts,
            "X-Device-Signature": sig,
            "X-Request-ID": str(uuid_mod.uuid4()),
            "Content-Type": "application/json",
        }
        
        # Only add MAC header if MAC is available (desktop)
        # Web clients should NOT send MAC (it would be NULL/fake)
        if mac and identity.mac_source == "psutil":
            headers["X-Device-MAC"] = mac
            headers["X-Device-MAC-Source"] = mac_source
        
        return headers
    
    def _on_response(self, response: httpx.Response) -> None:
        """Hook to handle auth-related responses (401 -> refresh)."""
        if response.status_code == 401 and not getattr(response, '_retried', False):
            response._retried = True
            # Try to refresh token
            if self._token_store.refresh():
                # Retry the request with new token
                # Note: In a full implementation, we'd need the original request info
                pass  # Simplified for this example
    
    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Override request to inject device headers."""
        # Extract body if present
        body = kwargs.get("content", b"")
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        
        # Get path from URL
        # URL could be absolute or relative
        path = url
        if not url.startswith(("http://", "https://")):
            # It's a relative path - extract from full URL if base_url set
            # For simplicity, assume full URL or construct properly
            pass
        
        headers = self._get_device_headers(method, path, body)
        
        # Add auth header if we have a token
        if self._token_store.access_token:
            headers["Authorization"] = f"Bearer {self._token_store.access_token}"
        
        # Remove content from kwargs if we already handled it
        kwargs.pop("content", None)
        kwargs["headers"] = headers
        kwargs["timeout"] = self.timeout
        
        return super().request(method, url, content=body, **kwargs)
    
    def enable_auto_refresh(self, on_refresh_failed: Callable = None):
        """Enable automatic token refresh on 401 responses."""
        # This is handled via response hooks
        original_hooks = self._hooks.get("response", [])
        
        def hooked_response(response):
            if response.status_code == 401 and not getattr(response, '_retried', False):
                response._retried = True
                if self._token_store.refresh():
                    # Retry with new token
                    path = response.url.path
                    method = response.method
                    body = response.request.content if hasattr(response.request, 'content') else b""
                    return self.request(method, response.url.path, content=body)
            return response
        
        self._hooks.setdefault("response", []).append(hooked_response)


# Convenience function for quick requests
def quick_get(url: str, token_store: TokenStore, **kwargs) -> httpx.Response:
    """Quick GET request with auth."""
    client = ApiClient(token_store=token_store)
    headers = kwargs.pop("headers", {})
    headers.update({"X-Device-Fingerprint": token_store._identity.fingerprint})
    kwargs["headers"] = headers
    return client.get(url, **kwargs)


def quick_post(url: str, json_body: dict, token_store: TokenStore, **kwargs) -> httpx.Response:
    """Quick POST request with auth and JSON body."""
    client = ApiClient(token_store=token_store)
    headers = kwargs.pop("headers", {})
    headers.update({"X-Device-Fingerprint": token_store._identity.fingerprint})
    kwargs["headers"] = headers
    kwargs["json"] = json_body
    return client.post(url, **kwargs)