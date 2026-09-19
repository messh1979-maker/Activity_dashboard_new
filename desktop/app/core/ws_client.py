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