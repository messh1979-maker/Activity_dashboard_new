"""WebSocket gateway (architecture ADR-05, sections 8.1, 12.8).

Exposes ``/ws/chat`` and ``/ws/notifications`` plus the connection
manager wired to the configurable Redis primary key.
"""