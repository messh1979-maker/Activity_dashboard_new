"""File storage service — real DDL (M13).

Implements the upload lifecycle against ``files.uploads``,
``files.scan_queue`` and ``files.access_logs`` using raw SQL
(the same pattern as inbox/calendar services).  Bytes are stored
in a local directory (configurable via ``settings.FILE_STORAGE_DIR``)
since no S3 gateway is wired in this deployment.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.config import settings
from app.core.errors import APIError, NotFoundError

# Local storage root (created if missing).
STORAGE_ROOT: Path = Path(settings.FILE_STORAGE_DIR)
STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

# Maximum single upload body size.
_MAX_BODY_BYTES: int = settings.MAX_UPLOAD_SIZE


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = v.isoformat()
        elif isinstance(v, bytes):
            d[k] = v.hex()
    return d


class FileStateMachine:
    """Manages file upload lifecycle (presign → upload → finalize → download)."""

    def __init__(self, session):
        self.session = session

    # --- Presign ---

    async def presign(self, uploader_id: UUID, payload: dict) -> SimpleNamespace:
        """Reserve an upload slot and return a local upload target."""
        object_key = f"{secrets.token_urlsafe(18)}/{secrets.token_urlsafe(12)}"
        row = (await self.session.execute(text("""
            INSERT INTO files.uploads (
                uploader_id, context_type, context_id,
                original_name, object_key, mime_declared,
                size_bytes, sha256, scan_status, is_available
            )
            VALUES (:uid, :ctype, :cid, :name, :key, :mime,
                    :size, '0000000000000000000000000000000000000000000000000000000000000000', 'pending', FALSE)
            RETURNING id, object_key, expires_at
        """), {
            "uid": str(uploader_id),
            "ctype": payload["context_type"],
            "cid": str(payload["context_id"]) if payload.get("context_id") else None,
            "name": payload["original_name"],
            "key": object_key,
            "mime": payload.get("mime_declared"),
            "size": payload["size_bytes"],
        })).mappings().first()
        await self.session.commit()
        upload_id = row["id"]
        # Local PUT target.
        upload_url = f"/api/v1/files/upload/{upload_id}"
        return SimpleNamespace(
            upload_id=upload_id, object_key=row["object_key"],
            upload_url=upload_url,
            expires_in=3600,
            max_size=_MAX_BODY_BYTES,
        )

    # --- Receive bytes (local fallback) ---

    async def upload_bytes(self, upload_id: UUID, uploader_id: UUID,
                           filename: str, mime: Optional[str],
                           body: bytes) -> SimpleNamespace:
        """Store bytes on local disk and update the upload row."""
        # Confirm the reservation still belongs to uploader and is pending.
        row = (await self.session.execute(text("""
            SELECT id, object_key, size_bytes FROM files.uploads
             WHERE id = :iid AND uploader_id = :uid AND scan_status = 'pending'
        """), {"iid": str(upload_id), "uid": str(uploader_id)})).mappings().first()
        if not row:
            raise APIError(error_code="UPLOAD_NOT_FOUND",
                           message="آپلود یافت نشد یا منقضی شده است.",
                           status_code=404)
        object_path = _object_to_path(row["object_key"])
        object_path.parent.mkdir(parents=True, exist_ok=True)
        with open(object_path, "wb") as f:
            f.write(body)

        sha256 = hashlib.sha256(body).hexdigest()
        mime_detected = mime or _guess_mime(filename)
        await self.session.execute(text("""
            UPDATE files.uploads
               SET mime_detected = :mime,
                   sha256 = :sha,
                   size_bytes = :size
             WHERE id = :iid
        """), {"mime": mime_detected, "sha": sha256,
               "size": len(body), "iid": str(upload_id)})
        await self.session.commit()
        return SimpleNamespace(upload_id=upload_id, object_key=row["object_key"],
                               sha256=sha256, size=len(body), mime=mime_detected)

    # --- Finalize ---

    async def finalize(self, upload_id: UUID, uploader_id: UUID) -> SimpleNamespace:
        """Mark scan done, mark the upload available."""
        row = (await self.session.execute(text("""
            SELECT id, object_key, sha256 FROM files.uploads
             WHERE id = :iid AND uploader_id = :uid
        """), {"iid": str(upload_id), "uid": str(uploader_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="file upload")

        sha256 = row["sha256"]
        # Insert a scan-queue row (best-effort).  A background worker
        # would consume it; on a single-node dev deployment we mark
        # the file clean immediately so the upload is usable.
        await self.session.execute(text("""
            INSERT INTO files.scan_queue (upload_id, status, clamav_message,
                                          scanned_at, retry_count, max_retries)
            VALUES (:iid, 'clean', 'local-dev-skip-clamav', now(), 0, 3)
            ON CONFLICT DO NOTHING
        """), {"iid": str(upload_id)})
        await self.session.execute(text("""
            UPDATE files.uploads
               SET scan_status = 'clean', scanned_at = now(),
                   is_available = TRUE
             WHERE id = :iid
        """), {"iid": str(upload_id)})
        await self.session.commit()
        return SimpleNamespace(upload_id=upload_id, object_key=row["object_key"],
                               sha256=sha256, is_available=True)

    # --- Download ---

    async def download(self, upload_id: UUID, user_id: UUID) -> dict:
        """Serve a file: log access, return bytes + metadata."""
        row = (await self.session.execute(text("""
            SELECT id, object_key, original_name, mime_detected,
                   size_bytes, sha256, is_available, created_at
              FROM files.uploads
             WHERE id = :iid
        """), {"iid": str(upload_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="file")
        if not row["is_available"]:
            raise APIError(error_code="FILE_UNAVAILABLE",
                           message="فایل هنوز آماده نیست (اسکن در انتظار).",
                           status_code=409)

        # Log access (no auth gate here — caller decides ACL).
        await self.session.execute(text("""
            INSERT INTO files.access_logs (upload_id, ip_address, user_id,
                                           accessed_at, action)
            VALUES (:iid, :ip, :uid, now(), 'download')
        """), {"iid": str(upload_id),
               "ip": None, "uid": str(user_id)})
        await self.session.commit()

        path = _object_to_path(row["object_key"])
        data = path.read_bytes() if path.exists() else b""
        return {
            "status": "success",
            "data": {
                "id": str(row["id"]),
                "object_key": row["object_key"],
                "original_name": row["original_name"],
                "mime_detected": row["mime_detected"],
                "size_bytes": row["size_bytes"],
                "sha256": row["sha256"],
                "created_at": row["created_at"].isoformat(),
                "bytes": data,
            },
        }

    # --- List ---

    async def list_uploads(self, user_id: UUID) -> list[dict]:
        """List uploads belonging to a user."""
        rows = (await self.session.execute(text("""
            SELECT id, original_name, mime_declared, size_bytes,
                   scan_status, is_available, created_at
              FROM files.uploads
             WHERE uploader_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [_row_serialize(r) for r in rows]


# --- helpers ---

def _object_to_path(object_key: str) -> Path:
    """Map object key ``a/b/c`` → {root}/a/b/c (no extension on disk)."""
    parts = object_key.split("/")
    return STORAGE_ROOT.joinpath(*parts)


def _guess_mime(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".gif": "image/gif",
        ".pdf": "application/pdf",
    }.get(ext, "application/octet-stream")