"""File storage module API routes (real DDL, M13).

Local-disk implementation: presign reserves a row in ``files.uploads``,
PUT /upload/{id} stores bytes under `FILE_STORAGE_DIR`, finalize marks
the file scanned + available, GET /{id}/download returns the bytes and
logs access in ``files.access_logs``.

This replaces the S3-oriented patch (boto3/MinIO required) because this
deployment has no object storage; the DDL and access_logging contract
are preserved.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Body
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.files.ports import (
    PresignUpload, PresignResponse, UploadFinalize,
)
from app.modules.files.services.files_service import FileStateMachine
from app.core.config import settings


router = APIRouter(prefix="/files", tags=["files"])


@router.post("/presign", response_model=dict)
async def presign_upload(
    payload: PresignUpload,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Reserve an upload slot and return the local PUT target."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            p = await svc.presign(user_id, payload.model_dump())
            return {"status": "success",
                    "data": PresignResponse(
                        upload_id=p.upload_id, object_key=p.object_key,
                        upload_url=p.upload_url, expires_in=p.expires_in,
                        max_size=p.max_size).model_dump()}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/upload/{upload_id}", response_model=dict)
async def upload_file(
    upload_id: UUID = Path(...),
    original_name: str = Query(...),
    mime: Optional[str] = Query(None),
    user_id: UUID = Depends(get_current_user),
    body: bytes = Body(...),
    db_session=Depends(get_db_session),
):
    """Receive file bytes locally (the presigned PUT target)."""
    if len(body) > settings.MAX_UPLOAD_SIZE:
        return JSONResponse(status_code=413,
                            content={"error": "FILE_TOO_LARGE",
                                     "message": "فایل بزرگ‌تر از حد مجاز است.",
                                     "success": False})
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            result = await svc.upload_bytes(upload_id, user_id,
                                            original_name, mime, body)
            return {"status": "uploaded",
                    "upload_id": str(result.upload_id),
                    "object_key": result.object_key,
                    "sha256": result.sha256,
                    "size": result.size}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/{upload_id}/finalize", response_model=dict)
async def finalize_upload(
    upload_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    finalize: UploadFinalize = Body(...),
    db_session=Depends(get_db_session),
):
    """Finalize the upload (mark scanned + available)."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            result = await svc.finalize(upload_id, user_id)
            return {"status": "finalized",
                    "upload_id": str(result.upload_id),
                    "is_available": result.is_available}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/{upload_id}/download", response_model=dict)
async def download_file(
    upload_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Download a file (metadata + bytes via access_logs)."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            return await svc.download(upload_id, user_id)
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("", response_model=dict)
async def list_uploads(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List uploads created by the caller."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            items = await svc.list_uploads(user_id)
            return {"status": "success", "data": items}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})