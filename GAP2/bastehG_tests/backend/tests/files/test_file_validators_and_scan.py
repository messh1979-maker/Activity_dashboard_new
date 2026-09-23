"""
tests/files/test_file_validators_and_scan.py

اجرا:
    cd backend && pytest tests/files/ -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.modules.files.db.models import Upload
from app.modules.files.services.av_scan_service import AvScanService
from app.modules.files.services.storage import StorageError
from app.modules.files.services.validators import (
    MAX_UPLOAD_SIZE_BYTES,
    FileValidationError,
    validate_extension,
    validate_magic_number_matches_extension,
    validate_size,
)


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── validators (خالص) ──────────────────────────────────────

def test_dangerous_extension_rejected():
    with pytest.raises(FileValidationError) as exc_info:
        validate_extension("resume.exe")
    assert exc_info.value.code == "DANGEROUS_FILE_TYPE"


def test_extension_not_in_whitelist_rejected():
    with pytest.raises(FileValidationError) as exc_info:
        validate_extension("archive.rar")
    assert exc_info.value.code == "EXTENSION_NOT_ALLOWED"


def test_allowed_extension_passes():
    assert validate_extension("report.PDF") == ".pdf"


def test_size_bounds():
    with pytest.raises(FileValidationError):
        validate_size(0)
    with pytest.raises(FileValidationError):
        validate_size(MAX_UPLOAD_SIZE_BYTES + 1)
    validate_size(1024)  # نباید خطا بدهد


def test_executable_renamed_as_pdf_is_caught_by_magic_number():
    """کلاسیک‌ترین حمله: فایل اجرایی با پسوند pdf."""
    exe_header = b"MZ\x90\x00\x03\x00\x00\x00"
    with pytest.raises(FileValidationError) as exc_info:
        validate_magic_number_matches_extension(exe_header, ".pdf")
    assert exc_info.value.code == "UNKNOWN_FILE_SIGNATURE"


def test_real_pdf_header_accepted():
    validate_magic_number_matches_extension(b"%PDF-1.7\nrest...", ".pdf")


def test_docx_zip_family_accepted():
    zip_header = b"PK\x03\x04" + b"\x00" * 20
    validate_magic_number_matches_extension(zip_header, ".docx")


def test_mismatched_real_signature_rejected():
    """jpeg واقعی که ادعا می‌کند png است."""
    jpeg_header = b"\xff\xd8\xff\xe0"
    with pytest.raises(FileValidationError) as exc_info:
        validate_magic_number_matches_extension(jpeg_header, ".png")
    assert exc_info.value.code == "EXTENSION_MISMATCH"


# ── AvScanService: Fail-Closed ─────────────────────────────

class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass


class FakeStorage:
    def __init__(self, header, fail_read=False):
        self.header = header
        self.fail_read = fail_read
        self.deleted = []

    def get_object_bytes(self, key, n):
        if self.fail_read:
            raise StorageError("boom")
        return self.header

    def delete_object(self, key):
        self.deleted.append(key)


def make_upload(**kw):
    defaults = dict(id=uuid4(), uploader_id=uuid4(), object_key="k", original_name="doc.pdf", size_bytes=100)
    defaults.update(kw)
    return Upload(**defaults)


@run_async
async def test_scan_is_fail_closed_when_clamav_not_installed():
    """طبق pip list پروژه‌ی شما: pyclamd نصب نیست — پس هیچ فایلی نباید
    هرگز به‌طور خودکار 'clean' علامت بخورد."""
    upload = make_upload(original_name="doc.pdf")
    storage = FakeStorage(header=b"%PDF-1.7 ...")
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "error"
    assert upload.is_available is False


@run_async
async def test_signature_mismatch_marks_infected_and_deletes_object():
    upload = make_upload(original_name="evil.pdf")
    storage = FakeStorage(header=b"MZ\x90\x00\x03\x00\x00\x00")  # PE header
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "infected"
    assert upload.is_available is False
    assert "k" in storage.deleted


@run_async
async def test_storage_read_failure_is_fail_closed():
    upload = make_upload()
    storage = FakeStorage(header=b"", fail_read=True)
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "error"
    assert upload.is_available is False
