"""
app/modules/files/services/validators.py

منطق خالص اعتبارسنجی فایل — طبق سند: «Whitelist گسترده (نه Blacklist)»
و «بررسی Magic Number، نه فقط پسوند». عمداً بدون وابستگی به
S3/ClamAV نوشته شده تا کاملاً آفلاین و سریع تست شود؛ چیزی که واقعاً
شبکه لازم دارد (اسکن ClamAV) در ``av_scan_service.py`` است.

⚠️ اگر پکیج ``python-magic`` نصب باشد، تشخیص دقیق‌تری ممکن است؛ این
فایل به‌صورت fallback از امضای بایت اول («magic number») برای
پرمصرف‌ترین انواع فایل در یک محیط اداری/کارتابلی استفاده می‌کند.
برای فرمت‌های نادرتر، ``python-magic`` را نصب و در ``av_scan_service.py``
جایگزین کنید.
"""

from __future__ import annotations

# طبق سند: «Whitelist گسترده» — لیست پسوند/mime مجاز، نه ممنوع
ALLOWED_EXTENSIONS: dict[str, str] = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".zip": "application/zip",  # طبق سند: آرشیوها فقط با whitelist داخلی مجازند
}

# پسوندهای اجراپذیر/اسکریپتی — حتی اگر کسی به‌اشتباه به ALLOWED_EXTENSIONS
# اضافه کند، این لیست همیشه رد می‌شود (دفاع لایه‌ی دوم).
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".msi",
    ".js", ".vbs", ".jar", ".com", ".scr", ".apk",
}

MAX_UPLOAD_SIZE_BYTES = 52_428_800  # ۵۰ مگابایت

# امضای بایت اول («magic number») برای رایج‌ترین انواع — RFC/مستندات فرمت‌ها
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # نیاز به بررسی بیشتر بایت ۸ تا ۱۱ برای "WEBP" دارد؛ ساده‌سازی شده
    (b"PK\x03\x04", "application/zip"),  # zip، docx، xlsx، pptx همه با این شروع می‌شوند (OOXML = zip)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),  # doc/xls/ppt قدیمی (OLE2)
]


class FileValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def validate_extension(filename: str) -> str:
    """پسوند را برمی‌گرداند اگر مجاز باشد، وگرنه خطا می‌دهد."""
    ext = _extract_extension(filename)
    if ext in DANGEROUS_EXTENSIONS:
        raise FileValidationError("DANGEROUS_FILE_TYPE", f"پسوند {ext} مجاز نیست.")
    if ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError("EXTENSION_NOT_ALLOWED", f"پسوند {ext} در فهرست مجاز نیست.")
    return ext


def validate_size(size_bytes: int) -> None:
    if size_bytes <= 0:
        raise FileValidationError("EMPTY_FILE", "فایل خالی است.")
    if size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise FileValidationError(
            "FILE_TOO_LARGE",
            f"حجم فایل بیش از حد مجاز است (حداکثر {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} مگابایت).",
        )


def sniff_mime_from_header(header_bytes: bytes) -> str | None:
    """اولین چند بایت فایل را با امضاهای شناخته‌شده مقایسه می‌کند."""
    for signature, mime in _MAGIC_SIGNATURES:
        if header_bytes.startswith(signature):
            return mime
    return None


def validate_magic_number_matches_extension(header_bytes: bytes, extension: str) -> None:
    """طبق سند: «بررسی Magic Number، نه فقط پسوند» — جلوی فایل اجرایی
    تغییرنام‌یافته به .pdf را می‌گیرد.

    برای فرمت‌های OOXML/OLE2 (docx/xlsx/doc/xls/zip) بررسی سخت‌گیرانه‌تر
    (باز کردن zip و چک کردن ساختار داخلی) بهتر است؛ اینجا فقط سطح
    امضای بایت اول چک می‌شود — کافی برای رد کردن اکثر تلاش‌های ساده‌ی
    جعل، نه یک ضدعفونی‌کننده‌ی کامل (آن کار ClamAV در av_scan_service است).
    """
    detected = sniff_mime_from_header(header_bytes)
    expected = ALLOWED_EXTENSIONS.get(extension)

    if detected is None:
        # فرمت‌های متنی ساده (txt, csv) امضای بایتی مشخصی ندارند — عبور می‌کنند
        if extension in (".txt", ".csv"):
            return
        raise FileValidationError(
            "UNKNOWN_FILE_SIGNATURE",
            "محتوای فایل با هیچ‌کدام از فرمت‌های شناخته‌شده مطابقت ندارد.",
        )

    # zip-family (docx/xlsx/pptx/zip) و OLE2-family (doc/xls/ppt) چندتایی هستند
    zip_family = {".zip", ".docx", ".xlsx", ".pptx"}
    ole_family = {".doc", ".xls", ".ppt"}
    if extension in zip_family and detected == "application/zip":
        return
    if extension in ole_family and detected == "application/x-ole-storage":
        return
    if detected != expected:
        raise FileValidationError(
            "EXTENSION_MISMATCH",
            f"پسوند فایل ({extension}) با محتوای واقعی آن ({detected}) هم‌خوانی ندارد.",
        )


def _extract_extension(filename: str) -> str:
    idx = filename.rfind(".")
    if idx == -1:
        return ""
    return filename[idx:].lower()
