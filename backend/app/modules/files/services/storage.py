"""
app/modules/files/services/storage.py

Wrapper نازک روی S3/MinIO — طبق سند («Presigned URL»، «Object Storage
(MinIO/S3)»). `boto3` در `pip list` شما نصب نیست، پس import تنبل است.

نصب لازم:
    pip install boto3

⚠️ تنظیمات لازم (به app/core/config.py اضافه کنید):
    FILES_S3_ENDPOINT_URL   # برای MinIO؛ برای AWS S3 واقعی خالی بگذارید
    FILES_S3_BUCKET
    FILES_S3_ACCESS_KEY
    FILES_S3_SECRET_KEY
    FILES_S3_REGION = "us-east-1"  # MinIO هم این را می‌خواهد، هرچه باشد کافی است
"""

from __future__ import annotations

from typing import Any


class StorageError(Exception):
    pass


class ObjectStorageClient:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise StorageError("`boto3` نصب نیست — `pip install boto3` را اجرا کنید.") from exc

        self._client = boto3.client(
            "s3",
            endpoint_url=getattr(self.settings, "FILES_S3_ENDPOINT_URL", None) or None,
            aws_access_key_id=self.settings.FILES_S3_ACCESS_KEY,
            aws_secret_access_key=self.settings.FILES_S3_SECRET_KEY,
            region_name=getattr(self.settings, "FILES_S3_REGION", "us-east-1"),
            config=Config(signature_version="s3v4"),
        )
        return self._client

    def presigned_put_url(self, object_key: str, content_type: str, expires_seconds: int = 300) -> str:
        client = self._get_client()
        return client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.settings.FILES_S3_BUCKET,
                "Key": object_key,
                "ContentType": content_type,
            },
            ExpiresIn=expires_seconds,
        )

    def presigned_get_url(self, object_key: str, download_filename: str, expires_seconds: int = 60) -> str:
        client = self._get_client()
        return client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.settings.FILES_S3_BUCKET,
                "Key": object_key,
                # طبق سند: Content-Disposition: attachment (هرگز inline برای فایل کاربر)
                "ResponseContentDisposition": f'attachment; filename="{download_filename}"',
                "ResponseContentType": "application/octet-stream",  # هرگز mime کلاینت را معتبر ندانید
            },
            ExpiresIn=expires_seconds,
        )

    def get_object_bytes(self, object_key: str, max_bytes: int) -> bytes:
        """برای اسکن AV — فقط تا ``max_bytes`` اول را می‌خواند (کافی برای magic number)."""
        client = self._get_client()
        response = client.get_object(
            Bucket=self.settings.FILES_S3_BUCKET, Key=object_key,
            Range=f"bytes=0-{max_bytes - 1}",
        )
        return response["Body"].read()

    def delete_object(self, object_key: str) -> None:
        client = self._get_client()
        client.delete_object(Bucket=self.settings.FILES_S3_BUCKET, Key=object_key)
