"""Artifact storage — MinIO-backed with local filesystem fallback.

Manages screenshots, HAR files, request/response archives, DOM snapshots.
"""

import logging
import os

from vulnhunter.config import settings

logger = logging.getLogger(__name__)

ARTIFACT_DIR = os.environ.get("VULNHUNTER_ARTIFACT_DIR", "/tmp/vulnhunter_artifacts")


class ArtifactStore:
    """Stores evidence artifacts. Uses MinIO when available, local FS as fallback."""

    def __init__(self) -> None:
        self._minio_client = None
        self.base_dir = ARTIFACT_DIR
        os.makedirs(self.base_dir, exist_ok=True)
        self._init_minio()

    def _init_minio(self) -> None:
        try:
            from miniopy_async import Minio
            self._minio_client = Minio(
                settings.minio_endpoint,
                access_key=settings.minio_access_key,
                secret_key=settings.minio_secret_key,
                secure=False,
            )
            logger.info("MinIO client initialized: %s", settings.minio_endpoint)
        except Exception as e:
            logger.warning("MinIO not available, using local FS: %s", e)
            self._minio_client = None

    async def save(self, name: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        local_path = os.path.join(self.base_dir, name)
        with open(local_path, "wb") as f:
            f.write(data)

        if self._minio_client:
            try:
                import io
                bucket = settings.minio_bucket
                if not await self._minio_client.bucket_exists(bucket):
                    await self._minio_client.make_bucket(bucket)
                await self._minio_client.put_object(
                    bucket, name, io.BytesIO(data), len(data), content_type=content_type,
                )
                url = f"http://{settings.minio_endpoint}/{bucket}/{name}"
                logger.info("Artifact uploaded to MinIO: %s", url)
                return url
            except Exception as e:
                logger.warning("MinIO upload failed, using local path: %s", e)

        logger.info("Artifact saved locally: %s (%d bytes)", local_path, len(data))
        return local_path

    def save_sync(self, name: str, data: bytes) -> str:
        path = os.path.join(self.base_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def load(self, name: str) -> bytes:
        path = os.path.join(self.base_dir, name)
        with open(path, "rb") as f:
            return f.read()

    def list_artifacts(self) -> list[str]:
        return os.listdir(self.base_dir)
