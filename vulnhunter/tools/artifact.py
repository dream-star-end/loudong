"""Artifact storage tool — manages screenshots, HARs, traces, and request/response archives."""

import logging
import os

logger = logging.getLogger(__name__)

ARTIFACT_DIR = os.environ.get("VULNHUNTER_ARTIFACT_DIR", "/tmp/vulnhunter_artifacts")


class ArtifactStore:
    """Local filesystem artifact store (MinIO/S3 adapter in production)."""

    def __init__(self, base_dir: str = ARTIFACT_DIR) -> None:
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def save(self, name: str, data: bytes) -> str:
        path = os.path.join(self.base_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        logger.info("Artifact saved: %s (%d bytes)", path, len(data))
        return path

    def load(self, name: str) -> bytes:
        path = os.path.join(self.base_dir, name)
        with open(path, "rb") as f:
            return f.read()

    def list_artifacts(self) -> list[str]:
        return os.listdir(self.base_dir)
