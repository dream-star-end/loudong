"""Tests for artifact storage."""

import os
import tempfile

from vulnhunter.tools.artifact import ArtifactStore


class TestArtifactStore:
    def test_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore(base_dir=tmpdir)
            data = b"screenshot data here"
            path = store.save("test_screenshot.png", data)
            assert os.path.exists(path)
            loaded = store.load("test_screenshot.png")
            assert loaded == data

    def test_list_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore(base_dir=tmpdir)
            store.save("a.png", b"aaa")
            store.save("b.har", b"bbb")
            items = store.list_artifacts()
            assert "a.png" in items
            assert "b.har" in items
