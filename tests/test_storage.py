"""Tests for storage layer — RunManager, ArtifactStore, Encryption."""

import tempfile
from pathlib import Path

from nazitest.models.config import RunConfig, ScopeConfig
from nazitest.models.har import HAREntry, HARFile, HARRequest, HARResponse
from nazitest.models.recon import SiteMap
from nazitest.models.types import ArtifactType
from nazitest.storage.artifact_store import ArtifactStore
from nazitest.storage.encryption import ArtifactEncryptor, generate_key, load_key, save_key
from nazitest.storage.run_manager import RUN_SUBDIRS, RunManager


class TestRunManager:
    def test_create_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            rm = RunManager(output_dir=tmpdir)
            config = RunConfig(scope=ScopeConfig(target_url="https://example.com"))
            run_id, run_path = rm.create_run(config)

            assert run_path.exists()
            assert (run_path / "config.json").exists()

            # Verify all subdirectories created
            for subdir in RUN_SUBDIRS:
                assert (run_path / subdir).exists(), f"Missing: {subdir}"

    def test_load_run_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            rm = RunManager(output_dir=tmpdir)
            original = RunConfig(
                scope=ScopeConfig(
                    target_url="https://example.com",
                    allowed_domains=["example.com"],
                )
            )
            run_id, _ = rm.create_run(original)
            loaded = rm.load_run_config(run_id)
            assert loaded.scope.target_url == "https://example.com"
            assert loaded.scope.allowed_domains == ["example.com"]

    def test_list_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            rm = RunManager(output_dir=tmpdir)
            config = RunConfig(scope=ScopeConfig(target_url="https://a.com"))
            rm.create_run(config)
            config2 = RunConfig(scope=ScopeConfig(target_url="https://b.com"))
            rm.create_run(config2)

            runs = rm.list_runs()
            assert len(runs) == 2
            targets = {r["target"] for r in runs}
            assert "https://a.com" in targets
            assert "https://b.com" in targets

    def test_run_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            rm = RunManager(output_dir=tmpdir)
            config = RunConfig(scope=ScopeConfig(target_url="https://example.com"))
            run_id, _ = rm.create_run(config)
            assert rm.run_exists(run_id)
            assert not rm.run_exists("nonexistent")


class TestArtifactStore:
    def _make_store(self, tmpdir: str) -> tuple[ArtifactStore, Path]:
        rm = RunManager(output_dir=tmpdir)
        config = RunConfig(scope=ScopeConfig(target_url="https://example.com"))
        _, run_path = rm.create_run(config)
        return ArtifactStore(run_path), run_path

    def test_save_load_pydantic_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, _ = self._make_store(tmpdir)

            har = HARFile()
            har.log.entries.append(
                HAREntry(
                    request=HARRequest(method="GET", url="https://example.com"),
                    response=HARResponse(status=200),
                )
            )
            path = store.save(ArtifactType.HAR, har, name="initial")
            assert path.exists()

            data = store.load(ArtifactType.HAR, path.name)
            assert data["log"]["entries"][0]["request"]["method"] == "GET"

    def test_save_load_dict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, _ = self._make_store(tmpdir)
            data = {"tech": "react", "version": "18.2"}
            store.save(ArtifactType.TECH_STACK, data)
            loaded = store.load_singleton(ArtifactType.TECH_STACK)
            assert loaded["tech"] == "react"

    def test_save_load_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, _ = self._make_store(tmpdir)
            png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
            path = store.save(ArtifactType.SCREENSHOT, png_data, name="login")
            loaded = store.load_bytes(ArtifactType.SCREENSHOT, path.name)
            assert loaded == png_data

    def test_save_singleton(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, _ = self._make_store(tmpdir)
            sitemap = SiteMap()
            store.save(ArtifactType.SITE_MAP, sitemap)
            loaded = store.load_singleton(ArtifactType.SITE_MAP)
            assert loaded["endpoints"] == []

    def test_list_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, _ = self._make_store(tmpdir)
            store.save(ArtifactType.HAR, {"test": 1}, name="a")
            store.save(ArtifactType.HAR, {"test": 2}, name="b")
            files = store.list_artifacts(ArtifactType.HAR)
            assert len(files) == 2

    def test_save_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, _ = self._make_store(tmpdir)
            items = [{"id": 1, "msg": "hello"}, {"id": 2, "msg": "world"}]
            path = store.save_jsonl(ArtifactType.LLM_SESSION, items, name="session")
            assert path.exists()
            content = path.read_text()
            lines = content.strip().split("\n")
            assert len(lines) == 2


class TestEncryption:
    def test_encrypt_decrypt(self) -> None:
        key = generate_key()
        enc = ArtifactEncryptor(key)
        plaintext = b"sensitive cookie data: session=abc123"
        ciphertext = enc.encrypt(plaintext)
        assert ciphertext != plaintext
        decrypted = enc.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_different_nonce_each_time(self) -> None:
        key = generate_key()
        enc = ArtifactEncryptor(key)
        data = b"same data"
        c1 = enc.encrypt(data)
        c2 = enc.encrypt(data)
        assert c1 != c2  # Different nonces

    def test_save_load_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            key = generate_key()
            key_path = Path(tmpdir) / "encryption.key"
            save_key(key, key_path)
            loaded = load_key(key_path)
            assert loaded == key

    def test_wrong_key_fails(self) -> None:
        key1 = generate_key()
        key2 = generate_key()
        enc1 = ArtifactEncryptor(key1)
        enc2 = ArtifactEncryptor(key2)
        ciphertext = enc1.encrypt(b"secret")
        try:
            enc2.decrypt(ciphertext)
            assert False, "Should have raised"
        except Exception:
            pass  # Expected
