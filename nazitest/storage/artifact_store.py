"""Artifact storage — single interface for saving/loading all artifact types."""

from __future__ import annotations

import time
from pathlib import Path

import orjson
from pydantic import BaseModel

from nazitest.models.types import ArtifactType

# Maps artifact types to their subdirectory within a run
ARTIFACT_PATHS: dict[ArtifactType, str] = {
    ArtifactType.HAR: "recon/har",
    ArtifactType.DOM_SNAPSHOT: "recon/dom",
    ArtifactType.SCREENSHOT: "recon/screenshots",
    ArtifactType.COOKIE_JAR: "recon/cookies",
    ArtifactType.WEBSOCKET_LOG: "recon/websockets",
    ArtifactType.SITE_MAP: "recon",
    ArtifactType.TECH_STACK: "recon",
    ArtifactType.KNOWLEDGE_GRAPH: "analysis/knowledge_graph",
    ArtifactType.HYPOTHESIS: "analysis/knowledge_graph",
    ArtifactType.LLM_SESSION: "analysis/llm_reasoning",
    ArtifactType.EXPLOIT_ATTEMPT: "exploitation/attempts",
    ArtifactType.EXPLOIT_RESULT: "exploitation",
    ArtifactType.POC: "exploitation/pocs",
    ArtifactType.REPORT: "report",
    ArtifactType.CONFIG: "",
    ArtifactType.AUTHORIZATION: "",
}

# Artifact types that use a single file (not timestamped)
SINGLETON_ARTIFACTS: dict[ArtifactType, str] = {
    ArtifactType.SITE_MAP: "site_map.json",
    ArtifactType.TECH_STACK: "tech_stack.json",
    ArtifactType.EXPLOIT_RESULT: "results.json",
}


class ArtifactStore:
    """Generic save/load for all artifact types. Single write path for DRY."""

    def __init__(self, run_path: Path) -> None:
        self.run_path = run_path

    def _resolve_dir(self, artifact_type: ArtifactType) -> Path:
        subdir = ARTIFACT_PATHS.get(artifact_type, "")
        target = self.run_path / subdir if subdir else self.run_path
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _make_filename(self, artifact_type: ArtifactType, name: str | None) -> str:
        if artifact_type in SINGLETON_ARTIFACTS:
            return SINGLETON_ARTIFACTS[artifact_type]
        ts = time.strftime("%Y%m%d_%H%M%S")
        suffix = f"_{name}" if name else ""
        ext = ".png" if artifact_type == ArtifactType.SCREENSHOT else ".json"
        return f"{ts}{suffix}{ext}"

    def save(
        self,
        artifact_type: ArtifactType,
        data: BaseModel | dict | bytes | str,
        name: str | None = None,
    ) -> Path:
        """Save an artifact. Returns the file path."""
        target_dir = self._resolve_dir(artifact_type)
        filename = self._make_filename(artifact_type, name)
        filepath = target_dir / filename

        if isinstance(data, bytes):
            filepath.write_bytes(data)
        elif isinstance(data, str):
            filepath.write_text(data)
        elif isinstance(data, BaseModel):
            filepath.write_bytes(
                orjson.dumps(data.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
            )
        elif isinstance(data, dict):
            filepath.write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")

        return filepath

    def save_jsonl(
        self,
        artifact_type: ArtifactType,
        items: list[BaseModel | dict],
        name: str | None = None,
    ) -> Path:
        """Save a list of items as JSONL (one JSON object per line)."""
        target_dir = self._resolve_dir(artifact_type)
        ts = time.strftime("%Y%m%d_%H%M%S")
        suffix = f"_{name}" if name else ""
        filepath = target_dir / f"{ts}{suffix}.jsonl"

        lines = []
        for item in items:
            if isinstance(item, BaseModel):
                lines.append(orjson.dumps(item.model_dump(mode="json")))
            else:
                lines.append(orjson.dumps(item))
        filepath.write_bytes(b"\n".join(lines))
        return filepath

    def _validate_path(self, target_dir: Path, filepath: Path) -> None:
        """Ensure filepath is within target_dir (prevent path traversal)."""
        if not filepath.resolve().is_relative_to(target_dir.resolve()):
            raise ValueError(f"Path traversal attempt: {filepath}")

    def load(self, artifact_type: ArtifactType, filename: str) -> dict:
        """Load a JSON artifact by filename."""
        target_dir = self._resolve_dir(artifact_type)
        filepath = target_dir / filename
        self._validate_path(target_dir, filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Artifact not found: {filepath}")
        return orjson.loads(filepath.read_bytes())

    def load_bytes(self, artifact_type: ArtifactType, filename: str) -> bytes:
        """Load a binary artifact (e.g., screenshot)."""
        target_dir = self._resolve_dir(artifact_type)
        filepath = target_dir / filename
        self._validate_path(target_dir, filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Artifact not found: {filepath}")
        return filepath.read_bytes()

    def list_artifacts(self, artifact_type: ArtifactType) -> list[str]:
        """List all artifact filenames of a given type."""
        target_dir = self._resolve_dir(artifact_type)
        if not target_dir.exists():
            return []
        return sorted(f.name for f in target_dir.iterdir() if f.is_file())

    def load_singleton(self, artifact_type: ArtifactType) -> dict:
        """Load a singleton artifact (site_map, tech_stack, results)."""
        if artifact_type not in SINGLETON_ARTIFACTS:
            raise ValueError(f"Not a singleton artifact: {artifact_type}")
        filename = SINGLETON_ARTIFACTS[artifact_type]
        return self.load(artifact_type, filename)
