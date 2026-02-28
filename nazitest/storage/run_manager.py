"""Run management — create, resume, list runs with directory layout from PRD section 6."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import orjson

from nazitest.models.config import RunConfig

# Directory structure matching PRD section 6
RUN_SUBDIRS = [
    "recon/har",
    "recon/dom",
    "recon/screenshots",
    "recon/cookies",
    "recon/websockets",
    "analysis/knowledge_graph",
    "analysis/codebase_xref",
    "analysis/llm_reasoning",
    "exploitation/attempts",
    "exploitation/pocs",
    "report",
]


def _generate_run_id() -> str:
    """Generate a unique run ID: UUID prefix + timestamp."""
    short_uuid = uuid.uuid4().hex[:8]
    ts = time.strftime("%Y%m%d_%H%M%S")
    return f"{short_uuid}_{ts}"


class RunManager:
    """Creates, resumes, and lists scan runs."""

    def __init__(self, output_dir: Path | str = "./nazitest_runs") -> None:
        self.output_dir = Path(output_dir)

    def create_run(self, config: RunConfig) -> tuple[str, Path]:
        """Create a new run directory with full structure. Returns (run_id, run_path)."""
        run_id = _generate_run_id()
        run_path = self.output_dir / run_id

        # Create all subdirectories
        for subdir in RUN_SUBDIRS:
            (run_path / subdir).mkdir(parents=True, exist_ok=True)

        # Save run config
        config_path = run_path / "config.json"
        config_path.write_bytes(
            orjson.dumps(config.model_dump(mode="json"), option=orjson.OPT_INDENT_2)
        )

        return run_id, run_path

    def get_run_path(self, run_id: str) -> Path:
        """Get the path for an existing run."""
        run_path = self.output_dir / run_id
        if not run_path.exists():
            raise FileNotFoundError(f"Run not found: {run_id}")
        return run_path

    def load_run_config(self, run_id: str) -> RunConfig:
        """Load the config for an existing run."""
        run_path = self.get_run_path(run_id)
        config_path = run_path / "config.json"
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found for run: {run_id}")
        raw = orjson.loads(config_path.read_bytes())
        return RunConfig.model_validate(raw)

    def list_runs(self) -> list[dict[str, str]]:
        """List all runs with basic metadata."""
        if not self.output_dir.exists():
            return []

        runs = []
        for entry in sorted(self.output_dir.iterdir(), reverse=True):
            if entry.is_dir() and (entry / "config.json").exists():
                config = orjson.loads((entry / "config.json").read_bytes())
                runs.append(
                    {
                        "run_id": entry.name,
                        "target": config.get("scope", {}).get("target_url", "unknown"),
                        "created": entry.name.split("_", 1)[-1] if "_" in entry.name else "",
                    }
                )
        return runs

    def run_exists(self, run_id: str) -> bool:
        return (self.output_dir / run_id).exists()
