"""Configuration loading — models.yaml, env vars, .env file, CLI overrides."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from nazitest.models.config import BudgetConfig, ModelConfig, ModelsConfig


class Settings(BaseModel):
    """Global application settings resolved from .env + env vars + config files."""

    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    chrome_path: str = ""
    proxy_url: str = ""
    proxy_list_path: str = ""
    output_dir: Path = Field(default=Path("./nazitest_runs"))
    models: ModelsConfig = Field(default_factory=ModelsConfig)

    @classmethod
    def load(cls, models_yaml: Path | str = "models.yaml") -> Settings:
        """Load settings from .env file, environment variables, and models.yaml."""
        # Load .env file (does not override existing env vars)
        load_dotenv()

        settings = cls(
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            chrome_path=os.environ.get("CHROME_PATH", ""),
            proxy_url=os.environ.get("NAZITEST_PROXY", ""),
            proxy_list_path=os.environ.get("NAZITEST_PROXY_LIST", ""),
        )

        output_dir = os.environ.get("NAZITEST_OUTPUT_DIR")
        if output_dir:
            settings.output_dir = Path(output_dir)

        models_path = Path(models_yaml)
        if models_path.exists():
            settings.models = load_models_config(models_path)

        return settings


def load_models_config(path: Path) -> ModelsConfig:
    """Parse models.yaml into ModelsConfig."""
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.warning("Failed to parse %s: %s — using defaults", path, e)
        return ModelsConfig()

    if not raw:
        return ModelsConfig()

    models: dict[str, ModelConfig] = {}
    for role, cfg in raw.get("models", {}).items():
        if not isinstance(cfg, dict):
            logger.warning("Skipping invalid model config for role '%s'", role)
            continue
        model_id = cfg.get("id")
        if not model_id:
            logger.warning("Skipping model role '%s' — missing 'id' field", role)
            continue
        models[role] = ModelConfig(
            id=model_id,
            temperature=cfg.get("temperature", 0.3),
            max_tokens=cfg.get("max_tokens", 8192),
            description=cfg.get("description", ""),
        )

    budget_raw = raw.get("budget", {})
    budget = BudgetConfig(
        max_cost_per_run_usd=budget_raw.get("max_cost_per_run_usd", 10.0),
        warn_at_usd=budget_raw.get("warn_at_usd", 7.5),
    )

    return ModelsConfig(models=models, budget=budget)
