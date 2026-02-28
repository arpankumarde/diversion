"""Tests for configuration loading."""

from pathlib import Path

from nazitest.config import Settings, load_models_config


class TestModelsConfig:
    def test_load_models_yaml(self) -> None:
        config = load_models_config(Path("models.yaml"))
        assert "strategist" in config.models
        assert "scout" in config.models
        assert config.models["strategist"].id == "anthropic/claude-opus-4.6"
        assert config.budget.max_cost_per_run_usd == 10.0

    def test_model_roles_complete(self) -> None:
        config = load_models_config(Path("models.yaml"))
        expected_roles = {
            "graph_builder",
            "strategist",
            "scout",
            "exploit_planner",
            "cross_validator",
            "codebase_analyzer",
            "report_writer",
        }
        assert set(config.models.keys()) == expected_roles


class TestSettings:
    def test_settings_load(self) -> None:
        settings = Settings.load(models_yaml="models.yaml")
        assert "strategist" in settings.models.models
        assert settings.openrouter_base_url == "https://openrouter.ai/api/v1"
