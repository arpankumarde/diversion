"""Configuration models for scope, proxy, and run settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from nazitest.models.types import ExploitMethod, ProxyProtocol, RotationStrategy


class ScopeConfig(BaseModel):
    """Defines the allowed testing scope."""

    target_url: str
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    excluded_paths: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    )
    max_crawl_depth: int = 5
    max_crawl_pages: int = 200
    include_subdomains: bool = True

    def summary(self) -> str:
        domains = ", ".join(self.allowed_domains) or "auto-detect"
        return f"domains=[{domains}] depth={self.max_crawl_depth} pages={self.max_crawl_pages}"


class ProxyEntry(BaseModel):
    """A single proxy endpoint."""

    url: str
    protocol: ProxyProtocol = ProxyProtocol.HTTP
    geo: str | None = None
    username: str | None = None
    password: str | None = None


class ProxyConfig(BaseModel):
    """Proxy rotation configuration."""

    proxy_list: list[ProxyEntry] = Field(default_factory=list)
    strategy: RotationStrategy = RotationStrategy.ROUND_ROBIN
    enabled: bool = False


class ModelConfig(BaseModel):
    """Configuration for a single LLM model role."""

    id: str
    temperature: float = 0.3
    max_tokens: int = 8192
    description: str = ""


class BudgetConfig(BaseModel):
    """LLM API budget controls."""

    max_cost_per_run_usd: float = 10.0
    warn_at_usd: float = 7.5


class ModelsConfig(BaseModel):
    """All LLM model configurations."""

    models: dict[str, ModelConfig] = Field(default_factory=dict)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)


class RunConfig(BaseModel):
    """Complete configuration for a single scan run."""

    scope: ScopeConfig
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    models_config_path: Path = Field(default=Path("models.yaml"))
    codebase_path: Path | None = None
    time_limit_minutes: int = 120
    exploit_mode: str = "confirm"  # "confirm" | "safe" | "aggressive"
    human_in_loop: bool = True
    output_dir: Path = Field(default=Path("./nazitest_runs"))
    exploit_methods: list[ExploitMethod] = Field(
        default_factory=lambda: [ExploitMethod.CURL_CFFI, ExploitMethod.BROWSER_REPLAY]
    )
    max_requests_per_second: int = 10
    max_concurrent_connections: int = 5
