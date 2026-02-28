"""OpenRouter API client — single LLM interface used by ALL agents (DRY)."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from nazitest.models.config import ModelConfig

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


class UsageTracker:
    """Tracks LLM API token usage and costs."""

    def __init__(self, budget_limit: float = 10.0, warn_at: float = 7.5) -> None:
        self.budget_limit = budget_limit
        self.warn_at = warn_at
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0
        self.calls: list[dict[str, Any]] = []

    def record(
        self, model: str, input_tokens: int, output_tokens: int, cost: float
    ) -> None:
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost
        self.calls.append(
            {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost": cost,
                "timestamp": time.time(),
            }
        )

        if self.total_cost_usd >= self.warn_at:
            logger.warning(
                "LLM budget warning: $%.2f / $%.2f used",
                self.total_cost_usd,
                self.budget_limit,
            )

    @property
    def budget_exceeded(self) -> bool:
        return self.total_cost_usd >= self.budget_limit

    def summary(self) -> dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "total_calls": len(self.calls),
            "budget_limit": self.budget_limit,
        }


class OpenRouterClient:
    """Async client for OpenRouter API. Used by ALL agent types.

    DRY: single client, multiple model roles.
    """

    def __init__(
        self,
        api_key: str,
        models: dict[str, ModelConfig],
        base_url: str = DEFAULT_BASE_URL,
        budget_limit: float = 10.0,
        warn_at: float = 7.5,
    ) -> None:
        self.api_key = api_key
        self.models = models
        self.base_url = base_url.rstrip("/")
        self.usage = UsageTracker(budget_limit=budget_limit, warn_at=warn_at)
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(120.0, connect=10.0),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://nazitest.local",
                    "X-Title": "NAZITEST Security Analysis",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def reason(
        self,
        role: str,
        messages: list[dict[str, str]],
        structured_output: dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Send a reasoning request to the appropriate model for the given role.

        Args:
            role: Agent role (strategist, scout, cross_validator, exploit_planner, etc.)
            messages: Chat messages [{"role": "system"/"user"/"assistant", "content": "..."}]
            structured_output: Optional JSON schema for structured output
            temperature: Override model default temperature
            max_tokens: Override model default max_tokens

        Returns:
            Response dict with "content", "model", "usage" keys.
        """
        if self.usage.budget_exceeded:
            raise RuntimeError(
                f"LLM budget exceeded: ${self.usage.total_cost_usd:.2f} / "
                f"${self.usage.budget_limit:.2f}"
            )

        model_config = self.models.get(role)
        if not model_config:
            raise ValueError(f"Unknown model role: {role}. Available: {list(self.models.keys())}")

        payload: dict[str, Any] = {
            "model": model_config.id,
            "messages": messages,
            "temperature": temperature if temperature is not None else model_config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else model_config.max_tokens,
        }

        if structured_output:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": structured_output,
            }

        client = await self._get_client()

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                )

                if response.status_code == 429:
                    # Rate limited — back off
                    wait = min(2**attempt * 2, 30)
                    logger.warning("Rate limited, waiting %ds...", wait)
                    import asyncio

                    await asyncio.sleep(wait)
                    continue

                # json_schema not supported — retry with json_object
                if (
                    response.status_code == 400
                    and structured_output
                    and payload["response_format"]["type"]
                    == "json_schema"
                ):
                    logger.info(
                        "json_schema not supported, "
                        "falling back to json_object"
                    )
                    payload["response_format"] = {
                        "type": "json_object",
                    }
                    continue

                response.raise_for_status()
                data = response.json()

                # Track usage
                usage = data.get("usage", {})
                input_tokens = usage.get("prompt_tokens", 0)
                output_tokens = usage.get("completion_tokens", 0)
                cost = usage.get("total_cost", 0.0) or 0.0
                self.usage.record(model_config.id, input_tokens, output_tokens, cost)

                # Extract response
                choices = data.get("choices", [])
                content = choices[0]["message"]["content"] if choices else ""

                return {
                    "content": content,
                    "model": data.get("model", model_config.id),
                    "usage": {
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                    },
                    "raw": data,
                }

            except httpx.HTTPStatusError as e:
                if attempt < max_retries - 1 and e.response.status_code >= 500:
                    import asyncio

                    await asyncio.sleep(2**attempt)
                    continue
                raise

        raise RuntimeError(f"Failed after {max_retries} retries")

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
