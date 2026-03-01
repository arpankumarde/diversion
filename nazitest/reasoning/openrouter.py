"""OpenRouter API client — single LLM interface used by ALL agents (DRY)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable, Awaitable

import httpx

from nazitest.models.config import ModelConfig

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


# Pricing per million tokens (USD) — updated Feb 2026
MODEL_PRICING: dict[str, dict[str, float]] = {
    "anthropic/claude-sonnet-4.6": {
        "input": 3.0,
        "output": 15.0,
    },
    "anthropic/claude-sonnet-4.5": {
        "input": 3.0,
        "output": 15.0,
    },
    "anthropic/claude-sonnet-4": {
        "input": 3.0,
        "output": 15.0,
    },
    "anthropic/claude-haiku-4.5": {
        "input": 1.0,
        "output": 5.0,
    },
    "anthropic/claude-opus-4.6": {
        "input": 5.0,
        "output": 25.0,
    },
    "anthropic/claude-opus-4.5": {
        "input": 5.0,
        "output": 25.0,
    },
    "anthropic/claude-3-haiku": {
        "input": 0.25,
        "output": 1.25,
    },
}


def _compute_cost(
    model: str, input_tokens: int, output_tokens: int
) -> float:
    """Compute cost in USD from token counts and model pricing."""
    pricing = MODEL_PRICING.get(model)
    if not pricing:
        return 0.0
    return (
        input_tokens * pricing["input"] / 1_000_000
        + output_tokens * pricing["output"] / 1_000_000
    )


class UsageTracker:
    """Tracks LLM API token usage and costs."""

    def __init__(
        self,
        budget_limit: float = 10.0,
        warn_at: float = 7.5,
    ) -> None:
        self.budget_limit = budget_limit
        self.warn_at = warn_at
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0
        self.calls: list[dict[str, Any]] = []
        self._per_model: dict[str, dict[str, Any]] = {}

    def record(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost: float = 0.0,
    ) -> None:
        # Compute cost from tokens if not provided
        if cost <= 0:
            cost = _compute_cost(model, input_tokens, output_tokens)

        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost
        self.calls.append(
            {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost, 6),
                "timestamp": time.time(),
            }
        )

        # Per-model aggregation
        if model not in self._per_model:
            self._per_model[model] = {
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0,
                "calls": 0,
            }
        m = self._per_model[model]
        m["input_tokens"] += input_tokens
        m["output_tokens"] += output_tokens
        m["cost_usd"] += cost
        m["calls"] += 1

        if self.total_cost_usd >= self.warn_at:
            logger.warning(
                "LLM budget warning: $%.4f / $%.2f used",
                self.total_cost_usd,
                self.budget_limit,
            )

    def merge(self, other: UsageTracker) -> None:
        """Merge another tracker's data into this one."""
        self.total_input_tokens += other.total_input_tokens
        self.total_output_tokens += other.total_output_tokens
        self.total_cost_usd += other.total_cost_usd
        self.calls.extend(other.calls)
        for model, data in other._per_model.items():
            if model not in self._per_model:
                self._per_model[model] = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                    "calls": 0,
                }
            m = self._per_model[model]
            m["input_tokens"] += data["input_tokens"]
            m["output_tokens"] += data["output_tokens"]
            m["cost_usd"] += data["cost_usd"]
            m["calls"] += data["calls"]

    @property
    def budget_exceeded(self) -> bool:
        return self.total_cost_usd >= self.budget_limit

    def summary(self) -> dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "total_calls": len(self.calls),
            "budget_limit": self.budget_limit,
            "per_model": {
                model: {
                    "input_tokens": d["input_tokens"],
                    "output_tokens": d["output_tokens"],
                    "cost_usd": round(d["cost_usd"], 6),
                    "calls": d["calls"],
                }
                for model, d in self._per_model.items()
            },
            "calls": self.calls,
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
                content = (
                    choices[0].get("message", {}).get("content", "")
                    if choices
                    else ""
                )

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
                    await asyncio.sleep(2**attempt)
                    continue
                raise

        raise RuntimeError(f"Failed after {max_retries} retries")

    async def reason_with_tools(
        self,
        role: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[..., Awaitable[str]] | None = None,
        max_tool_rounds: int = 8,
        structured_output: dict | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Agentic tool-use loop: send messages, execute tool calls, repeat.

        Falls back to regular reason() if no tools provided.

        Tool-use and response_format (json_schema) are mutually exclusive
        in OpenAI/OpenRouter, so structured_output is omitted when tools are active.
        """
        if not tools or not tool_executor:
            return await self.reason(
                role=role,
                messages=messages,
                structured_output=structured_output,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        if self.usage.budget_exceeded:
            raise RuntimeError(
                f"LLM budget exceeded: ${self.usage.total_cost_usd:.2f} / "
                f"${self.usage.budget_limit:.2f}"
            )

        model_config = self.models.get(role)
        if not model_config:
            raise ValueError(
                f"Unknown model role: {role}. Available: {list(self.models.keys())}"
            )

        # Work on a mutable copy of messages
        working_messages = list(messages)
        client = await self._get_client()

        for round_num in range(max_tool_rounds):
            if self.usage.budget_exceeded:
                logger.warning("Budget exceeded during tool-use round %d", round_num)
                break

            payload: dict[str, Any] = {
                "model": model_config.id,
                "messages": working_messages,
                "tools": tools,
                "temperature": (
                    temperature if temperature is not None else model_config.temperature
                ),
                "max_tokens": (
                    max_tokens if max_tokens is not None else model_config.max_tokens
                ),
            }

            # Send request with retries
            data: dict[str, Any] | None = None
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                    )
                    if response.status_code == 429:
                        wait = min(2**attempt * 2, 30)
                        logger.warning("Rate limited in tool loop, waiting %ds...", wait)
                        await asyncio.sleep(wait)
                        continue
                    response.raise_for_status()
                    data = response.json()
                    break
                except httpx.HTTPStatusError as e:
                    if attempt < max_retries - 1 and e.response.status_code >= 500:
                        await asyncio.sleep(2**attempt)
                        continue
                    raise

            if data is None:
                raise RuntimeError("Failed to get response in tool-use loop")

            # Track usage for this round
            usage = data.get("usage", {})
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)
            cost = usage.get("total_cost", 0.0) or 0.0
            self.usage.record(model_config.id, input_tokens, output_tokens, cost)

            choices = data.get("choices", [])
            if not choices:
                break

            message = choices[0].get("message", {})
            finish_reason = choices[0].get("finish_reason", "stop")

            # Check for tool calls
            tool_calls = message.get("tool_calls")
            if not tool_calls or finish_reason == "stop":
                # No more tool calls — return final content
                content = message.get("content", "")
                return {
                    "content": content or "",
                    "model": data.get("model", model_config.id),
                    "usage": {
                        "input_tokens": self.usage.total_input_tokens,
                        "output_tokens": self.usage.total_output_tokens,
                    },
                    "raw": data,
                }

            # Append assistant message with tool_calls
            working_messages.append(message)

            # Execute each tool call
            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                try:
                    arguments = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    arguments = {}

                logger.info(
                    "Tool call [round %d]: %s(%s)",
                    round_num + 1,
                    tool_name,
                    json.dumps(arguments)[:200],
                )

                try:
                    tool_result = await tool_executor(tool_name, arguments)
                except Exception as e:
                    tool_result = f"Tool error: {e}"
                    logger.warning("Tool execution failed: %s", e)

                # Append tool result message
                working_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": str(tool_result)[:10_000],
                })

        # Exhausted max rounds — return last content
        content = ""
        if working_messages:
            last = working_messages[-1]
            if isinstance(last, dict):
                content = last.get("content", "")
        return {
            "content": content or "",
            "model": model_config.id if model_config else "",
            "usage": {
                "input_tokens": self.usage.total_input_tokens,
                "output_tokens": self.usage.total_output_tokens,
            },
            "raw": {},
        }

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
