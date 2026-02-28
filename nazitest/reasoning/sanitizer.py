"""LLM data sanitization — strips credentials/tokens/PII before sending to LLM."""

from __future__ import annotations

import re
from typing import Any

# Patterns to redact, with replacement descriptors
REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JWTs (header.payload.signature)
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "<JWT_TOKEN>"),
    # Bearer tokens
    (re.compile(r"(Bearer\s+)\S{20,}"), r"\1<BEARER_TOKEN>"),
    # Basic auth
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/=]{10,}"), r"\1<BASIC_AUTH>"),
    # API keys (common patterns)
    (re.compile(r"(api[_-]?key[\"'\s:=]+)\S{15,}", re.I), r"\1<API_KEY>"),
    # Generic passwords
    (re.compile(r"(password[\"'\s:=]+)\S+", re.I), r"\1<PASSWORD>"),
    # AWS keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "<AWS_ACCESS_KEY>"),
    # Long base64 blobs (>40 chars, likely tokens)
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "<BASE64_BLOB>"),
    # Email addresses (PII)
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "<EMAIL>"),
    # IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<IP_ADDR>"),
]


class LLMDataSanitizer:
    """Strips sensitive data before sending to OpenRouter.

    The LLM sees structure and patterns, not secrets.
    """

    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        self._patterns = list(REDACT_PATTERNS)
        if extra_patterns:
            for pattern_str, replacement in extra_patterns:
                self._patterns.append((re.compile(pattern_str), replacement))

    def sanitize(self, data: Any) -> Any:
        """Recursively sanitize data for LLM consumption."""
        if isinstance(data, str):
            return self._sanitize_string(data)
        elif isinstance(data, dict):
            return {k: self.sanitize(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize(item) for item in data]
        return data

    def _sanitize_string(self, text: str) -> str:
        result = text
        for pattern, replacement in self._patterns:
            result = pattern.sub(replacement, result)
        return result

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitize HTTP headers, preserving structure."""
        sensitive_headers = {
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "proxy-authorization",
        }
        result = {}
        for name, value in headers.items():
            if name.lower() in sensitive_headers:
                result[name] = self._sanitize_string(value)
            else:
                result[name] = value
        return result

    def sanitize_for_llm(self, data: dict) -> dict:
        """Top-level sanitization entry point."""
        return self.sanitize(data)
