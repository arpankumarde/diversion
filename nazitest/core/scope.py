"""Scope enforcement — validates all URLs against configured scope."""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract

from nazitest.models.config import ScopeConfig


class ScopeEnforcer:
    """Validates URLs against scope config. Every outbound request passes through this."""

    def __init__(self, config: ScopeConfig) -> None:
        self.config = config
        self._target_parts = tldextract.extract(config.target_url)
        self._allowed_domains = set(config.allowed_domains)

        # If no explicit domains, auto-detect from target URL
        if not self._allowed_domains:
            domain = f"{self._target_parts.domain}.{self._target_parts.suffix}"
            self._allowed_domains.add(domain)

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the allowed scope."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        # Only allow http/https
        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Check domain
        if not self._is_domain_allowed(hostname):
            return False

        # Check path exclusions
        path = parsed.path or "/"
        if self._is_path_excluded(path):
            return False

        # Check path inclusions
        if not self._is_path_allowed(path):
            return False

        return True

    def _is_domain_allowed(self, hostname: str) -> bool:
        """Check if hostname matches allowed domains."""
        # Exact hostname match always works
        if hostname in self._allowed_domains:
            return True

        parts = tldextract.extract(hostname)
        domain = f"{parts.domain}.{parts.suffix}"
        has_subdomain = bool(parts.subdomain)

        if has_subdomain:
            # Subdomain present — only allow if include_subdomains is True
            if not self.config.include_subdomains:
                return False
            return domain in self._allowed_domains
        else:
            # No subdomain — check registered domain
            return domain in self._allowed_domains

    def _is_path_excluded(self, path: str) -> bool:
        for excluded in self.config.excluded_paths:
            if path.startswith(excluded):
                return True
        return False

    def _is_path_allowed(self, path: str) -> bool:
        # "/" allows everything
        if "/" in self.config.allowed_paths:
            return True
        for allowed in self.config.allowed_paths:
            if path.startswith(allowed):
                return True
        return False

    def validate_or_raise(self, url: str) -> None:
        """Raise ValueError if URL is out of scope."""
        if not self.is_in_scope(url):
            raise ValueError(f"URL out of scope: {url}")
