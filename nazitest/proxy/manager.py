"""Proxy rotation — shared between browser recon and curl_cffi exploitation."""

from __future__ import annotations

import random
from itertools import cycle
from urllib.parse import quote

from nazitest.models.config import ProxyConfig, ProxyEntry
from nazitest.models.types import RotationStrategy


class ProxyManager:
    """Manages proxy rotation for both recon and exploitation.

    DRY: single proxy manager used by browser controller and curl_cffi client.
    """

    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self._proxies = list(config.proxy_list)
        self._burned: set[str] = set()
        self._rr_cycle = cycle(range(len(self._proxies))) if self._proxies else cycle([])
        self._rr_index = 0

    @property
    def has_proxies(self) -> bool:
        return self.config.enabled and len(self._proxies) > 0

    def get_proxy(self, purpose: str = "recon") -> ProxyEntry | None:
        """Get next proxy based on rotation strategy.

        Args:
            purpose: "recon" for residential/blending, "exploit" for speed,
                     "validation" for geo-diversity.
        """
        if not self.has_proxies:
            return None

        available = [p for p in self._proxies if p.url not in self._burned]
        if not available:
            return None

        # Filter by geo if purpose is "validation" and geo proxies exist
        if purpose == "validation":
            geo_proxies = [p for p in available if p.geo]
            if geo_proxies:
                available = geo_proxies

        if self.config.strategy == RotationStrategy.RANDOM:
            return random.choice(available)
        elif self.config.strategy == RotationStrategy.GEO_TARGETED:
            # Prefer proxies with geo tag
            geo_proxies = [p for p in available if p.geo]
            return random.choice(geo_proxies) if geo_proxies else random.choice(available)
        else:
            # Round-robin (default)
            idx = next(self._rr_cycle) % len(available)
            return available[idx]

    def get_proxy_url(self, purpose: str = "recon") -> str | None:
        """Get proxy URL string for direct use in requests."""
        proxy = self.get_proxy(purpose)
        if not proxy:
            return None

        url = proxy.url
        if proxy.username and proxy.password:
            # Insert auth into URL (percent-encode credentials for safety)
            proto, rest = url.split("://", 1)
            user = quote(proxy.username, safe="")
            passwd = quote(proxy.password, safe="")
            url = f"{proto}://{user}:{passwd}@{rest}"
        return url

    def mark_burned(self, proxy_url: str, reason: str = "") -> None:
        """Remove a proxy from rotation after detection."""
        self._burned.add(proxy_url)

    def reset_burned(self) -> None:
        """Reset all burned proxies (useful for new scan phase)."""
        self._burned.clear()

    @property
    def available_count(self) -> int:
        return len([p for p in self._proxies if p.url not in self._burned])
