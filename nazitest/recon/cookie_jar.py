"""Cookie jar — extracts and analyzes cookies with security flag tracking."""

from __future__ import annotations

import logging
from typing import Any

from nazitest.models.recon import CookieInfo

logger = logging.getLogger(__name__)


class CookieJarAnalyzer:
    """Extracts cookies and analyzes their security properties."""

    def __init__(self) -> None:
        self._cookies: dict[str, CookieInfo] = {}  # key = domain+name

    def add_from_cdp(self, cdp_cookies: list[dict[str, Any]]) -> None:
        """Add cookies from CDP Network.getCookies response."""
        for c in cdp_cookies:
            info = CookieInfo(
                name=c.get("name", ""),
                value=c.get("value", ""),
                domain=c.get("domain", ""),
                path=c.get("path", "/"),
                expires=str(c.get("expires", "")),
                http_only=c.get("httpOnly", False),
                secure=c.get("secure", False),
                same_site=c.get("sameSite", ""),
                size=c.get("size", 0),
            )
            key = f"{info.domain}:{info.name}"
            self._cookies[key] = info

    def add_from_headers(self, set_cookie_headers: list[str], domain: str = "") -> None:
        """Parse Set-Cookie headers and add to jar."""
        for header in set_cookie_headers:
            info = self._parse_set_cookie(header, domain)
            if info:
                key = f"{info.domain}:{info.name}"
                self._cookies[key] = info

    def _parse_set_cookie(self, header: str, default_domain: str) -> CookieInfo | None:
        """Parse a single Set-Cookie header."""
        parts = header.split(";")
        if not parts:
            return None

        # First part is name=value
        name_value = parts[0].strip()
        if "=" not in name_value:
            return None

        name, value = name_value.split("=", 1)
        info = CookieInfo(name=name.strip(), value=value.strip(), domain=default_domain)

        # Parse flags
        for part in parts[1:]:
            part = part.strip().lower()
            if part == "httponly":
                info.http_only = True
            elif part == "secure":
                info.secure = True
            elif part.startswith("samesite="):
                info.same_site = part.split("=", 1)[1]
            elif part.startswith("domain="):
                info.domain = part.split("=", 1)[1]
            elif part.startswith("path="):
                info.path = part.split("=", 1)[1]
            elif part.startswith("expires="):
                info.expires = part.split("=", 1)[1]

        return info

    def get_all(self) -> list[CookieInfo]:
        return list(self._cookies.values())

    def get_security_issues(self) -> list[dict[str, str]]:
        """Analyze cookies for security weaknesses."""
        issues = []
        for cookie in self._cookies.values():
            if not cookie.http_only and self._looks_like_session(cookie.name):
                issues.append(
                    {
                        "cookie": cookie.name,
                        "issue": "Session cookie missing HttpOnly flag",
                        "severity": "medium",
                    }
                )
            if not cookie.secure:
                issues.append(
                    {
                        "cookie": cookie.name,
                        "issue": "Cookie missing Secure flag",
                        "severity": "low",
                    }
                )
            if not cookie.same_site or cookie.same_site.lower() == "none":
                issues.append(
                    {
                        "cookie": cookie.name,
                        "issue": f"Cookie SameSite={cookie.same_site or 'not set'}",
                        "severity": "low",
                    }
                )
        return issues

    @staticmethod
    def _looks_like_session(name: str) -> bool:
        session_indicators = [
            "session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf"
        ]
        name_lower = name.lower()
        return any(ind in name_lower for ind in session_indicators)

    def clear(self) -> None:
        self._cookies.clear()
