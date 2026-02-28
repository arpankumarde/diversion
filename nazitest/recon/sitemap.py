"""Site map builder — aggregates endpoints, API routes, auth flows from recon data."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from nazitest.models.recon import (
    APIRoute,
    Endpoint,
    SecurityHeaders,
    SiteMap,
)
from nazitest.models.types import AuthType, HttpMethod

logger = logging.getLogger(__name__)

# Common API path patterns
API_PATTERNS = re.compile(r"/(api|v\d+|graphql|rest|rpc)/", re.IGNORECASE)

# Auth header indicators
AUTH_HEADERS = {"authorization", "x-auth-token", "x-api-key", "x-csrf-token"}


class SiteMapBuilder:
    """Builds a site map from HAR entries and DOM data."""

    def __init__(self) -> None:
        self._endpoints: dict[str, Endpoint] = {}
        self._api_routes: dict[str, APIRoute] = {}
        self._security_headers: dict[str, SecurityHeaders] = {}

    def add_from_har_entry(self, request: dict, response: dict) -> None:
        """Add endpoint info from a HAR request/response pair."""
        url = request.get("url", "")
        method_str = request.get("method", "GET").upper()

        try:
            method = HttpMethod(method_str)
        except ValueError:
            method = HttpMethod.GET

        parsed = urlparse(url)
        # Normalize: strip query string for endpoint key
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        key = f"{method_str} {clean_url}"

        # Detect auth
        headers = request.get("headers", {})
        auth_type = self._detect_auth_type(headers)

        # Extract params
        params = list(request.get("queryParams", {}).keys())

        status_code = response.get("status", 0)
        content_type = response.get("mimeType", "")

        if key not in self._endpoints:
            self._endpoints[key] = Endpoint(
                url=clean_url,
                method=method,
                status_code=status_code,
                content_type=content_type,
                params=params,
                requires_auth=auth_type != AuthType.NONE,
                auth_type=auth_type,
                discovered_via="har",
            )

        # Check if it's an API route
        if API_PATTERNS.search(parsed.path) or content_type.startswith("application/json"):
            route_key = parsed.path
            if route_key not in self._api_routes:
                self._api_routes[route_key] = APIRoute(
                    url_pattern=parsed.path,
                    methods=[method],
                    request_content_type=request.get("postDataMimeType", ""),
                    response_content_type=content_type,
                    params=params,
                    requires_auth=auth_type != AuthType.NONE,
                )
            else:
                route = self._api_routes[route_key]
                if method not in route.methods:
                    route.methods.append(method)

        # Extract security headers
        resp_headers = response.get("headers", {})
        self._extract_security_headers(clean_url, resp_headers)

    def add_from_dom_links(self, links: list[str], base_url: str) -> None:
        """Add endpoints discovered from DOM link extraction."""
        parsed_base = urlparse(base_url)
        for link in links:
            if link.startswith("/"):
                full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{link}"
            elif link.startswith("http"):
                full_url = link
            else:
                continue

            key = f"GET {full_url}"
            if key not in self._endpoints:
                self._endpoints[key] = Endpoint(
                    url=full_url,
                    method=HttpMethod.GET,
                    discovered_via="dom",
                )

    def _detect_auth_type(self, headers: dict) -> AuthType:
        headers_lower = {k.lower(): v for k, v in headers.items()}

        auth = headers_lower.get("authorization", "")
        if auth.lower().startswith("bearer"):
            # Check if JWT
            token = auth.split(" ", 1)[-1] if " " in auth else ""
            if token.count(".") == 2:
                return AuthType.JWT
            return AuthType.BEARER
        elif auth.lower().startswith("basic"):
            return AuthType.BASIC

        if any(h in headers_lower for h in AUTH_HEADERS - {"authorization"}):
            return AuthType.API_KEY

        return AuthType.NONE

    def _extract_security_headers(self, url: str, headers: dict) -> None:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        self._security_headers[url] = SecurityHeaders(
            csp=headers_lower.get("content-security-policy", ""),
            x_frame_options=headers_lower.get("x-frame-options", ""),
            x_content_type_options=headers_lower.get("x-content-type-options", ""),
            strict_transport_security=headers_lower.get("strict-transport-security", ""),
            x_xss_protection=headers_lower.get("x-xss-protection", ""),
            referrer_policy=headers_lower.get("referrer-policy", ""),
            permissions_policy=headers_lower.get("permissions-policy", ""),
            cors_allow_origin=headers_lower.get("access-control-allow-origin", ""),
            cors_allow_methods=headers_lower.get("access-control-allow-methods", ""),
            cors_allow_headers=headers_lower.get("access-control-allow-headers", ""),
        )

    def build(self) -> SiteMap:
        """Build the final SiteMap from collected data."""
        return SiteMap(
            endpoints=list(self._endpoints.values()),
            api_routes=list(self._api_routes.values()),
            security_headers=self._security_headers,
        )

    def clear(self) -> None:
        self._endpoints.clear()
        self._api_routes.clear()
        self._security_headers.clear()
