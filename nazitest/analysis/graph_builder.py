"""Graph builder — constructs knowledge graph from recon artifacts."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlparse

from nazitest.analysis.knowledge_graph import KnowledgeGraph
from nazitest.models.har import HARFile
from nazitest.models.recon import DOMSnapshot, SiteMap
from nazitest.models.types import EdgeType, NodeType

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Constructs the knowledge graph from HAR, DOM, and sitemap data.

    Phase 1: Automated construction from recon artifacts.
    Phase 2: LLM-assisted enrichment (handled in reasoning module).
    Phase 3: Codebase cross-reference (handled in codebase_xref module).
    """

    def __init__(self) -> None:
        self._endpoint_ids: dict[str, str] = {}  # "METHOD url" -> node_id
        self._param_ids: dict[str, str] = {}  # "name:location" -> node_id
        self._tech_ids: dict[str, str] = {}  # tech_name -> node_id
        self._cookie_ids: dict[str, str] = {}  # cookie_name -> node_id
        self._ctrl_ids: dict[str, str] = {}  # control_name -> node_id

    def build(
        self,
        graph: KnowledgeGraph | None = None,
        har_files: list[HARFile] | None = None,
        dom_snapshots: list[DOMSnapshot] | None = None,
        sitemap: SiteMap | None = None,
    ) -> KnowledgeGraph:
        """Build graph from all available recon data."""
        kg = graph or KnowledgeGraph()

        if har_files:
            for har in har_files:
                self._process_har(kg, har)

        if dom_snapshots:
            for snap in dom_snapshots:
                self._process_dom(kg, snap)

        if sitemap:
            self._process_sitemap(kg, sitemap)

        return kg

    def _process_har(self, kg: KnowledgeGraph, har: HARFile) -> None:
        """Extract endpoints, parameters, auth, security controls from HAR."""
        for entry in har.log.entries:
            ep_id = self._ensure_endpoint(kg, entry.request.method, entry.request.url)

            # Extract query parameters
            for param in entry.request.query_string:
                param_id = self._ensure_parameter(kg, param.name, "query")
                kg.add_edge(ep_id, param_id, EdgeType.ACCEPTS_INPUT)

            # Extract POST body parameters
            if entry.request.post_data and entry.request.post_data.text:
                self._extract_body_params(kg, ep_id, entry.request.post_data.text)

            # Detect auth
            self._detect_auth_from_headers(kg, ep_id, entry.request.headers)

            # Extract security controls from response headers
            self._extract_security_controls(kg, ep_id, entry.response.headers)

            # Extract cookies set by response
            for cookie in entry.response.cookies:
                cookie_id = self._ensure_cookie(kg, cookie.name, cookie.domain or "")
                kg.add_edge(ep_id, cookie_id, EdgeType.SETS_COOKIE)

    def _process_dom(self, kg: KnowledgeGraph, snap: DOMSnapshot) -> None:
        """Extract form inputs, technologies from DOM."""
        ep_id = self._ensure_endpoint(kg, "GET", snap.url)

        for form in snap.forms:
            form_ep_id = self._ensure_endpoint(kg, form.method, form.action or snap.url)
            for inp in form.inputs:
                if inp.name:
                    param_id = self._ensure_parameter(kg, inp.name, "body")
                    kg.add_edge(form_ep_id, param_id, EdgeType.ACCEPTS_INPUT)

        for cookie in snap.cookies:
            cookie_id = self._ensure_cookie(kg, cookie.name, cookie.domain)
            kg.add_edge(ep_id, cookie_id, EdgeType.USES_COOKIE)

    def _process_sitemap(self, kg: KnowledgeGraph, sitemap: SiteMap) -> None:
        """Add sitemap endpoints and tech stack to graph."""
        for ep in sitemap.endpoints:
            self._ensure_endpoint(kg, ep.method.value, ep.url)

        tech = sitemap.technologies
        for category in [tech.frameworks, tech.servers, tech.cdns, tech.languages]:
            for name in category:
                self._ensure_technology(kg, name)

    def _ensure_endpoint(self, kg: KnowledgeGraph, method: str, url: str) -> str:
        # Normalize URL (strip query string)
        parsed = urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else url
        key = f"{method} {clean_url}"
        if key not in self._endpoint_ids:
            nid = kg.add_endpoint(clean_url, method)
            self._endpoint_ids[key] = nid
        return self._endpoint_ids[key]

    def _ensure_parameter(self, kg: KnowledgeGraph, name: str, location: str) -> str:
        key = f"{name}:{location}"
        if key not in self._param_ids:
            nid = kg.add_parameter(name, location)
            self._param_ids[key] = nid
        return self._param_ids[key]

    def _ensure_technology(self, kg: KnowledgeGraph, name: str) -> str:
        if name not in self._tech_ids:
            nid = kg.add_technology(name)
            self._tech_ids[name] = nid
        return self._tech_ids[name]

    def _ensure_cookie(self, kg: KnowledgeGraph, name: str, domain: str) -> str:
        key = f"{name}@{domain}"
        if key not in self._cookie_ids:
            nid = kg.add_cookie(name, domain)
            self._cookie_ids[key] = nid
        return self._cookie_ids[key]

    def _ensure_control(self, kg: KnowledgeGraph, name: str, value: str) -> str:
        if name not in self._ctrl_ids:
            nid = kg.add_security_control(name, value)
            self._ctrl_ids[name] = nid
        return self._ctrl_ids[name]

    def _extract_body_params(self, kg: KnowledgeGraph, ep_id: str, body: str) -> None:
        """Try to extract parameters from POST body (JSON or form-encoded)."""
        # Try JSON
        try:
            import orjson

            data = orjson.loads(body)
            if isinstance(data, dict):
                for key in data:
                    param_id = self._ensure_parameter(kg, key, "body")
                    kg.add_edge(ep_id, param_id, EdgeType.ACCEPTS_INPUT)
                return
        except Exception:
            pass

        # Try form-encoded
        try:
            params = parse_qs(body)
            for key in params:
                param_id = self._ensure_parameter(kg, key, "body")
                kg.add_edge(ep_id, param_id, EdgeType.ACCEPTS_INPUT)
        except Exception:
            pass

    def _detect_auth_from_headers(
        self, kg: KnowledgeGraph, ep_id: str, headers: list
    ) -> None:
        """Detect auth mechanisms from request headers."""
        for header in headers:
            name = header.name.lower() if hasattr(header, "name") else ""
            value = header.value if hasattr(header, "value") else ""

            if name == "authorization":
                auth_id = kg.add_node(
                    NodeType.AUTH_MECHANISM,
                    value.split(" ")[0] if " " in value else "unknown",
                )
                kg.add_edge(ep_id, auth_id, EdgeType.AUTHENTICATED_BY)
            elif name in ("x-csrf-token", "x-xsrf-token"):
                ctrl_id = self._ensure_control(kg, "CSRF Token", name)
                kg.add_edge(ep_id, ctrl_id, EdgeType.PROTECTED_BY)

    def _extract_security_controls(
        self, kg: KnowledgeGraph, ep_id: str, headers: list
    ) -> None:
        """Extract security controls from response headers."""
        security_headers = {
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "strict-transport-security": "HSTS",
            "x-xss-protection": "XSS Protection",
        }
        for header in headers:
            name = header.name.lower() if hasattr(header, "name") else ""
            value = header.value if hasattr(header, "value") else ""
            if name in security_headers:
                ctrl_id = self._ensure_control(kg, security_headers[name], value)
                kg.add_edge(ep_id, ctrl_id, EdgeType.PROTECTED_BY)
