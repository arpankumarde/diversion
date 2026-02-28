"""Tests for knowledge graph, graph builder, and tech detector."""

from nazitest.analysis.graph_builder import GraphBuilder
from nazitest.analysis.knowledge_graph import KnowledgeGraph
from nazitest.analysis.tech_detector import TechDetector
from nazitest.models.graph import Hypothesis
from nazitest.models.har import (
    HARContent,
    HARCookie,
    HAREntry,
    HARFile,
    HARHeader,
    HARLog,
    HARPostData,
    HARQueryParam,
    HARRequest,
    HARResponse,
)
from nazitest.models.recon import DOMSnapshot, FormData, FormInput
from nazitest.models.types import EdgeType, NodeType, Severity


class TestKnowledgeGraph:
    def test_add_nodes_and_edges(self) -> None:
        kg = KnowledgeGraph()
        ep = kg.add_endpoint("https://example.com/api/users", "GET")
        param = kg.add_parameter("id", "query")
        kg.add_edge(ep, param, EdgeType.ACCEPTS_INPUT)

        assert kg.node_count == 2
        assert kg.edge_count == 1

    def test_get_nodes_by_type(self) -> None:
        kg = KnowledgeGraph()
        kg.add_endpoint("https://example.com/a", "GET")
        kg.add_endpoint("https://example.com/b", "POST")
        kg.add_parameter("id", "query")

        eps = kg.get_nodes_by_type(NodeType.ENDPOINT)
        assert len(eps) == 2
        params = kg.get_nodes_by_type(NodeType.PARAMETER)
        assert len(params) == 1

    def test_get_neighbors(self) -> None:
        kg = KnowledgeGraph()
        ep = kg.add_endpoint("https://example.com/api", "GET")
        p1 = kg.add_parameter("q", "query")
        p2 = kg.add_parameter("page", "query")
        tech = kg.add_technology("React")
        kg.add_edge(ep, p1, EdgeType.ACCEPTS_INPUT)
        kg.add_edge(ep, p2, EdgeType.ACCEPTS_INPUT)
        kg.add_edge(ep, tech, EdgeType.PROTECTED_BY)  # not really, just testing

        # All neighbors
        all_n = kg.get_neighbors(ep)
        assert len(all_n) == 3

        # Filtered by edge type
        input_n = kg.get_neighbors(ep, EdgeType.ACCEPTS_INPUT)
        assert len(input_n) == 2

    def test_hypothesis_management(self) -> None:
        kg = KnowledgeGraph()
        h = Hypothesis(
            id="h1",
            title="SQLi in login",
            description="Test",
            confidence=0.8,
            severity=Severity.HIGH,
        )
        kg.add_hypothesis(h)
        assert len(kg.get_exploitable_hypotheses()) == 1
        assert kg.get_hypothesis("h1") is not None

    def test_serialization_roundtrip(self) -> None:
        kg = KnowledgeGraph()
        ep = kg.add_endpoint("https://example.com/api", "GET")
        param = kg.add_parameter("q", "query")
        kg.add_edge(ep, param, EdgeType.ACCEPTS_INPUT)
        kg.add_hypothesis(
            Hypothesis(id="h1", title="Test", description="Test vuln")
        )

        # Serialize
        json_data = kg.to_json()
        # Deserialize
        kg2 = KnowledgeGraph.from_json(json_data)
        assert kg2.node_count == 2
        assert kg2.edge_count == 1
        assert len(kg2.get_all_hypotheses()) == 1


class TestGraphBuilder:
    def _make_har(self) -> HARFile:
        return HARFile(
            log=HARLog(
                entries=[
                    HAREntry(
                        request=HARRequest(
                            method="GET",
                            url="https://example.com/api/users?page=1",
                            headers=[HARHeader(name="Authorization", value="Bearer token123")],
                            queryString=[HARQueryParam(name="page", value="1")],
                        ),
                        response=HARResponse(
                            status=200,
                            headers=[
                                HARHeader(name="Content-Security-Policy", value="default-src 'self'"),
                                HARHeader(name="X-Frame-Options", value="DENY"),
                            ],
                            cookies=[HARCookie(name="session", value="abc", domain=".example.com")],
                            content=HARContent(mimeType="application/json"),
                        ),
                    ),
                    HAREntry(
                        request=HARRequest(
                            method="POST",
                            url="https://example.com/api/login",
                            headers=[],
                            postData=HARPostData(
                                mimeType="application/json",
                                text='{"username": "admin", "password": "test"}',
                            ),
                        ),
                        response=HARResponse(status=200),
                    ),
                ]
            )
        )

    def test_build_from_har(self) -> None:
        builder = GraphBuilder()
        kg = builder.build(har_files=[self._make_har()])

        # Should have endpoints
        eps = kg.get_nodes_by_type(NodeType.ENDPOINT)
        assert len(eps) >= 2  # GET /api/users and POST /api/login

        # Should have parameters
        params = kg.get_nodes_by_type(NodeType.PARAMETER)
        assert len(params) >= 1  # page, username, password

        # Should have auth mechanism
        auth = kg.get_nodes_by_type(NodeType.AUTH_MECHANISM)
        assert len(auth) >= 1

        # Should have security controls
        ctrls = kg.get_nodes_by_type(NodeType.SECURITY_CTRL)
        assert len(ctrls) >= 1

    def test_build_from_dom(self) -> None:
        snap = DOMSnapshot(
            url="https://example.com/login",
            timestamp=0,
            forms=[
                FormData(
                    action="/api/login",
                    method="POST",
                    inputs=[
                        FormInput(name="email", input_type="email"),
                        FormInput(name="password", input_type="password"),
                    ],
                )
            ],
        )
        builder = GraphBuilder()
        kg = builder.build(dom_snapshots=[snap])

        params = kg.get_nodes_by_type(NodeType.PARAMETER)
        param_names = [data.get("param_name") for _, data in params]
        assert "email" in param_names
        assert "password" in param_names

    def test_deduplication(self) -> None:
        """Building from the same HAR twice shouldn't duplicate nodes."""
        har = self._make_har()
        builder = GraphBuilder()
        kg = builder.build(har_files=[har, har])
        eps = kg.get_nodes_by_type(NodeType.ENDPOINT)
        # Should still be 2 endpoints, not 4
        assert len(eps) == 2


class TestTechDetector:
    def test_detect_from_headers(self) -> None:
        detector = TechDetector()
        stack = detector.detect(
            response_headers={
                "Server": "nginx/1.25.0",
                "X-Powered-By": "Express",
                "CF-Ray": "abc123",
            }
        )
        assert "Nginx" in stack.servers
        assert "Express" in stack.servers
        assert "Cloudflare" in stack.cdns

    def test_detect_from_scripts(self) -> None:
        detector = TechDetector()
        stack = detector.detect(
            script_sources=[
                "https://cdn.example.com/react.production.min.js",
                "https://www.google-analytics.com/analytics.js",
            ]
        )
        assert "React" in stack.frameworks
        assert "Google Analytics" in stack.analytics

    def test_detect_from_html(self) -> None:
        detector = TechDetector()
        stack = detector.detect(
            html_content='<div id="__NEXT_DATA__">{"props":{}}</div>'
        )
        assert "Next.js" in stack.frameworks or "React" in stack.frameworks

    def test_detect_from_meta(self) -> None:
        detector = TechDetector()
        stack = detector.detect(meta_tags={"generator": "WordPress 6.4"})
        assert "WordPress" in stack.cms

    def test_combined_detection(self) -> None:
        detector = TechDetector()
        stack = detector.detect(
            response_headers={"Server": "nginx"},
            script_sources=["vue.min.js", "hotjar.js"],
            meta_tags={"generator": "Drupal 10"},
        )
        assert "Nginx" in stack.servers
        assert "Vue.js" in stack.frameworks
        assert "Hotjar" in stack.analytics
        assert "Drupal" in stack.cms
