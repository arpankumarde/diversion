"""Tests for shared Pydantic models."""

from nazitest.models.config import RunConfig, ScopeConfig
from nazitest.models.exploit import ExploitResult, ExploitStrategy
from nazitest.models.graph import Evidence, GraphEdge, GraphNode, GraphSnapshot, Hypothesis
from nazitest.models.har import HAREntry, HARFile, HARRequest, HARResponse
from nazitest.models.recon import DOMSnapshot, Endpoint, SiteMap
from nazitest.models.types import (
    ArtifactType,
    EdgeType,
    HttpMethod,
    NodeType,
    OrchestratorPhase,
    Severity,
)


class TestEnums:
    def test_http_methods(self) -> None:
        assert HttpMethod.GET.value == "GET"
        assert HttpMethod.POST.value == "POST"

    def test_severity_ordering(self) -> None:
        severities = [s.value for s in Severity]
        assert "critical" in severities
        assert "info" in severities

    def test_orchestrator_phases(self) -> None:
        phases = list(OrchestratorPhase)
        assert phases[0] == OrchestratorPhase.INIT
        assert phases[-1] == OrchestratorPhase.DONE

    def test_node_types_match_prd(self) -> None:
        assert len(NodeType) == 12

    def test_edge_types_match_prd(self) -> None:
        assert len(EdgeType) == 11

    def test_artifact_types(self) -> None:
        assert ArtifactType.HAR.value == "har"
        assert ArtifactType.SCREENSHOT.value == "screenshot"


class TestHARModels:
    def test_har_entry_creation(self) -> None:
        entry = HAREntry(
            request=HARRequest(method="GET", url="https://example.com/api/users"),
            response=HARResponse(status=200),
        )
        assert entry.request.method == "GET"
        assert entry.response.status == 200

    def test_har_file_structure(self) -> None:
        har = HARFile()
        assert har.log.version == "1.2"
        assert har.log.creator.name == "nazitest"
        assert har.log.entries == []

    def test_har_serialization(self) -> None:
        entry = HAREntry(
            request=HARRequest(method="POST", url="https://example.com/login"),
            response=HARResponse(status=302),
        )
        data = entry.model_dump()
        assert data["request"]["method"] == "POST"
        roundtrip = HAREntry.model_validate(data)
        assert roundtrip.request.url == entry.request.url


class TestReconModels:
    def test_dom_snapshot(self) -> None:
        snap = DOMSnapshot(
            url="https://example.com",
            timestamp=1234567890.0,
            links=["https://example.com/about", "https://example.com/login"],
        )
        assert len(snap.links) == 2
        assert snap.forms == []

    def test_endpoint(self) -> None:
        ep = Endpoint(
            url="https://example.com/api/users",
            method=HttpMethod.GET,
            status_code=200,
            content_type="application/json",
        )
        assert ep.requires_auth is False

    def test_sitemap_defaults(self) -> None:
        sm = SiteMap()
        assert sm.endpoints == []
        assert sm.api_routes == []


class TestGraphModels:
    def test_graph_node(self) -> None:
        node = GraphNode(
            id="ep_1",
            node_type=NodeType.ENDPOINT,
            label="GET /api/users",
            properties={"method": "GET", "path": "/api/users"},
        )
        assert node.node_type == NodeType.ENDPOINT

    def test_graph_edge(self) -> None:
        edge = GraphEdge(
            source_id="ep_1",
            target_id="param_1",
            edge_type=EdgeType.ACCEPTS_INPUT,
        )
        assert edge.edge_type == EdgeType.ACCEPTS_INPUT

    def test_hypothesis_lifecycle(self) -> None:
        h = Hypothesis(
            id="h_1",
            title="SQL injection in login",
            description="Login form may be vulnerable to SQL injection",
            vuln_type="sqli",
            severity=Severity.HIGH,
        )
        assert h.confidence == 0.3
        assert not h.is_ready_for_cross_validation()
        assert not h.is_ready_for_exploitation()

        h.confidence = 0.65
        assert h.is_ready_for_cross_validation()
        assert not h.is_ready_for_exploitation()

        h.confidence = 0.8
        assert h.is_ready_for_exploitation()

    def test_graph_snapshot_serialization(self) -> None:
        snap = GraphSnapshot(
            nodes=[
                GraphNode(id="n1", node_type=NodeType.ENDPOINT, label="GET /"),
            ],
            edges=[],
            hypotheses=[],
        )
        data = snap.model_dump()
        roundtrip = GraphSnapshot.model_validate(data)
        assert len(roundtrip.nodes) == 1


class TestExploitModels:
    def test_exploit_strategy_poc_generation(self) -> None:
        strategy = ExploitStrategy(
            hypothesis_id="h_1",
            url="https://example.com/login",
            http_method=HttpMethod.POST,
            body='{"user": "admin", "pass": "test"}',
        )
        poc = strategy.to_poc_script()
        assert "curl_cffi" in poc
        assert "example.com/login" in poc

    def test_exploit_result(self) -> None:
        result = ExploitResult(hypothesis_id="h_1", confirmed=True)
        assert result.confirmed
        assert result.attempts == []


class TestConfigModels:
    def test_scope_config(self) -> None:
        scope = ScopeConfig(
            target_url="https://example.com",
            allowed_domains=["example.com"],
        )
        assert "example.com" in scope.summary()

    def test_scope_defaults(self) -> None:
        scope = ScopeConfig(target_url="https://example.com")
        assert scope.max_crawl_depth == 5
        assert scope.max_crawl_pages == 200
        assert scope.include_subdomains is True

    def test_run_config(self) -> None:
        run = RunConfig(
            scope=ScopeConfig(target_url="https://example.com"),
        )
        assert run.time_limit_minutes == 120
        assert run.human_in_loop is True
        assert run.exploit_mode == "confirm"
