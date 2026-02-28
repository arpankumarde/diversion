"""Knowledge graph models — nodes, edges, hypotheses, evidence."""

from __future__ import annotations

from pydantic import BaseModel, Field

from nazitest.models.types import EdgeType, NodeType, Severity


class GraphNode(BaseModel):
    """A node in the knowledge graph."""

    id: str
    node_type: NodeType
    label: str
    properties: dict[str, str | int | float | bool | list[str]] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """An edge in the knowledge graph."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: dict[str, str | int | float | bool] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Supporting evidence for a vulnerability hypothesis."""

    id: str
    description: str
    source: str = ""  # "har", "dom", "code", "llm"
    artifact_ref: str = ""  # path or ID to the source artifact
    confidence_delta: float = 0.0  # how much this changes confidence
    raw_data: dict[str, str | int | float | bool | list[str]] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    """A vulnerability hypothesis with belief tracking."""

    id: str
    title: str
    description: str
    vuln_type: str = ""  # "sqli", "xss", "idor", "ssrf", etc.
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.3  # Starting baseline per PRD
    target_endpoint: str = ""
    target_parameter: str = ""
    http_method: str = ""  # GET, POST — from LLM hypothesis
    evidence: list[Evidence] = Field(default_factory=list)
    owasp_category: str = ""
    cwe_id: str = ""
    cvss_score: float | None = None
    confirmed: bool = False
    exploitation_attempted: bool = False

    def is_ready_for_exploitation(self) -> bool:
        return self.confidence > 0.75

    def is_ready_for_cross_validation(self) -> bool:
        return self.confidence > 0.6


class GraphSnapshot(BaseModel):
    """Serializable snapshot of the knowledge graph."""

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
