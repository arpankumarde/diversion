"""Knowledge graph — NetworkX wrapper with typed nodes/edges per PRD section 8."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx
import orjson

from nazitest.models.graph import GraphEdge, GraphNode, GraphSnapshot, Hypothesis
from nazitest.models.types import EdgeType, NodeType

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """Typed knowledge graph built on NetworkX.

    12 node types, 11 edge types matching PRD section 8.
    """

    def __init__(self) -> None:
        self._graph = nx.DiGraph()
        self._hypotheses: dict[str, Hypothesis] = {}
        self._node_counter = 0

    def _next_id(self, prefix: str) -> str:
        self._node_counter += 1
        return f"{prefix}_{self._node_counter}"

    # --- Node operations ---

    def add_node(
        self,
        node_type: NodeType,
        label: str,
        node_id: str | None = None,
        **properties: Any,
    ) -> str:
        """Add a typed node. Returns the node ID."""
        nid = node_id or self._next_id(node_type.value)
        self._graph.add_node(
            nid,
            node_type=node_type.value,
            label=label,
            **properties,
        )
        return nid

    def add_endpoint(self, url: str, method: str) -> str:
        return self.add_node(NodeType.ENDPOINT, f"{method} {url}", url=url, method=method)

    def add_parameter(self, name: str, location: str, param_type: str = "") -> str:
        return self.add_node(
            NodeType.PARAMETER, name, param_name=name, location=location, param_type=param_type
        )

    def add_technology(self, name: str, version: str = "") -> str:
        return self.add_node(NodeType.TECHNOLOGY, name, version=version)

    def add_security_control(self, name: str, value: str = "") -> str:
        return self.add_node(NodeType.SECURITY_CTRL, name, value=value)

    def add_cookie(self, name: str, domain: str = "", **flags: Any) -> str:
        return self.add_node(NodeType.COOKIE, name, domain=domain, **flags)

    def add_vulnerability(self, title: str, vuln_type: str = "") -> str:
        return self.add_node(NodeType.VULNERABILITY, title, vuln_type=vuln_type)

    def add_evidence(self, description: str, source: str = "") -> str:
        return self.add_node(NodeType.EVIDENCE, description, source=source)

    # --- Edge operations ---

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        **properties: Any,
    ) -> None:
        """Add a typed edge between two nodes."""
        if source_id not in self._graph:
            raise ValueError(f"Source node not found: {source_id}")
        if target_id not in self._graph:
            raise ValueError(f"Target node not found: {target_id}")
        self._graph.add_edge(
            source_id,
            target_id,
            edge_type=edge_type.value,
            **properties,
        )

    # --- Hypothesis operations ---

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._hypotheses[hypothesis.id] = hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hypothesis_id)

    def get_all_hypotheses(self) -> list[Hypothesis]:
        return list(self._hypotheses.values())

    def get_confirmed_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.confirmed]

    def get_exploitable_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.is_ready_for_exploitation()]

    # --- Query operations ---

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        if node_id not in self._graph:
            return None
        return dict(self._graph.nodes[node_id])

    def get_nodes_by_type(self, node_type: NodeType) -> list[tuple[str, dict[str, Any]]]:
        return [
            (nid, dict(data))
            for nid, data in self._graph.nodes(data=True)
            if data.get("node_type") == node_type.value
        ]

    def get_edges_by_type(self, edge_type: EdgeType) -> list[tuple[str, str, dict[str, Any]]]:
        return [
            (u, v, dict(data))
            for u, v, data in self._graph.edges(data=True)
            if data.get("edge_type") == edge_type.value
        ]

    def get_neighbors(self, node_id: str, edge_type: EdgeType | None = None) -> list[str]:
        if node_id not in self._graph:
            return []
        neighbors = []
        for _, target, data in self._graph.edges(node_id, data=True):
            if edge_type is None or data.get("edge_type") == edge_type.value:
                neighbors.append(target)
        return neighbors

    def get_predecessors(self, node_id: str, edge_type: EdgeType | None = None) -> list[str]:
        if node_id not in self._graph:
            return []
        predecessors = []
        for source, _, data in self._graph.in_edges(node_id, data=True):
            if edge_type is None or data.get("edge_type") == edge_type.value:
                predecessors.append(source)
        return predecessors

    # --- Stats ---

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    # --- Serialization ---

    def to_snapshot(self) -> GraphSnapshot:
        """Serialize to a GraphSnapshot for storage."""
        nodes = []
        for nid, data in self._graph.nodes(data=True):
            node_type_str = data.pop("node_type", "endpoint")
            label = data.pop("label", "")
            nodes.append(
                GraphNode(
                    id=nid,
                    node_type=NodeType(node_type_str),
                    label=label,
                    properties=data,
                )
            )
            # Restore popped data
            self._graph.nodes[nid]["node_type"] = node_type_str
            self._graph.nodes[nid]["label"] = label

        edges = []
        for u, v, data in self._graph.edges(data=True):
            edge_type_str = data.pop("edge_type", "accepts_input")
            edges.append(
                GraphEdge(
                    source_id=u,
                    target_id=v,
                    edge_type=EdgeType(edge_type_str),
                    properties=data,
                )
            )
            self._graph.edges[u, v]["edge_type"] = edge_type_str

        return GraphSnapshot(
            nodes=nodes,
            edges=edges,
            hypotheses=list(self._hypotheses.values()),
        )

    @classmethod
    def from_snapshot(cls, snapshot: GraphSnapshot) -> KnowledgeGraph:
        """Deserialize from a GraphSnapshot."""
        kg = cls()
        for node in snapshot.nodes:
            kg.add_node(
                node.node_type,
                node.label,
                node_id=node.id,
                **node.properties,
            )
        for edge in snapshot.edges:
            kg.add_edge(
                edge.source_id,
                edge.target_id,
                edge.edge_type,
                **edge.properties,
            )
        for h in snapshot.hypotheses:
            kg.add_hypothesis(h)
        return kg

    def to_json(self) -> bytes:
        """Serialize to JSON bytes."""
        snapshot = self.to_snapshot()
        return orjson.dumps(snapshot.model_dump(mode="json"), option=orjson.OPT_INDENT_2)

    @classmethod
    def from_json(cls, data: bytes) -> KnowledgeGraph:
        """Deserialize from JSON bytes."""
        raw = orjson.loads(data)
        snapshot = GraphSnapshot.model_validate(raw)
        return cls.from_snapshot(snapshot)
