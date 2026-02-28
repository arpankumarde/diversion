"""Report generator — reads knowledge graph + exploit results, generates reports."""

from __future__ import annotations

import html as html_mod
import logging
import time
from pathlib import Path
from typing import Any

import orjson
from jinja2 import Environment, FileSystemLoader, select_autoescape

from nazitest.models.exploit import ExploitResult
from nazitest.models.graph import GraphSnapshot, Hypothesis
from nazitest.models.types import Severity

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportData(dict):
    """Report data container (dict subclass for Jinja2 compatibility)."""

    pass


class ReportGenerator:
    """Generates structured JSON and HTML reports."""

    def __init__(self, run_path: Path) -> None:
        self.run_path = run_path
        self.report_dir = run_path / "report"
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        graph: GraphSnapshot | None = None,
        exploit_results: list[ExploitResult] | None = None,
        target_url: str = "",
        run_id: str = "",
    ) -> Path:
        """Generate JSON and HTML reports. Returns path to HTML report."""
        report_data = self._build_report_data(
            graph, exploit_results or [], target_url, run_id
        )

        # Save JSON report
        json_path = self.report_dir / "report.json"
        json_path.write_bytes(
            orjson.dumps(report_data, option=orjson.OPT_INDENT_2)
        )

        # Render HTML report
        html_path = self._render_html(report_data)

        return html_path

    def save_meta(self, meta: dict[str, Any]) -> Path:
        """Save meta.json with run metadata, token usage, and network stats."""
        meta_path = self.report_dir / "meta.json"
        meta_path.write_bytes(
            orjson.dumps(meta, option=orjson.OPT_INDENT_2)
        )
        return meta_path

    def _build_report_data(
        self,
        graph: GraphSnapshot | None,
        exploit_results: list[ExploitResult],
        target_url: str,
        run_id: str,
    ) -> dict[str, Any]:
        hypotheses = graph.hypotheses if graph else []
        confirmed = [h for h in hypotheses if h.confirmed]
        by_severity = self._group_by_severity(hypotheses)

        return {
            "metadata": {
                "target_url": target_url,
                "run_id": run_id,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "tool": "NAZITEST",
                "version": "0.1.0",
            },
            "summary": {
                "total_hypotheses": len(hypotheses),
                "confirmed_vulnerabilities": len(confirmed),
                "critical": len(by_severity.get(Severity.CRITICAL, [])),
                "high": len(by_severity.get(Severity.HIGH, [])),
                "medium": len(by_severity.get(Severity.MEDIUM, [])),
                "low": len(by_severity.get(Severity.LOW, [])),
                "info": len(by_severity.get(Severity.INFO, [])),
            },
            "vulnerabilities": [
                self._vuln_to_dict(h, exploit_results) for h in hypotheses
            ],
            "all_hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "graph_stats": {
                "nodes": len(graph.nodes) if graph else 0,
                "edges": len(graph.edges) if graph else 0,
            },
            "exploit_results": [r.model_dump(mode="json") for r in exploit_results],
        }

    def _vuln_to_dict(
        self, h: Hypothesis, results: list[ExploitResult]
    ) -> dict[str, Any]:
        matching_result = next(
            (r for r in results if r.hypothesis_id == h.id), None
        )
        return {
            "id": h.id,
            "title": h.title,
            "description": h.description,
            "severity": h.severity.value,
            "vuln_type": h.vuln_type,
            "confidence": h.confidence,
            "endpoint": h.target_endpoint,
            "parameter": h.target_parameter,
            "owasp_category": h.owasp_category,
            "cwe_id": h.cwe_id,
            "cvss_score": h.cvss_score,
            "poc_script": matching_result.poc_script if matching_result else "",
            "remediation": matching_result.remediation if matching_result else "",
            "evidence": [e.model_dump(mode="json") for e in h.evidence],
        }

    @staticmethod
    def _group_by_severity(
        hypotheses: list[Hypothesis],
    ) -> dict[Severity, list[Hypothesis]]:
        groups: dict[Severity, list[Hypothesis]] = {}
        for h in hypotheses:
            groups.setdefault(h.severity, []).append(h)
        return groups

    def _render_html(self, report_data: dict) -> Path:
        """Render HTML report from Jinja2 template."""
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

        try:
            template = env.get_template("report.html.j2")
        except Exception:
            # Template not found — generate minimal HTML
            return self._render_minimal_html(report_data)

        html = template.render(**report_data)
        html_path = self.report_dir / "report.html"
        html_path.write_text(html)
        return html_path

    def _render_minimal_html(self, data: dict) -> Path:
        """Minimal HTML report when template is missing."""
        esc = html_mod.escape
        meta = data.get("metadata", {})
        summary = data.get("summary", {})
        vulns = data.get("vulnerabilities", [])

        vuln_rows = ""
        for v in vulns:
            vuln_rows += (
                f"<tr><td>{esc(str(v['severity']))}</td>"
                f"<td>{esc(str(v['title']))}</td>"
                f"<td>{esc(str(v['endpoint']))}</td>"
                f"<td>{v['confidence']:.0%}</td></tr>\n"
            )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NAZITEST Report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #333; color: white; }}
.critical {{ color: #d32f2f; font-weight: bold; }}
.high {{ color: #f57c00; font-weight: bold; }}
.medium {{ color: #fbc02d; }}
.low {{ color: #388e3c; }}
</style></head><body>
<h1>NAZITEST Security Report</h1>
<p><strong>Target:</strong> {esc(str(meta.get('target_url', 'N/A')))}</p>
<p><strong>Run ID:</strong> {esc(str(meta.get('run_id', 'N/A')))}</p>
<p><strong>Generated:</strong> {esc(str(meta.get('generated_at', 'N/A')))}</p>
<h2>Summary</h2>
<p>Total hypotheses: {summary.get('total_hypotheses', 0)}<br>
Confirmed vulnerabilities: {summary.get('confirmed_vulnerabilities', 0)}<br>
Critical: {summary.get('critical', 0)} |
High: {summary.get('high', 0)} |
Medium: {summary.get('medium', 0)} |
Low: {summary.get('low', 0)}</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>Confidence</th></tr>
{vuln_rows}</table>
</body></html>"""

        html_path = self.report_dir / "report.html"
        html_path.write_text(html)
        return html_path
