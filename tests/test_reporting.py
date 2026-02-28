"""Tests for report generation."""

import tempfile
from pathlib import Path

from nazitest.models.exploit import ExploitResult
from nazitest.models.graph import GraphSnapshot, Hypothesis
from nazitest.models.types import Severity
from nazitest.reporting.generator import ReportGenerator


class TestReportGenerator:
    def _make_report(self, tmpdir: str) -> Path:
        run_path = Path(tmpdir)
        gen = ReportGenerator(run_path)

        graph = GraphSnapshot(
            hypotheses=[
                Hypothesis(
                    id="h1",
                    title="SQL Injection in Login",
                    description="The login form is vulnerable to SQL injection",
                    vuln_type="sqli",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    confirmed=True,
                    target_endpoint="/api/login",
                    target_parameter="username",
                    owasp_category="A03:2021 Injection",
                    cwe_id="CWE-89",
                ),
                Hypothesis(
                    id="h2",
                    title="Missing CSRF Protection",
                    description="Forms lack CSRF tokens",
                    vuln_type="csrf",
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    confirmed=False,
                ),
            ]
        )

        exploit_results = [
            ExploitResult(
                hypothesis_id="h1",
                confirmed=True,
                poc_script='curl -X POST https://example.com/login -d "user=admin\' OR 1=1--"',
                remediation="Use parameterized queries",
            )
        ]

        return gen.generate(
            graph=graph,
            exploit_results=exploit_results,
            target_url="https://example.com",
            run_id="test_run_001",
        )

    def test_generates_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = self._make_report(tmpdir)
            assert html_path.exists()
            assert html_path.suffix == ".html"

    def test_html_contains_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = self._make_report(tmpdir)
            content = html_path.read_text()
            assert "SQL Injection in Login" in content
            assert "example.com" in content

    def test_json_report_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_report(tmpdir)
            json_path = Path(tmpdir) / "report" / "report.json"
            assert json_path.exists()

            import orjson
            data = orjson.loads(json_path.read_bytes())
            assert data["summary"]["confirmed_vulnerabilities"] == 1
            assert data["summary"]["high"] == 1
            assert len(data["all_hypotheses"]) == 2

    def test_empty_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(Path(tmpdir))
            html_path = gen.generate(target_url="https://example.com")
            assert html_path.exists()
