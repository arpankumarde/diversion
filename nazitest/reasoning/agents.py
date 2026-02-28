"""LLM agents — Strategist, Scout, CrossValidator, ExploitPlanner."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

from nazitest.models.exploit import ExploitStrategy
from nazitest.models.graph import Hypothesis
from nazitest.models.types import HttpMethod, Severity
from nazitest.reasoning.openrouter import OpenRouterClient
from nazitest.reasoning.sanitizer import LLMDataSanitizer

logger = logging.getLogger(__name__)


class BaseAgent:
    """Base class for all LLM agents. Uses shared OpenRouterClient (DRY)."""

    role: str = ""

    def __init__(
        self,
        client: OpenRouterClient,
        sanitizer: LLMDataSanitizer | None = None,
    ) -> None:
        self.client = client
        self.sanitizer = sanitizer or LLMDataSanitizer()

    async def _ask(
        self,
        system_prompt: str,
        user_message: str,
        structured_output: dict | None = None,
    ) -> str:
        """Send a message to the LLM and get the response content."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        result = await self.client.reason(
            role=self.role,
            messages=messages,
            structured_output=structured_output,
        )
        return result["content"]

    def _sanitize(self, data: Any) -> Any:
        return self.sanitizer.sanitize(data)


class Strategist(BaseAgent):
    """Lead reasoning agent — reviews knowledge graph, generates hypotheses."""

    role = "strategist"

    SYSTEM_PROMPT = (
        "You are an expert penetration tester analyzing a web application's attack surface. "
        "You have access to a knowledge graph of the target containing endpoints, parameters, "
        "authentication mechanisms, security controls, and technologies. "
        "Your job is to: "
        "1) Identify potential vulnerabilities based on the data "
        "2) Generate ranked hypotheses with descriptions "
        "3) Assign investigation tasks for scout agents "
        "Be thorough but avoid false positives. Consider OWASP Top 10 categories."
    )

    async def analyze(self, graph_summary: dict) -> str:
        """Analyze the knowledge graph and produce an audit plan."""
        sanitized = self._sanitize(graph_summary)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Analyze this knowledge graph and create an audit plan:\n\n{sanitized}",
        )

    async def hypothesize(self, analysis: str, graph_summary: dict) -> str:
        """Generate vulnerability hypotheses based on analysis."""
        sanitized = self._sanitize(graph_summary)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Based on this analysis:\n{analysis}\n\n"
            f"And this knowledge graph data:\n{sanitized}\n\n"
            "Generate specific vulnerability hypotheses. For each, provide:\n"
            "- Title\n- Description\n- Target endpoint and parameter\n"
            "- Vulnerability type (sqli, xss, idor, ssrf, etc.)\n"
            "- OWASP category\n- Estimated severity\n"
            "- Suggested investigation steps",
        )

    HYPOTHESES_SCHEMA: dict[str, Any] = {
        "name": "hypotheses",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "vuln_type": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "enum": [
                                    "critical",
                                    "high",
                                    "medium",
                                    "low",
                                    "info",
                                ],
                            },
                            "confidence": {"type": "number"},
                            "target_endpoint": {"type": "string"},
                            "target_parameter": {"type": "string"},
                            "owasp_category": {"type": "string"},
                            "cwe_id": {"type": "string"},
                        },
                        "required": [
                            "id",
                            "title",
                            "description",
                            "vuln_type",
                            "severity",
                            "confidence",
                            "target_endpoint",
                            "target_parameter",
                            "owasp_category",
                            "cwe_id",
                        ],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["hypotheses"],
            "additionalProperties": False,
        },
    }

    async def hypothesize_structured(
        self, analysis: str, graph_summary: dict
    ) -> list[Hypothesis]:
        """Generate structured Hypothesis objects via JSON schema output."""
        sanitized = self._sanitize(graph_summary)
        raw = await self._ask(
            self.SYSTEM_PROMPT,
            f"Based on this analysis:\n{analysis}\n\n"
            f"And this knowledge graph data:\n{sanitized}\n\n"
            "Generate specific vulnerability hypotheses as structured JSON. "
            "For each hypothesis include: id, title, description, vuln_type, "
            "severity (critical/high/medium/low/info), confidence (0.0-1.0), "
            "target_endpoint, target_parameter, owasp_category, cwe_id.",
            structured_output=self.HYPOTHESES_SCHEMA,
        )
        return self._parse_hypotheses(raw)

    @staticmethod
    def _parse_hypotheses(raw: str) -> list[Hypothesis]:
        """Parse LLM output into Hypothesis objects. Handles JSON and text fallback."""
        # Try JSON parse first
        try:
            data = json.loads(raw)
            items = data.get("hypotheses", data) if isinstance(data, dict) else data
            if not isinstance(items, list):
                items = [items]
            hypotheses = []
            for item in items:
                severity_str = item.get("severity", "medium")
                try:
                    severity = Severity(severity_str.lower())
                except ValueError:
                    severity = Severity.MEDIUM
                hypotheses.append(
                    Hypothesis(
                        id=item.get("id", f"hyp-{uuid.uuid4().hex[:8]}"),
                        title=item.get("title", "Unknown"),
                        description=item.get("description", ""),
                        vuln_type=item.get("vuln_type", ""),
                        severity=severity,
                        confidence=float(item.get("confidence", 0.3)),
                        target_endpoint=item.get("target_endpoint", ""),
                        target_parameter=item.get("target_parameter", ""),
                        owasp_category=item.get("owasp_category", ""),
                        cwe_id=item.get("cwe_id", ""),
                    )
                )
            return hypotheses
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

        # Fallback: split on "HYPOTHESIS N:" pattern to get real blocks
        hypotheses = []
        blocks = re.split(
            r"(?:^|\n)(?:#{1,3}\s*)?HYPOTHESIS\s+\d+\s*[:—–-]\s*",
            raw,
            flags=re.IGNORECASE,
        )
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            lines = block.split("\n")
            title = lines[0].strip().rstrip(":")
            if not title or len(title) < 5:
                continue
            body = "\n".join(lines[1:])

            # Try to extract structured fields from the markdown body
            def _extract(label: str) -> str:
                m = re.search(
                    rf"(?:^|\n)\**{label}\**[:\s]*\**\s*(.+?)(?:\n\**[A-Z]|\n---|\Z)",
                    body,
                    re.DOTALL | re.IGNORECASE,
                )
                return m.group(1).strip() if m else ""

            desc = _extract("Description")
            vuln_type = _extract("Vulnerability Type")
            owasp = _extract("OWASP Category")
            cwe = _extract("CWE")
            endpoint = _extract("Target")
            sev_raw = _extract("Estimated Severity") or _extract("Severity")

            # Parse severity from text like "CRITICAL (CVSS 9.8)"
            severity = Severity.MEDIUM
            if sev_raw:
                for s in Severity:
                    if s.value in sev_raw.lower():
                        severity = s
                        break

            # Parse confidence from summary table if present
            conf = 0.3
            conf_match = re.search(
                re.escape(title[:40]) + r".*?(\d{1,3})%",
                raw,
            )
            if conf_match:
                conf = int(conf_match.group(1)) / 100.0

            hypotheses.append(
                Hypothesis(
                    id=f"hyp-{uuid.uuid4().hex[:8]}",
                    title=title[:200],
                    description=(desc or body)[:2000],
                    vuln_type=vuln_type.strip("`").split("—")[0].strip()
                    if vuln_type
                    else "",
                    severity=severity,
                    confidence=conf,
                    target_endpoint=endpoint[:500] if endpoint else "",
                    owasp_category=owasp.strip("*").strip() if owasp else "",
                    cwe_id=cwe.strip() if cwe else "",
                )
            )
        return hypotheses


class Scout(BaseAgent):
    """Exploration agent — investigates specific hypotheses."""

    role = "scout"

    SYSTEM_PROMPT = (
        "You are a security researcher investigating a specific vulnerability hypothesis. "
        "Analyze the provided evidence and determine if the hypothesis is likely valid. "
        "Look for supporting and contradicting evidence. "
        "Be precise about what evidence supports or contradicts the hypothesis."
    )

    async def investigate(self, hypothesis: dict, evidence: dict) -> str:
        """Investigate a hypothesis with available evidence."""
        sanitized_evidence = self._sanitize(evidence)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Investigate this hypothesis:\n{hypothesis}\n\n"
            f"Available evidence:\n{sanitized_evidence}\n\n"
            "Analyze: Is this vulnerability likely real? "
            "What additional evidence would confirm or deny it? "
            "Rate your confidence (0.0 to 1.0) and explain.",
        )


class CrossValidator(BaseAgent):
    """Independent verification agent — challenges assumptions."""

    role = "cross_validator"

    SYSTEM_PROMPT = (
        "You are an independent security reviewer. Your job is to challenge vulnerability "
        "findings and check for false positives. You should be skeptical and look for "
        "alternative explanations. Consider: "
        "1) Could the observed behavior be normal? "
        "2) Are there security controls that would prevent exploitation? "
        "3) Is the evidence sufficient to confirm the vulnerability? "
        "4) What would a definitive test look like?"
    )

    async def challenge(self, hypothesis: dict, evidence: dict) -> str:
        """Challenge a high-confidence hypothesis."""
        sanitized = self._sanitize(evidence)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Challenge this vulnerability finding:\n{hypothesis}\n\n"
            f"Supporting evidence:\n{sanitized}\n\n"
            "Is this a real vulnerability or a false positive? "
            "What alternative explanations exist? "
            "Rate your adjusted confidence (0.0 to 1.0).",
        )


class ExploitPlanner(BaseAgent):
    """Exploit generation agent — creates PoC strategies."""

    role = "exploit_planner"

    SYSTEM_PROMPT = (
        "You are an expert exploit developer. Given a confirmed vulnerability hypothesis, "
        "generate a safe, minimal proof-of-concept exploit strategy. "
        "The exploit should: "
        "1) Confirm the vulnerability exists (not cause damage) "
        "2) Be reproducible "
        "3) Include the exact HTTP request(s) needed "
        "4) Suggest encoding and delivery variations if the first attempt is blocked "
        "Output should be specific enough to construct curl_cffi or browser replay requests."
    )

    STRATEGY_SCHEMA: dict[str, Any] = {
        "name": "exploit_strategy",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "http_method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                },
                "url": {"type": "string"},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "body": {"type": "string"},
                "params": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "payload": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": [
                "http_method",
                "url",
                "headers",
                "body",
                "params",
                "payload",
                "description",
            ],
            "additionalProperties": False,
        },
    }

    async def plan(
        self, hypothesis: dict, previous_attempts: list[dict] | None = None
    ) -> str:
        """Plan an exploit strategy for a confirmed hypothesis."""
        context = f"Vulnerability:\n{hypothesis}\n\n"
        if previous_attempts:
            sanitized_attempts = self._sanitize(previous_attempts)
            context += f"Previous failed attempts:\n{sanitized_attempts}\n\n"
            context += (
                "Generate an alternative strategy that avoids "
                "the same failure mode."
            )
        else:
            context += "Generate the initial exploit strategy."

        return await self._ask(self.SYSTEM_PROMPT, context)

    async def plan_structured(
        self,
        hypothesis: dict,
        previous_attempts: list[dict] | None = None,
        target_url: str = "",
    ) -> ExploitStrategy:
        """Plan an exploit and return a parsed ExploitStrategy.

        Tries structured JSON output first, falls back to text
        plan + regex parsing.
        """
        context = f"Vulnerability:\n{hypothesis}\n\n"
        if target_url:
            context += f"Target base URL: {target_url}\n\n"
        context += (
            "IMPORTANT: The 'url' field must be an absolute "
            "URL starting with http:// or https://. "
            "Do NOT return relative paths.\n\n"
        )
        if previous_attempts:
            sanitized_attempts = self._sanitize(previous_attempts)
            context += (
                f"Previous failed attempts:\n{sanitized_attempts}\n\n"
                "Generate an alternative strategy that avoids "
                "the same failure mode.\n"
            )
        else:
            context += "Generate the initial exploit strategy.\n"
        context += (
            "Return the exploit as structured JSON with: "
            "http_method, url, headers, body, params, "
            "payload, description."
        )

        hypothesis_id = hypothesis.get("id", "unknown")

        try:
            raw = await self._ask(
                self.SYSTEM_PROMPT,
                context,
                structured_output=self.STRATEGY_SCHEMA,
            )
            return self._parse_strategy(
                raw, hypothesis_id, hypothesis, target_url
            )
        except Exception as e:
            logger.warning(
                "Structured exploit plan failed (%s), "
                "falling back to text",
                e,
            )

        # Fallback: text plan + regex extraction
        text = await self.plan(hypothesis, previous_attempts)
        return self._parse_strategy_from_text(
            text, hypothesis_id, hypothesis, target_url
        )

    @staticmethod
    def _resolve_url(
        url: str,
        target_url: str = "",
        endpoint: str = "",
    ) -> str:
        """Clean and resolve a URL from LLM output.

        Strips trailing junk, resolves relative paths against
        target_url, falls back to endpoint if empty.
        """
        url = url.strip().rstrip("`\"'>,;) ")
        if not url and endpoint:
            url = endpoint.strip().rstrip("`\"'>,;) ")
        if not url:
            return target_url
        parsed = urlparse(url)
        if not parsed.scheme and target_url:
            url = urljoin(target_url, url)
        return url

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        """Extract a JSON object from text that may contain
        markdown code fences or other wrapping."""
        # Try direct parse
        text = text.strip()
        if text.startswith("{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass

        # Try extracting from markdown code fence
        fence_match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```",
            text,
            re.DOTALL,
        )
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding any top-level JSON object
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        return None

    @staticmethod
    def _parse_strategy(
        raw: str,
        hypothesis_id: str,
        hypothesis: dict | None = None,
        target_url: str = "",
    ) -> ExploitStrategy:
        """Parse JSON string into an ExploitStrategy."""
        data = ExploitPlanner._extract_json(raw)
        if data is None:
            raise ValueError("No valid JSON found in response")
        endpoint = (
            (hypothesis or {}).get("target_endpoint", "")
        )
        return ExploitStrategy(
            hypothesis_id=hypothesis_id,
            http_method=HttpMethod(
                data.get("http_method", "GET")
            ),
            url=ExploitPlanner._resolve_url(
                data.get("url", ""),
                target_url,
                endpoint,
            ),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            params=data.get("params", {}),
            payload=data.get("payload", ""),
            description=data.get("description", ""),
        )

    @staticmethod
    def _parse_strategy_from_text(
        text: str,
        hypothesis_id: str,
        hypothesis: dict,
        target_url: str = "",
    ) -> ExploitStrategy:
        """Best-effort extraction of strategy fields from text."""
        endpoint = hypothesis.get("target_endpoint", "")

        # Try to find JSON in the text
        data = ExploitPlanner._extract_json(text)
        if data and ("url" in data or "http_method" in data):
            try:
                return ExploitStrategy(
                    hypothesis_id=hypothesis_id,
                    http_method=HttpMethod(
                        data.get("http_method", "GET")
                    ),
                    url=ExploitPlanner._resolve_url(
                        data.get("url", ""),
                        target_url,
                        endpoint,
                    ),
                    headers=data.get("headers", {}),
                    body=data.get("body", ""),
                    params=data.get("params", {}),
                    payload=data.get("payload", ""),
                    description=data.get("description", ""),
                )
            except (ValueError, KeyError):
                pass

        # Extract what we can from text
        method_match = re.search(
            r"\b(GET|POST|PUT|DELETE|PATCH)\b", text
        )
        url_match = re.search(r"(https?://\S+)", text)
        payload_match = re.search(
            r"payload[:\s]+[\"'`](.+?)[\"'`]", text, re.I
        )

        raw_url = (
            url_match.group(1)
            if url_match
            else ""
        )

        return ExploitStrategy(
            hypothesis_id=hypothesis_id,
            http_method=(
                HttpMethod(method_match.group(1))
                if method_match
                else HttpMethod.GET
            ),
            url=ExploitPlanner._resolve_url(
                raw_url, target_url, endpoint
            ),
            payload=(
                payload_match.group(1)
                if payload_match
                else ""
            ),
            description=text[:500],
        )
