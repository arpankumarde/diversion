"""LLM agents — Strategist, Scout, CrossValidator, ExploitPlanner."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

from nazitest.models.exploit import ExploitResponse, ExploitResult, ExploitStrategy
from nazitest.models.graph import Hypothesis
from nazitest.models.types import HttpMethod, Severity
from nazitest.reasoning.openrouter import OpenRouterClient
from nazitest.reasoning.sanitizer import LLMDataSanitizer

logger = logging.getLogger(__name__)


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
        "parameters, authentication mechanisms, security "
        "controls, and technologies. "
        "Your job is to: "
        "1) Identify ALL potential vulnerabilities "
        "2) Generate ranked hypotheses with high confidence "
        "3) Be aggressive — if there's any indicator, flag it "
        "with confidence 0.8+ "
        "4) Cover ALL OWASP Top 10 categories "
        "5) For each parameter, consider: SQLi, XSS, SSRF, "
        "path traversal, command injection, IDOR "
        "6) Don't hold back — false positives are better than "
        "missing a real vulnerability"
    )

    async def analyze(
        self, graph_summary: dict, code_context: dict | None = None,
    ) -> str:
        sanitized = self._sanitize(graph_summary)
        user_msg = (
            f"Analyze this knowledge graph and create an "
            f"aggressive pentest plan:\n\n{sanitized}"
        )
        if code_context:
            user_msg += self._format_code_context(code_context)
        return await self._ask(self.SYSTEM_PROMPT, user_msg)

    @staticmethod
    def _format_code_context(code_context: dict) -> str:
        """Format code analysis results for LLM context."""
        lines = ["\n\n--- SOURCE CODE ANALYSIS ---"]

        routes = code_context.get("routes", [])
        if routes:
            lines.append("Discovered routes from source code:")
            for r in routes:
                methods = ", ".join(r.get("methods", ["?"]))
                handler = r.get("handler", "")
                fpath = r.get("file_path", "")
                lnum = r.get("line_number", 0)
                handler_info = f" -> {handler}" if handler else ""
                loc_info = f" ({fpath}:{lnum})" if fpath else ""
                lines.append(f"  [{methods}] {r.get('path', '?')}{handler_info}{loc_info}")

        sinks = code_context.get("sinks", [])
        if sinks:
            lines.append("\nDangerous sinks detected:")
            for s in sinks:
                lines.append(
                    f"  {s.get('sink_type', '?')}: {s.get('sink', '?')} "
                    f"at {s.get('file_path', '?')}:{s.get('line_number', 0)}"
                )

        auth = code_context.get("auth_patterns", [])
        if auth:
            lines.append("\nAuthentication patterns:")
            for a in auth:
                lines.append(
                    f"  {a.get('type', '?')}: {a.get('name', '?')} "
                    f"at {a.get('file_path', '?')}:{a.get('line_number', 0)}"
                )

        lines.append(
            "\nIf a route has a dangerous sink nearby in the same file, "
            "rate confidence 0.9+."
        )
        return "\n".join(lines)

    async def hypothesize(
        self, analysis: str, graph_summary: dict
    ) -> str:
        sanitized = self._sanitize(graph_summary)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Based on this analysis:\n{analysis}\n\n"
            f"Knowledge graph:\n{sanitized}\n\n"
            "Generate specific vulnerability hypotheses. "
            "For each: Title, Description, Target endpoint "
            "and parameter, Vulnerability type "
            "(sqli, xss, idor, ssrf, cmdi, etc.), "
            "OWASP category, Severity, "
            "Confidence (0.8+ if any indicator), "
            "Specific payloads to try.",
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
                            "description": {
                                "type": "string",
                            },
                            "vuln_type": {
                                "type": "string",
                                "description": (
                                    "Vulnerability class: sqli, xss, "
                                    "cmdi, idor, ssrf, csrf, "
                                    "path_traversal, etc."
                                ),
                            },
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
                                "description": (
                                    "URL path only, e.g. "
                                    "/vulnerabilities/exec/ — "
                                    "do NOT include scheme, host, "
                                    "port, or HTTP method"
                                ),
                            },
                            "target_parameter": {
                                "type": "string",
                                "description": (
                                    "The vulnerable parameter name, "
                                    "e.g. id, ip, username"
                                ),
                            },
                            "http_method": {
                                "type": "string",
                                "description": (
                                    "HTTP method: GET or POST"
                                ),
                                "enum": [
                                    "GET",
                                    "POST",
                                ],
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
                            "http_method",
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
        self,
        analysis: str,
        graph_summary: dict,
        code_context: dict | None = None,
    ) -> list[Hypothesis]:
        sanitized = self._sanitize(graph_summary)
        user_msg = (
            f"Based on this analysis:\n{analysis}\n\n"
            f"Knowledge graph:\n{sanitized}\n\n"
            "Generate vulnerability hypotheses as JSON. "
            "Be aggressive with confidence — 0.8+ if any "
            "basis exists.\n\n"
            "IMPORTANT field rules:\n"
            "- target_endpoint: URL PATH ONLY "
            "(e.g. /vulnerabilities/exec/). "
            "Do NOT include scheme, host, port, or HTTP method.\n"
            "- http_method: GET or POST (the HTTP method to use)\n"
            "- target_parameter: the vulnerable parameter name "
            "(e.g. id, ip, username)\n"
            "- vuln_type: sqli, xss, cmdi, idor, ssrf, csrf, "
            "path_traversal, etc.\n"
            "- severity: critical/high/medium/low/info\n"
            "- confidence: 0.0-1.0"
        )
        if code_context:
            user_msg += self._format_code_context(code_context)
        raw = await self._ask(
            self.SYSTEM_PROMPT,
            user_msg,
            structured_output=self.HYPOTHESES_SCHEMA,
        )
        return self._parse_hypotheses(raw)

    @staticmethod
    def _parse_hypotheses(raw: str) -> list[Hypothesis]:
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
                sev_str = item.get("severity", "medium")
                try:
                    severity = Severity(sev_str.lower())
                except ValueError:
                    severity = Severity.MEDIUM
                endpoint_raw = item.get(
                    "target_endpoint", ""
                )
                # Clean endpoint: strip HTTP method prefix
                # and extract path only
                endpoint_raw = re.sub(
                    r"^(GET|POST|PUT|DELETE|PATCH|HEAD"
                    r"|OPTIONS)\s+",
                    "",
                    endpoint_raw.strip(),
                    flags=re.IGNORECASE,
                )
                # Strip scheme+host if LLM included full URL
                ep_parsed = urlparse(endpoint_raw)
                if ep_parsed.scheme and ep_parsed.netloc:
                    endpoint_clean = ep_parsed.path or "/"
                    if ep_parsed.query:
                        endpoint_clean += (
                            f"?{ep_parsed.query}"
                        )
                else:
                    endpoint_clean = endpoint_raw

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
                        target_endpoint=endpoint_clean,
                        target_parameter=item.get(
                            "target_parameter", ""
                        ),
                        http_method=item.get(
                            "http_method", ""
                        ).upper(),
                        owasp_category=item.get(
                            "owasp_category", ""
                        ),
                        cwe_id=item.get("cwe_id", ""),
                    )
                )
            return hypotheses
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.warning("JSON hypothesis parsing failed: %s", e)

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
            endpoint_raw = _extract("Target")
            # Clean: strip method prefix and extract path
            endpoint_raw = re.sub(
                r"^(GET|POST|PUT|DELETE|PATCH|HEAD"
                r"|OPTIONS)\s+",
                "",
                endpoint_raw.strip(),
                flags=re.IGNORECASE,
            )
            ep_parsed = urlparse(endpoint_raw)
            if ep_parsed.scheme and ep_parsed.netloc:
                endpoint = ep_parsed.path or "/"
                if ep_parsed.query:
                    endpoint += f"?{ep_parsed.query}"
            else:
                endpoint = endpoint_raw
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
        if not hypotheses:
            logger.warning(
                "All hypothesis parsing failed — LLM response may be malformed. "
                "Raw preview: %s",
                raw[:200],
            )
        return hypotheses


class Scout(BaseAgent):
    """Exploration agent — optional, not used in main pipeline."""

    role = "scout"

    SYSTEM_PROMPT = (
        "You are an aggressive penetration tester actively "
        "hunting for vulnerabilities. You are investigating a "
        "specific vulnerability hypothesis. "
        "Your mindset: ASSUME the vulnerability EXISTS and look "
        "for confirming evidence. "
        "Rate your confidence HIGH (0.7+) if: "
        "- The parameter accepts user input "
        "- There's no visible input sanitization "
        "- The technology stack is known to be vulnerable "
        "- Similar endpoints have been vulnerable before "
        "- No WAF/security headers "
        "Only rate below 0.5 if there's strong evidence the "
        "vulnerability does NOT exist."
    )

    async def investigate(
        self, hypothesis: dict, evidence: dict
    ) -> str:
        sanitized_evidence = self._sanitize(evidence)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Investigate this hypothesis:\n{hypothesis}\n\n"
            f"Evidence:\n{sanitized_evidence}\n\n"
            "Is this vulnerability likely exploitable? "
            "Rate your confidence (0.0 to 1.0). "
            "If the parameter takes user input and there's "
            "no clear protection, rate 0.7+.",
        )


class CrossValidator(BaseAgent):
    """Advisory validation agent — optional, not used in main pipeline."""

    role = "cross_validator"

    SYSTEM_PROMPT = (
        "You are a security consultant reviewing vulnerability "
        "findings. Your role is ADVISORY. "
        "Focus on: "
        "1) Any obvious false positive indicators? "
        "2) What specific payloads would best confirm this? "
        "3) What security controls might be in place? "
        "Be fair — don't dismiss vulnerabilities without "
        "strong evidence they're false positives."
    )

    async def challenge(
        self, hypothesis: dict, evidence: dict
    ) -> str:
        sanitized = self._sanitize(evidence)
        return await self._ask(
            self.SYSTEM_PROMPT,
            f"Review this finding:\n{hypothesis}\n\n"
            f"Evidence:\n{sanitized}\n\n"
            "Rate your confidence (0.0 to 1.0). "
            "Suggest specific payloads to confirm.",
        )


class ExploitPlanner(BaseAgent):
    """Agentic exploit planner — LLM-driven feedback loop.

    Architecture:
    1. LLM generates targeted payloads (small set, 3-5)
    2. We send them, collect responses
    3. LLM sees response behavior (sizes, status, reflection)
    4. LLM decides: confirmed / not_vulnerable / try more
    5. If "try more": LLM generates new payloads adapting
       to what it saw. Repeat.

    No hardcoded payload lists. No confidence scores.
    Binary outcome: confirmed or not.
    """

    role = "exploit_planner"

    GENERATE_PROMPT = (
        "You are an expert penetration tester actively "
        "exploiting a target. Generate 3-5 targeted payloads "
        "to test the described vulnerability. "
        "Think like a real pentester: "
        "- Start with detection payloads (confirm the vuln) "
        "- Include at least one boolean test "
        "  (e.g. AND 1=1 vs AND 1=2 for SQLi) "
        "- Include at least one data extraction payload "
        "- Vary your approach (error-based, union, blind) "
        "Return ONLY raw payloads, one per line. "
        "No explanations, no numbering, no markdown."
    )

    JUDGE_PROMPT = (
        "You are an expert penetration tester analyzing "
        "exploit attempt results. You must determine if "
        "the vulnerability is CONFIRMED based on how the "
        "target responded. "
        "Key signals: "
        "- Response SIZE changes: if an OR 1=1 payload "
        "  returns significantly MORE data than baseline, "
        "  that means data extraction = SQLi CONFIRMED. "
        "- Boolean behavior: if AND 1=1 returns normal data "
        "  but AND 1=2 returns less/empty, the query is "
        "  being interpreted = SQLi CONFIRMED. "
        "- Payload reflection: if your XSS payload appears "
        "  unescaped in the response body = XSS CONFIRMED. "
        "- Time delays: if SLEEP payload takes 5+ seconds "
        "  = time-based injection CONFIRMED. "
        "- Error messages: SQL syntax errors, stack traces "
        "  = error-based injection CONFIRMED. "
        "- Different status codes or redirects compared to "
        "  baseline can indicate injection. "
        "Be decisive. If the evidence is clear, say confirmed."
    )

    JUDGE_SCHEMA: dict[str, Any] = {
        "name": "exploit_judgment",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": [
                        "confirmed",
                        "not_vulnerable",
                        "continue",
                    ],
                },
                "evidence": {"type": "string"},
                "next_payloads": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": [
                "verdict",
                "evidence",
                "next_payloads",
            ],
            "additionalProperties": False,
        },
    }

    async def generate_payloads(
        self,
        hypothesis: dict,
        baseline_info: str = "",
    ) -> list[str]:
        """Ask LLM to generate targeted payloads."""
        vuln_type = hypothesis.get("vuln_type", "")
        param = hypothesis.get("target_parameter", "")
        endpoint = hypothesis.get("target_endpoint", "")
        desc = hypothesis.get("description", "")

        context = (
            f"Vulnerability type: {vuln_type}\n"
            f"Target endpoint: {endpoint}\n"
            f"Target parameter: {param}\n"
            f"Description: {desc}\n"
        )
        if baseline_info:
            context += f"\nBaseline response: {baseline_info}\n"

        context += (
            "\nGenerate 3-5 payloads to test this. "
            "One per line, raw payloads only."
        )

        raw = await self._ask(self.GENERATE_PROMPT, context)

        payloads = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            line = re.sub(r"^\d+[\.\)]\s*", "", line)
            line = re.sub(r"^[-*]\s*", "", line)
            line = line.strip().strip("`")
            if line and len(line) > 1:
                payloads.append(line)

        logger.info(
            "LLM generated %d payloads for %s: %s",
            len(payloads),
            vuln_type,
            [p[:40] for p in payloads],
        )
        return payloads[:5]

    async def judge_results(
        self,
        hypothesis: dict,
        results_summary: str,
        baseline_info: str = "",
    ) -> dict[str, Any]:
        """Show LLM the response behavior and get verdict."""
        vuln_type = hypothesis.get("vuln_type", "")
        param = hypothesis.get("target_parameter", "")
        endpoint = hypothesis.get("target_endpoint", "")

        context = (
            f"Testing for: {vuln_type}\n"
            f"Endpoint: {endpoint}\n"
            f"Parameter: {param}\n"
        )
        if baseline_info:
            context += f"Baseline: {baseline_info}\n"

        context += f"\nResults:\n{results_summary}\n"
        context += (
            "\nBased on the response BEHAVIOR (size changes, "
            "reflection, timing, errors), is this vulnerability "
            "CONFIRMED? Be decisive."
        )

        raw = await self._ask(
            self.JUDGE_PROMPT,
            context,
            structured_output=self.JUDGE_SCHEMA,
        )

        try:
            result = json.loads(raw)
            verdict = result.get("verdict", "not_vulnerable")
            evidence = result.get("evidence", "")
            next_payloads = result.get("next_payloads", [])

            # Clean next_payloads
            clean = []
            for p in next_payloads:
                if isinstance(p, str) and len(p) > 1:
                    clean.append(p.strip())
            next_payloads = clean[:5]

            logger.info(
                "LLM verdict: %s (evidence: %s)",
                verdict,
                evidence[:100],
            )

            return {
                "verdict": verdict,
                "evidence": evidence,
                "next_payloads": next_payloads,
            }
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(
                "Judge structured output failed: %s", e
            )
            # Fallback: parse text
            text_lower = raw.lower()
            if "confirmed" in text_lower:
                return {
                    "verdict": "confirmed",
                    "evidence": raw[:500],
                    "next_payloads": [],
                }
            if "continue" in text_lower:
                return {
                    "verdict": "continue",
                    "evidence": raw[:500],
                    "next_payloads": [],
                }
            return {
                "verdict": "not_vulnerable",
                "evidence": raw[:500],
                "next_payloads": [],
            }

    @staticmethod
    def build_strategy(
        hypothesis: dict,
        payload: str,
        target_url: str,
        method: HttpMethod = HttpMethod.GET,
    ) -> ExploitStrategy:
        """Build an ExploitStrategy from hypothesis + payload.

        No LLM — pure code. LLM gives us WHAT payload,
        we handle HOW to deliver it.
        """
        endpoint = hypothesis.get("target_endpoint", "")
        param = hypothesis.get("target_parameter", "")
        hypothesis_id = hypothesis.get("id", "unknown")

        url = _resolve_url(endpoint, target_url)

        if method == HttpMethod.POST:
            return ExploitStrategy(
                hypothesis_id=hypothesis_id,
                http_method=HttpMethod.POST,
                url=url,
                body=(
                    f"{param}={payload}"
                    if param
                    else payload
                ),
                headers={
                    "Content-Type": (
                        "application/"
                        "x-www-form-urlencoded"
                    ),
                },
                payload=payload,
                description=(
                    f"POST {param}={payload[:50]}"
                ),
            )
        else:
            return ExploitStrategy(
                hypothesis_id=hypothesis_id,
                http_method=HttpMethod.GET,
                url=url,
                params=(
                    {param: payload} if param else {}
                ),
                payload=payload,
                description=(
                    f"GET ?{param}={payload[:50]}"
                ),
            )

    @staticmethod
    def format_baseline_info(
        baseline: ExploitResponse,
    ) -> str:
        """Format baseline response for LLM context."""
        return (
            f"status={baseline.status}, "
            f"body={len(baseline.body)} bytes, "
            f"time={baseline.elapsed_ms:.0f}ms"
        )

    @staticmethod
    def format_results_summary(
        results: list[tuple[str, str, ExploitResult]],
        baseline: ExploitResponse | None = None,
    ) -> str:
        """Format attempt results for LLM context.

        Shows each payload's response behavior relative
        to the baseline so the LLM can make smart decisions.
        """
        bl = len(baseline.body) if baseline else 0
        lines: list[str] = []
        seen: set[str] = set()

        for payload, method, result in results:
            for attempt in result.attempts:
                resp = attempt.response
                if not resp:
                    continue

                # Deduplicate
                key = f"{method}:{payload}"
                if key in seen:
                    continue
                seen.add(key)

                rl = len(resp.body)
                diff = ""
                if bl > 0:
                    pct = ((rl - bl) / bl) * 100
                    diff = f" ({pct:+.0f}% from baseline)"

                reflected = (
                    payload in resp.body if payload else False
                )

                lines.append(
                    f"  {method} payload: {payload[:80]}\n"
                    f"    status={resp.status}, "
                    f"body={rl}b{diff}, "
                    f"time={resp.elapsed_ms:.0f}ms, "
                    f"reflected={reflected}"
                )

        return "\n".join(lines)


def _resolve_url(
    endpoint: str,
    target_url: str,
) -> str:
    """Resolve an endpoint against the target base URL.

    ALWAYS uses target_url's scheme + host + port.
    """
    endpoint = endpoint.strip()
    if not endpoint:
        return target_url

    parsed = urlparse(endpoint)

    if parsed.scheme and parsed.netloc:
        endpoint = parsed.path
        if parsed.query:
            endpoint += f"?{parsed.query}"

    return urljoin(target_url, endpoint)
