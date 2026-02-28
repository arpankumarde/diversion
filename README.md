# nazitest

AI-powered autonomous penetration testing framework. Combines manual browsing reconnaissance with LLM-driven vulnerability reasoning and automated exploitation.

## How it works

```
CRAWL → MODEL → REASON → EXPLOIT → REPORT
```

1. **Crawl** — Opens a real browser. You browse the target manually while nazitest auto-captures DOM snapshots, cookies, HAR traffic, and screenshots via CDP.
2. **Model** — Builds a knowledge graph (NetworkX) from captured artifacts: endpoints, parameters, auth mechanisms, security headers, cookies, technologies.
3. **Reason** — LLM agents analyze the graph and generate ranked vulnerability hypotheses using a multi-agent pipeline:
   - **Strategist** — analyzes attack surface, generates hypotheses
   - **Scout** — investigates each hypothesis against evidence
   - **CrossValidator** — independently challenges findings to reduce false positives
   - **ExploitPlanner** — generates structured exploit strategies
4. **Exploit** — Executes real HTTP requests against the target with TLS fingerprint impersonation, strategy rotation (encoding/delivery/UA), and exponential backoff.
5. **Report** — Generates HTML + JSON reports with confirmed vulnerabilities, PoC scripts, and remediation guidance.

## Vulnerability types

Detection is LLM-driven (not a fixed ruleset), guided by OWASP Top 10 analysis of the knowledge graph. Commonly identified:

| Type | Exploit method |
|---|---|
| SQL Injection | curl_cffi (parameterized payloads) |
| Cross-Site Scripting (XSS) | curl_cffi + browser replay (JS execution) |
| IDOR | curl_cffi (parameter tampering) |
| SSRF | curl_cffi |
| CSRF | Browser replay |
| Command Injection | curl_cffi |
| Path Traversal | curl_cffi |
| Auth/Session flaws | curl_cffi |
| Info Disclosure | curl_cffi |

**Two exploit engines:**
- **CurlExploiter** — TLS-fingerprint-safe HTTP via `curl_cffi` (impersonates Chrome/Safari TLS signatures)
- **BrowserReplay** — Real browser via Zendriver for client-side vulns requiring JS execution

**Evasion:** Strategy rotation across 7 encoding types (URL, double-URL, unicode, hex, HTML, mixed-case, raw), 7 delivery methods (query param, path segment, POST JSON/form, header injection, cookie injection, fragment), and multiple TLS fingerprints with exponential backoff + jitter.

## Belief refinement

Hypotheses go through a confidence pipeline before exploitation:

```
Baseline (0.3) → Scout (40/40/20 weighting) → CrossValidator (if >0.6) → Exploit (if >0.75)
```

- Confirmed exploits set confidence to 1.0
- Blocked attempts reduce by 10%
- Failed attempts reduce by 30%

## Setup

```bash
pip install -e .
```

Set your OpenRouter API key:

```bash
export OPENROUTER_API_KEY=sk-or-...
```

Configure models in `models.yaml` (defaults to Claude Sonnet 4.6 + Haiku 4.5).

## Usage

```bash
nazitest scan https://target.example.com
```

Browse the target in the opened browser window, then press ENTER to continue. The tool runs through reasoning and exploitation automatically and outputs an HTML report.

## Project structure

```
nazitest/
  core/         Orchestrator state machine, scope enforcement
  recon/        Browser controller, HAR recorder, DOM snapshots, sitemap
  analysis/     Knowledge graph builder, tech detection
  reasoning/    LLM agents (Strategist, Scout, CrossValidator, ExploitPlanner),
                belief refinement, OpenRouter client
  exploitation/ Exploit engine, curl_cffi client, browser replay,
                strategy rotation, backoff
  models/       Pydantic models (graph, exploit, HAR, recon, config)
  reporting/    HTML/JSON report generator (Jinja2)
  storage/      Artifact store, run manager
  proxy/        Proxy rotation manager
```

## License

For authorized security testing only. Always obtain written permission before testing targets you do not own.
