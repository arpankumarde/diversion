# nazitest

AI-powered autonomous penetration testing framework. Combines manual browsing reconnaissance with LLM-driven vulnerability reasoning and automated exploitation.

## How it works

```
INIT → CRAWL → MODEL → CODEBASE →
  LOOP (max 3 iterations):
    REASON (with web research) →
    SCOUT (+ optional CrossValidator) →
    EXPLOIT (with web research) →
    CHAIN ANALYSIS → new hypotheses? → continue/break
→ REPORT
```

1. **Crawl** — Opens a real browser. You browse the target manually while nazitest auto-captures DOM snapshots, cookies, HAR traffic, and screenshots via CDP.
2. **Model** — Builds a knowledge graph (NetworkX) from captured artifacts: endpoints, parameters, auth mechanisms, security headers, cookies, technologies.
3. **Codebase** (optional) — Clones the target's source repo, runs AST analysis (tree-sitter) to extract routes, dangerous sinks, and auth patterns. Correlates with the knowledge graph.
4. **Reason** — LLM agents analyze the graph and generate ranked vulnerability hypotheses using a multi-agent pipeline:
   - **Strategist** — analyzes attack surface, generates hypotheses. Can research CVEs and known vulnerabilities via web search/scrape tools.
   - **Scout** — investigates each hypothesis against evidence, adjusts confidence via belief refinement loop
   - **CrossValidator** — independently challenges findings to reduce false positives (optional, off by default)
   - **ExploitPlanner** — generates targeted payloads. Can search PayloadsAllTheThings, HackTricks, and vulnerability databases for real-world payloads.
5. **Exploit** — Executes real HTTP requests against the target with TLS fingerprint impersonation, strategy rotation (encoding/delivery/UA), and exponential backoff.
6. **Chain Analysis** — Confirmed vulnerabilities spawn follow-up hypotheses (SQLi → extract creds, XSS → steal sessions, IDOR → privilege escalation). The pipeline loops back to REASON with chain hypotheses for up to 3 iterations.
7. **Report** — Generates HTML + JSON reports with confirmed vulnerabilities, PoC scripts, iteration metadata, and remediation guidance.

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

## Web research (BrightData)

LLM agents have access to two tools backed by the BrightData SDK:

- **`web_search`** — SERP API for searching CVEs, vulnerability databases, bypass techniques, and exploit writeups
- **`web_scrape`** — Scrapes pages from PayloadsAllTheThings, HackTricks, CVE databases, and other security resources

Research happens inline during reasoning and payload generation via an agentic tool-use loop (up to 8 tool rounds per LLM call). Results are cached per-run to avoid redundant lookups. Content is truncated to 15K chars to protect LLM context.

Set `BRIGHTDATA_API_KEY` to enable. Without it, agents fall back to training data only — no web calls are made.

## Iterative pipeline + vulnerability chaining

After exploitation, confirmed vulnerabilities spawn chain hypotheses:

| Confirmed vuln | Follow-up hypotheses |
|---|---|
| SQL Injection | Extract credentials, dump schema, read files via `LOAD_FILE` |
| XSS | Steal session cookies, phish credentials, CSRF bypass |
| IDOR | Privilege escalation, access admin resources |
| SSRF | Internal service discovery, cloud metadata (`169.254.169.254`) |
| Path Traversal | Read config files, source code, credentials |
| Command Injection | Reverse shell, file read, pivot to internal network |

The pipeline loops `REASON → SCOUT → EXPLOIT → CHAIN` up to 3 iterations (configurable via `max_iterations`). It stops early if no new confirmed vulnerabilities or no chain hypotheses are generated.

## Belief refinement

Hypotheses go through a confidence pipeline before exploitation:

```
Baseline (0.3) → Scout (60/20/20 weighting) → CrossValidator (advisory, if >0.5) → Exploit (if >0.5)
```

- Scout confidence weighted 60%, prior 20%, evidence 20%
- CrossValidator is advisory only — cannot drop confidence below 80% of current value
- Confirmed exploits set confidence to 1.0
- Blocked attempts reduce by 10%
- Failed attempts reduce by 30%

## Setup

```bash
pip install -e .
```

Set your API keys:

```bash
export OPENROUTER_API_KEY=sk-or-...
export BRIGHTDATA_API_KEY=...          # optional, enables web research
```

Configure models in `models.yaml` (defaults to Claude Sonnet 4.6 + Haiku 4.5).

## Usage

### CLI mode

```bash
nazitest scan https://target.example.com
```

Browse the target in the opened browser window, then press ENTER to continue. The tool runs through reasoning and exploitation automatically and outputs an HTML report.

### API server mode

Start the server:

```bash
uvicorn nazitest.server:app --reload --port 8000
```

#### Quick commands

**Start a scan** (returns run_id immediately, browser opens):

```bash
curl -X POST http://localhost:8000/api/scans/start \
  -H 'Content-Type: application/json' \
  -d '{"target": "https://target.example.com"}'
```

Optional fields: `depth` (default 5), `pages` (default 200), `time_limit` (default 120 minutes), `proxy` (proxy URL string or null).

**Stop recording** (browser closes, agent continues with model/reason/exploit/report):

```bash
curl -X POST http://localhost:8000/api/scans/{run_id}/stop
```

**Check scan status:**

```bash
curl http://localhost:8000/api/scans/{run_id}/status
```

Returns the current phase (`crawl`, `model`, `reason`, `exploit`, `report`, `done`) and whether the scan is completed.

**List all completed reports:**

```bash
curl http://localhost:8000/api/reports
```

Returns a list of completed runs with severity count summaries (total, confirmed, critical, high, medium, low, info).

#### Viewing files

Static files (HTML reports, screenshots, HAR files, etc.) are served at:

```
http://localhost:8000/runs/
```

View a specific run's HTML report:

```
http://localhost:8000/runs/{run_id}/report/report.html
```

View a specific run's JSON report:

```
http://localhost:8000/runs/{run_id}/report/report.json
```

View screenshots:

```
http://localhost:8000/runs/{run_id}/recon/screenshots/
```

API docs (auto-generated by FastAPI):

```
http://localhost:8000/docs
```

#### Example workflow

```bash
# 1. Start server
uvicorn nazitest.server:app --port 8000

# 2. Start a scan
curl -s -X POST http://localhost:8000/api/scans/start \
  -H 'Content-Type: application/json' \
  -d '{"target": "https://pentest-ground.com:4280"}' | jq .

# 3. Browse the target in the opened browser window

# 4. Stop recording when done browsing
curl -s -X POST http://localhost:8000/api/scans/{run_id}/stop | jq .

# 5. Poll status until complete
curl -s http://localhost:8000/api/scans/{run_id}/status | jq .

# 6. View reports
curl -s http://localhost:8000/api/reports | jq .

# 7. Open HTML report in browser
open http://localhost:8000/runs/{run_id}/report/report.html
```

### Output directory

All scan artifacts are stored in `nazitest_runs/` with one directory per run:

```
nazitest_runs/{run_id}/
  config.json                    # scan configuration
  recon/
    har/                         # HTTP archive files
    dom/                         # DOM snapshots (JSON)
    screenshots/                 # page screenshots (PNG)
    cookies/                     # captured cookies
    site_map.json                # discovered endpoints
  analysis/
    knowledge_graph/             # graph snapshots (JSON)
    llm_reasoning/               # LLM session logs
  exploitation/
    attempts/                    # individual exploit attempts
    pocs/                        # proof-of-concept scripts
  report/
    report.json                  # structured report data
    report.html                  # rendered HTML report
    meta.json                    # run metadata (timings, LLM costs)
```

### Environment variables

| Variable | Description |
|---|---|
| `OPENROUTER_API_KEY` | OpenRouter API key (required for reasoning/exploit phases) |
| `BRIGHTDATA_API_KEY` | BrightData API token (optional, enables web research tools) |
| `CHROME_PATH` | Path to Chrome binary (optional, auto-detected) |
| `NAZITEST_PROXY` | Default proxy URL |
| `NAZITEST_PROXY_LIST` | Path to proxy list file |
| `NAZITEST_OUTPUT_DIR` | Custom output directory (default: `./nazitest_runs`) |

### Tests

```bash
pytest tests/
```

## Project structure

```
nazitest/
  server.py       FastAPI server (API + static file serving)
  cli.py          Typer CLI (scan, resume, report, graph commands)
  config.py       Settings loader (.env, env vars, models.yaml)
  core/           Orchestrator (iterative pipeline), scope enforcement
  recon/          Browser controller, HAR recorder, DOM snapshots, sitemap
  analysis/       Knowledge graph builder, tech detection, codebase xref (AST)
  reasoning/      LLM agents (Strategist, Scout, CrossValidator, ExploitPlanner),
                  belief refinement, OpenRouter client (with tool-use loop),
                  web research (BrightData wrapper)
  exploitation/   Exploit engine, curl_cffi client, browser replay,
                  strategy rotation, backoff
  models/         Pydantic models (graph, exploit, HAR, recon, config)
  reporting/      HTML/JSON report generator (Jinja2)
  storage/        Artifact store, run manager
  proxy/          Proxy rotation manager
```

## License

For authorized security testing only. Always obtain written permission before testing targets you do not own.
