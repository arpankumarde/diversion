# NAZITEST - Project Documentation

## 1. The problem it solves

**NAZITEST** is an AI-driven autonomous penetration testing framework. Here's what it's for and how it makes security testing easier and safer.

### What people use it for

- **Web app pentesting** - Run structured, repeatable tests against web applications (SPAs, APIs, WebSocket apps) with minimal manual clicking.
- **Finding logic and chain bugs** - Focus on business logic flaws, auth bypasses, and chained issues that scanners usually miss (aligned with the ~82% of breaches that involve reasoning and context, per Verizon DBIR).
- **Recon that matches real users** - Use a real browser over CDP so JS, CSP, AJAX, WebSockets, and anti-bot flows run as they do for users; no synthetic HTTP-only blind spots.
- **From crawl to exploit in one pipeline** - One flow: crawl → record (HAR, DOM, cookies, WS) → build a knowledge graph → LLM hypotheses → autonomous exploitation → report.
- **Safe, authorized testing** - Scope and authorization are first-class; the tool is designed for use only on targets you're allowed to test (e.g. RoE, bug bounty scope).

### How it makes existing tasks easier or safer

| Before                                                                 | With NAZITEST                                                                 |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Scanners = signatures only; manual pentest = expensive, non-repeatable | KG + LLM reasoning for hypotheses; automated recon/exploit with human-in-loop |
| Proxy/HTTP tools miss SPAs, WS, and anti-bot behavior                  | Real browser (CDP) sees full client-side behavior and tokens                  |
| Ad-hoc notes; unclear scope risk                                       | Structured run artifacts; explicit scope and authorization gates              |

### What it is _not_

- **Not** a generic vulnerability scanner (no CVE/signature database).
- **Not** a replacement for a human pentester (it augments and scales their workflow).
- **Not** for unauthorized testing (assumes explicit scope and authorization).

---

## 2. Challenges I ran into

### Browser automation: WAF blocking and state drift

**What went wrong:** Using Playwright (or similar) for recon meant a Node relay in front of CDP; requests often got blocked by Cloudflare/Akamai, and state (cookies, redirects) drifted between the tool and the real browser so we missed SPA endpoints and post-login flows.

**What I tried:** Tweaking headers and user agents, and running checks only at startup to avoid drift.

**How I got over it:** Switched to Zendriver with direct CDP (no Node relay). The browser matches real Chrome and bypasses many anti-bot layers; single process and no RPC relay kept cookie and navigation state consistent so recon became reliable.

---

### LLM hallucinating vulnerabilities

**What went wrong:** The reasoning engine kept emitting high-confidence findings that didn't reproduce when we replayed them manually - classic LLM hallucination applied to vuln reporting.

**What I tried:** Stronger system prompts and switching models; that reduced but didn't remove false positives.

**How I got over it:** Only treat as confirmed findings what the exploitation engine actually reproduces. Added a cross-validator step (second model / different family via OpenRouter) to challenge high-confidence hypotheses before they become reportable findings.

---

### Exploit requests fingerprinted as bots

**What went wrong:** Exploitation-phase HTTP requests from standard Python clients (requests/httpx) were TLS-fingerprinted as non-browser and got dropped or challenged by WAFs, so valid hypotheses looked like failures.

**What I tried:** Rotating user-agent and headers; helped a bit but TLS fingerprint (JA3/JA4) still gave us away.

**How I got over it:** Use curl_cffi for exploitation so requests use real Chrome TLS fingerprints. Combined with cookie/token replay from the browser session, exploit traffic now matches the recon session and gets through where plain HTTP clients were blocked.

---

### Large targets blowing the LLM context window

**What went wrong:** Big sites produced huge HAR + DOM + site maps; stuffing them into the prompt exceeded the model's context and either failed or produced useless summaries.

**What I tried:** Truncating inputs and summarizing manually; we lost the structure the model needed to reason over.

**How I got over it:** Build the knowledge graph first and feed the LLM graph-centric views (nodes, edges, beliefs) instead of raw HAR. Use chunked processing and focused crawling so each reasoning step sees a bounded subgraph; the KG acts as the compression layer.

---

### Guaranteeing scope so we never hit out-of-scope hosts

**What went wrong:** Exploitation and redirects can touch domains we didn't intend to test; a single mistake could mean unauthorized testing and legal risk.

**What I tried:** Scope checks only at startup and in the config; one code path could still send a request to a redirect or linked domain outside scope.

**How I got over it:** Scope validation at request time: both the orchestrator and the exploitation layer check every URL (and redirect targets) against an explicit whitelist before sending. No "trust config at startup" - every outbound request is validated so we never hit out-of-scope assets.
