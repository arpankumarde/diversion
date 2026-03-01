"""FastAPI server — wraps the orchestrator for API-driven scans."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import orjson
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from nazitest.config import Settings
from nazitest.core.orchestrator import Orchestrator
from nazitest.models.config import ProxyConfig, ProxyEntry, RunConfig, ScopeConfig
from nazitest.models.types import OrchestratorPhase
from nazitest.storage.run_manager import RunManager

logger = logging.getLogger(__name__)

RUNS_DIR = Path("./nazitest_runs")


# ── Request / Response models ──


class ScanStartRequest(BaseModel):
    target: str
    repo: str | None = None
    depth: int = 5
    pages: int = 200
    time_limit: int = 120
    proxy: str | None = None


class ScanStartResponse(BaseModel):
    status: str
    run_id: str


class ScanStopResponse(BaseModel):
    status: str
    run_id: str


class ScanStatusResponse(BaseModel):
    run_id: str
    phase: str
    completed: bool


class ReportSummary(BaseModel):
    total_hypotheses: int = 0
    confirmed: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ReportItem(BaseModel):
    run_id: str
    target: str
    completed: bool
    summary: ReportSummary


# ── Active scan tracking ──


@dataclass
class ActiveScan:
    run_id: str
    task: asyncio.Task[str]
    orchestrator: Orchestrator
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)


active_scans: dict[str, ActiveScan] = {}


# ── App ──

app = FastAPI(title="nazitest", version="0.1.0")
RUNS_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/scans/start", response_model=ScanStartResponse)
async def start_scan(req: ScanStartRequest) -> ScanStartResponse:
    """Start a new scan. Returns run_id immediately; browser opens visually."""
    scope = ScopeConfig(
        target_url=req.target,
        max_crawl_depth=req.depth,
        max_crawl_pages=req.pages,
    )

    proxy = ProxyConfig()
    if req.proxy:
        proxy = ProxyConfig(
            proxy_list=[ProxyEntry(url=req.proxy)],
            enabled=True,
        )

    config = RunConfig(
        scope=scope,
        proxy=proxy,
        repo_url=req.repo,
        time_limit_minutes=req.time_limit,
        output_dir=RUNS_DIR,
    )

    settings = Settings.load(config.models_config_path)
    stop_event = asyncio.Event()
    orchestrator = Orchestrator(config, settings=settings, stop_event=stop_event)

    task = asyncio.create_task(_run_scan(orchestrator))

    # The run_id is set during orchestrator.run() INIT phase.
    # We need to wait briefly for it to be assigned.
    for _ in range(50):
        if orchestrator.run_id:
            break
        await asyncio.sleep(0.1)

    if not orchestrator.run_id:
        raise HTTPException(status_code=500, detail="Failed to initialize scan")

    run_id = orchestrator.run_id
    active_scans[run_id] = ActiveScan(
        run_id=run_id,
        task=task,
        orchestrator=orchestrator,
        stop_event=stop_event,
    )

    return ScanStartResponse(status="started", run_id=run_id)


async def _run_scan(orchestrator: Orchestrator) -> str:
    """Background wrapper for orchestrator.run()."""
    try:
        return await orchestrator.run()
    except Exception as e:
        logger.exception("Scan failed: %s", e)
        return ""


@app.post("/api/scans/{run_id}/stop", response_model=ScanStopResponse)
async def stop_scan(run_id: str) -> ScanStopResponse:
    """Signal the crawl phase to stop. The orchestrator continues with remaining phases."""
    scan = active_scans.get(run_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"No active scan with run_id: {run_id}")

    scan.stop_event.set()
    return ScanStopResponse(status="stopped", run_id=run_id)


@app.get("/api/scans/{run_id}/status", response_model=ScanStatusResponse)
async def scan_status(run_id: str) -> ScanStatusResponse:
    """Check current phase of a scan."""
    # Check active scans first
    scan = active_scans.get(run_id)
    if scan:
        completed = scan.orchestrator.phase == OrchestratorPhase.DONE or scan.task.done()
        return ScanStatusResponse(
            run_id=run_id,
            phase=scan.orchestrator.phase.value,
            completed=completed,
        )

    # Check on-disk for completed runs
    run_path = RUNS_DIR / run_id
    if not run_path.exists():
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")

    meta_path = run_path / "report" / "meta.json"
    completed = meta_path.exists()
    phase = "done" if completed else "unknown"

    return ScanStatusResponse(run_id=run_id, phase=phase, completed=completed)


@app.get("/api/reports", response_model=list[ReportItem])
async def list_reports() -> list[ReportItem]:
    """List all completed runs with severity count summaries."""
    run_manager = RunManager(RUNS_DIR)
    runs = run_manager.list_runs()
    reports: list[ReportItem] = []

    for run_info in runs:
        run_id = run_info["run_id"]
        target = run_info.get("target", "unknown")
        run_path = RUNS_DIR / run_id
        report_path = run_path / "report" / "report.json"

        if not report_path.exists():
            continue

        try:
            report_data = orjson.loads(report_path.read_bytes())
            summary_data = report_data.get("summary", {})
            summary = ReportSummary(
                total_hypotheses=summary_data.get("total_hypotheses", 0),
                confirmed=summary_data.get("confirmed_vulnerabilities", 0),
                critical=summary_data.get("critical", 0),
                high=summary_data.get("high", 0),
                medium=summary_data.get("medium", 0),
                low=summary_data.get("low", 0),
                info=summary_data.get("info", 0),
            )
            reports.append(ReportItem(
                run_id=run_id,
                target=target,
                completed=True,
                summary=summary,
            ))
        except Exception as e:
            logger.warning("Failed to read report for %s: %s", run_id, e)

    return reports


# ── Attack Narrative (Opus deep analysis) ──

ATTACK_NARRATIVE_MODEL = "anthropic/claude-opus-4.6"
ATTACK_NARRATIVE_TIMEOUT = 600  # 10 minutes

ATTACK_NARRATIVE_PROMPT = """You are an elite red team operator writing an internal debrief after a successful penetration test. You have been given the complete scan results — every vulnerability found, every exploit attempted, every confirmed finding with proof-of-concept evidence.

Your job: write a detailed, realistic ATTACK NARRATIVE describing exactly how a real-world attacker would chain these vulnerabilities together to cause maximum damage. This is not a compliance report — this is a war story.

Think step by step:

1. **Initial Access** — Which vulnerability gets the attacker in the door? What's the easiest entry point? Walk through the exact HTTP requests, payloads, and responses.

2. **Privilege Escalation** — Once inside, how does the attacker escalate? Can they go from anonymous → authenticated → admin? Chain the confirmed vulns.

3. **Data Exfiltration** — What sensitive data can they steal? Database dumps via SQLi? Session tokens via XSS? Internal files via path traversal? Be specific about what tables, what files, what tokens.

4. **Lateral Movement** — Can they pivot? SSRF to internal services? Credential reuse? Cloud metadata access?

5. **Persistence** — How would they maintain access? Backdoor accounts? Modified application code? Scheduled tasks?

6. **Impact Assessment** — What's the worst-case business impact? Data breach? Ransomware deployment? Supply chain compromise? Financial fraud?

For each step:
- Reference the SPECIFIC vulnerabilities from the scan by ID and endpoint
- Include the ACTUAL payloads and curl commands that would work
- Describe what the attacker sees at each stage
- Estimate the time an experienced attacker would need

End with:
- **Attack Timeline** — minute-by-minute breakdown of the full attack chain
- **Crown Jewels at Risk** — the most valuable assets the attacker could reach
- **What Would Make Headlines** — the worst-case scenario if this were exploited in the wild

Be thorough. Be creative. Be evil. This is what keeps CISOs up at night."""


class AttackNarrativeResponse(BaseModel):
    run_id: str
    target: str
    model: str
    narrative: str
    usage: dict[str, Any] = {}


@app.post("/api/reports/{run_id}/attack-narrative", response_model=AttackNarrativeResponse)
async def generate_attack_narrative(run_id: str) -> AttackNarrativeResponse:
    """Generate a deep-think attack narrative from a completed scan using Opus.

    Loads the full report data, POCs, and metadata, sends it all to Claude Opus
    with extended context, and returns a realistic attack scenario narrative.
    Timeout: 10 minutes.
    """
    settings = Settings.load()

    if not settings.openrouter_api_key:
        raise HTTPException(status_code=500, detail="No OPENROUTER_API_KEY configured")

    run_path = RUNS_DIR / run_id
    if not run_path.exists():
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")

    report_path = run_path / "report" / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=400, detail="Scan not complete — no report.json found")

    # Load all available data
    report_data = orjson.loads(report_path.read_bytes())
    target = report_data.get("metadata", {}).get("target_url", "unknown")

    meta_data = {}
    meta_path = run_path / "report" / "meta.json"
    if meta_path.exists():
        meta_data = orjson.loads(meta_path.read_bytes())

    # Load POCs
    pocs: list[dict] = []
    poc_dir = run_path / "exploitation" / "pocs"
    if poc_dir.exists():
        for poc_file in sorted(poc_dir.glob("*.json")):
            try:
                pocs.append(orjson.loads(poc_file.read_bytes()))
            except Exception:
                pass

    # Load exploit attempts (summarized)
    attempts: list[dict] = []
    attempts_dir = run_path / "exploitation" / "attempts"
    if attempts_dir.exists():
        for att_file in sorted(attempts_dir.glob("*.json"))[:50]:  # cap at 50
            try:
                attempts.append(orjson.loads(att_file.read_bytes()))
            except Exception:
                pass

    # Build the context payload for Opus
    context = json.dumps({
        "target": target,
        "run_id": run_id,
        "summary": report_data.get("summary", {}),
        "vulnerabilities": report_data.get("vulnerabilities", []),
        "graph_stats": report_data.get("graph_stats", {}),
        "proof_of_concepts": pocs,
        "exploit_attempts_sample": attempts[:30],
        "scan_metadata": {
            k: v for k, v in meta_data.items()
            if k in ("target_url", "total_elapsed_seconds", "stages",
                      "network", "knowledge_graph", "iterative_pipeline")
        },
    }, indent=2)

    user_message = (
        f"Here is the complete penetration test data for {target}:\n\n"
        f"{context}\n\n"
        "Now write the attack narrative. Be specific, reference actual "
        "vulnerability IDs and endpoints from the data above. Include "
        "real curl commands using the confirmed payloads."
    )

    # Call Opus via OpenRouter with extended timeout
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(ATTACK_NARRATIVE_TIMEOUT, connect=15.0),
        headers={
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "HTTP-Referer": "https://nazitest.local",
            "X-Title": "NAZITEST Attack Narrative",
            "Content-Type": "application/json",
        },
    ) as client:
        payload = {
            "model": ATTACK_NARRATIVE_MODEL,
            "messages": [
                {"role": "system", "content": ATTACK_NARRATIVE_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0.7,
            "max_tokens": 16384,
        }

        try:
            response = await client.post(
                f"{settings.openrouter_base_url}/chat/completions",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="Opus timed out — the narrative generation exceeded 10 minutes",
            )
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"OpenRouter API error: {e.response.text[:500]}",
            )

    choices = data.get("choices", [])
    narrative = choices[0]["message"]["content"] if choices else "No response generated."
    usage = data.get("usage", {})
    model_used = data.get("model", ATTACK_NARRATIVE_MODEL)

    # Save the narrative to disk alongside the report
    narrative_path = run_path / "report" / "attack_narrative.md"
    narrative_path.write_text(narrative)

    narrative_meta_path = run_path / "report" / "attack_narrative_meta.json"
    narrative_meta_path.write_bytes(orjson.dumps({
        "model": model_used,
        "usage": usage,
        "target": target,
        "run_id": run_id,
    }, option=orjson.OPT_INDENT_2))

    return AttackNarrativeResponse(
        run_id=run_id,
        target=target,
        model=model_used,
        narrative=narrative,
        usage=usage,
    )


# Mount static files AFTER API routes so /api/* paths aren't intercepted
app.mount("/runs", StaticFiles(directory=str(RUNS_DIR), html=True), name="runs")
