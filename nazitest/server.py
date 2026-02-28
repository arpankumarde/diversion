"""FastAPI server — wraps the orchestrator for API-driven scans."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

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


# Mount static files AFTER API routes so /api/* paths aren't intercepted
app.mount("/runs", StaticFiles(directory=str(RUNS_DIR), html=True), name="runs")
