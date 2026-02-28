"""Orchestrator — main state machine tying all phases together."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from nazitest.analysis.graph_builder import GraphBuilder
from nazitest.analysis.knowledge_graph import KnowledgeGraph
from nazitest.config import Settings
from nazitest.core.auth_gate import AuthorizationGate
from nazitest.core.scope import ScopeEnforcer
from nazitest.models.config import RunConfig
from nazitest.models.types import ArtifactType, OrchestratorPhase
from nazitest.proxy.manager import ProxyManager
from nazitest.recon.browser import BrowserController
from nazitest.recon.dom_snapshot import DOMSnapshotCapture
from nazitest.recon.har_recorder import HARRecorder
from nazitest.recon.sitemap import SiteMapBuilder
from nazitest.reporting.generator import ReportGenerator
from nazitest.storage.artifact_store import ArtifactStore
from nazitest.storage.run_manager import RunManager

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """Main state machine: INIT -> AUTHORIZE -> CRAWL -> MODEL -> REASON -> EXPLOIT -> REPORT.

    Manages phase transitions, human-in-loop gates, error recovery, run persistence.
    """

    def __init__(self, config: RunConfig, settings: Settings | None = None) -> None:
        self.config = config
        self.settings = settings or Settings.load(config.models_config_path)
        self.phase = OrchestratorPhase.INIT
        self.run_id: str = ""
        self.run_path: Path = Path()

        # Core components
        self.run_manager = RunManager(config.output_dir)
        self.scope = ScopeEnforcer(config.scope)
        self.proxy_manager = ProxyManager(config.proxy)
        self.knowledge_graph = KnowledgeGraph()

        # Initialized during run
        self.store: ArtifactStore | None = None
        self.start_time: float = 0.0

    async def run(self) -> str:
        """Execute the full scan pipeline. Returns the run ID."""
        try:
            # INIT phase
            self._set_phase(OrchestratorPhase.INIT)
            self.run_id, self.run_path = self.run_manager.create_run(self.config)
            self.store = ArtifactStore(self.run_path)
            self.start_time = time.time()
            console.print(f"[green]Run created:[/green] {self.run_id}")

            # AUTHORIZE phase
            self._set_phase(OrchestratorPhase.AUTHORIZE)
            if not await self._authorize():
                console.print("[red]Authorization denied. Aborting.[/red]")
                return self.run_id

            # CRAWL + RECORD phase
            self._set_phase(OrchestratorPhase.CRAWL)
            await self._crawl()

            # MODEL phase — build knowledge graph
            self._set_phase(OrchestratorPhase.MODEL)
            self._build_graph()

            # REASON phase — LLM hypothesis generation
            self._set_phase(OrchestratorPhase.REASON)
            await self._reason()

            # EXPLOIT phase
            if self.config.exploit_mode != "none":
                self._set_phase(OrchestratorPhase.EXPLOIT)
                console.print(
                    "[yellow]Exploitation phase deferred to "
                    "reasoning output.[/yellow]"
                )

            # REPORT phase
            self._set_phase(OrchestratorPhase.REPORT)
            self._generate_report()

            self._set_phase(OrchestratorPhase.DONE)
            elapsed = time.time() - self.start_time
            console.print(
                f"[green]Scan complete in {elapsed:.0f}s.[/green] "
                f"Run ID: {self.run_id}"
            )

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            self._save_state()
        except Exception as e:
            logger.exception("Scan failed: %s", e)
            console.print(f"[red]Scan failed: {e}[/red]")
            self._save_state()

        return self.run_id

    async def _authorize(self) -> bool:
        """Run the authorization gate."""
        gate = AuthorizationGate(self.run_path)

        # Check if already authorized (resuming)
        if gate.is_authorized():
            console.print("[green]Previously authorized — continuing.[/green]")
            return True

        return gate.require_authorization(
            self.config.scope.target_url,
            self.config.scope,
        )

    async def _crawl(self) -> None:
        """Open a visible browser for the user to manually browse the target.

        Auto-captures DOM snapshots, screenshots, cookies, and network traffic
        on every page load via CDP event handlers.
        """
        assert self.store is not None
        proxy_url = self.proxy_manager.get_proxy_url("recon")
        target_url = self.config.scope.target_url

        console.print(
            f"[bold blue]Manual browse mode[/bold blue] — opening browser to {target_url}"
        )

        har_recorder = HARRecorder()
        dom_capture = DOMSnapshotCapture()
        sitemap_builder = SiteMapBuilder()
        pages_captured: list[str] = []

        browser = BrowserController(headless=False, proxy_url=proxy_url)
        try:
            await browser.start()

            # Enable CDP event-driven capture
            await browser.enable_network_capture(har_recorder)

            async def on_page_load() -> None:
                """Auto-capture DOM, cookies, storage, screenshot on each navigation."""
                try:
                    url = await browser.get_page_url()
                    if not url or url == "about:blank":
                        return

                    # Settle time for SPA rendering
                    await asyncio.sleep(1.5)

                    html = await browser.get_page_html()
                    cookies = await browser.get_cookies()
                    local_storage = await browser.get_local_storage()
                    session_storage = await browser.get_session_storage()

                    snapshot = dom_capture.capture(
                        url=url,
                        html=html,
                        local_storage=local_storage,
                        session_storage=session_storage,
                        cookies=cookies,
                    )

                    slug = self._url_slug(url)
                    self.store.save(ArtifactType.DOM_SNAPSHOT, snapshot, name=slug)

                    # Screenshot
                    try:
                        screenshot_data = await browser.screenshot()
                        self.store.save(ArtifactType.SCREENSHOT, screenshot_data, name=slug)
                    except Exception:
                        pass

                    # Feed links to sitemap builder
                    sitemap_builder.add_from_dom_links(snapshot.links, url)

                    pages_captured.append(url)
                    console.print(f"  [green]Captured:[/green] {url}")
                except Exception as e:
                    logger.warning("Auto-capture failed: %s", e)

            await browser.enable_page_tracking(on_load_callback=on_page_load)

            # Navigate to the target
            await browser.navigate(target_url)

            console.print(
                "\n[bold yellow]Browse the target in the browser window.[/bold yellow]"
                "\n[bold yellow]Press ENTER here when done...[/bold yellow]\n"
            )

            # Block until user presses ENTER (non-blocking for the event loop)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, input)

            console.print(f"[blue]Finishing up — captured {len(pages_captured)} pages[/blue]")

            # Save accumulated artifacts
            if har_recorder.entry_count > 0:
                har_file = har_recorder.to_har_file()
                self.store.save(ArtifactType.HAR, har_file, name="manual_crawl")

            sitemap = sitemap_builder.build()
            self.store.save(ArtifactType.SITE_MAP, sitemap)

            # Save cookie jar
            try:
                cookies = await browser.get_cookies()
                if cookies:
                    self.store.save(ArtifactType.COOKIE_JAR, {"cookies": cookies})
            except Exception:
                pass

            console.print(
                f"[green]Manual crawl complete:[/green] {len(pages_captured)} pages, "
                f"{har_recorder.entry_count} network requests captured"
            )

        finally:
            await browser.stop()

    @staticmethod
    def _url_slug(url: str) -> str:
        """Create a filesystem-safe slug from a URL."""
        parsed = urlparse(url)
        path = parsed.path.strip("/").replace("/", "_") or "index"
        return path[:80]

    def _build_graph(self) -> None:
        """Build knowledge graph from recon artifacts."""
        assert self.store is not None
        builder = GraphBuilder()

        # Load HAR files
        from nazitest.models.har import HARFile

        har_files = []
        for filename in self.store.list_artifacts(ArtifactType.HAR):
            try:
                data = self.store.load(ArtifactType.HAR, filename)
                har_files.append(HARFile.model_validate(data))
            except Exception as e:
                logger.warning("Failed to load HAR %s: %s", filename, e)

        # Load DOM snapshots
        from nazitest.models.recon import DOMSnapshot

        dom_snapshots = []
        for filename in self.store.list_artifacts(ArtifactType.DOM_SNAPSHOT):
            try:
                data = self.store.load(ArtifactType.DOM_SNAPSHOT, filename)
                dom_snapshots.append(DOMSnapshot.model_validate(data))
            except Exception as e:
                logger.warning("Failed to load DOM %s: %s", filename, e)

        self.knowledge_graph = builder.build(
            har_files=har_files if har_files else None,
            dom_snapshots=dom_snapshots if dom_snapshots else None,
        )

        # Save graph
        self.store.save(ArtifactType.KNOWLEDGE_GRAPH, self.knowledge_graph.to_snapshot())

        console.print(
            f"[green]Knowledge graph:[/green] {self.knowledge_graph.node_count} nodes, "
            f"{self.knowledge_graph.edge_count} edges"
        )

    async def _reason(self) -> None:
        """Run LLM reasoning to generate vulnerability hypotheses."""
        if not self.settings.openrouter_api_key:
            console.print(
                "[yellow]No OpenRouter API key configured. "
                "Skipping reasoning phase.[/yellow]"
            )
            return

        if self.knowledge_graph.node_count == 0:
            console.print("[yellow]Empty knowledge graph. Skipping reasoning.[/yellow]")
            return

        from nazitest.reasoning.agents import Strategist
        from nazitest.reasoning.openrouter import OpenRouterClient

        client = OpenRouterClient(
            api_key=self.settings.openrouter_api_key,
            models=self.settings.models.models,
            base_url=self.settings.openrouter_base_url,
            budget_limit=self.settings.models.budget.max_cost_per_run_usd,
            warn_at=self.settings.models.budget.warn_at_usd,
        )

        try:
            strategist = Strategist(client)
            graph_summary = self.knowledge_graph.to_snapshot().model_dump(mode="json")

            console.print("[blue]Strategist analyzing attack surface...[/blue]")
            analysis = await strategist.analyze(graph_summary)
            console.print("[green]Analysis complete.[/green]")

            # Try structured output first, fall back to text parsing
            console.print("[blue]Generating vulnerability hypotheses...[/blue]")
            hypotheses: list = []
            hypotheses_text = ""
            try:
                hypotheses = await strategist.hypothesize_structured(
                    analysis, graph_summary
                )
                console.print(
                    f"[green]Structured hypotheses:[/green] {len(hypotheses)} generated"
                )
            except Exception as e:
                logger.warning("Structured output failed, falling back to text: %s", e)
                hypotheses_text = await strategist.hypothesize(analysis, graph_summary)
                hypotheses = Strategist._parse_hypotheses(hypotheses_text)
                console.print(
                    f"[green]Parsed hypotheses from text:[/green] {len(hypotheses)} found"
                )

            # Add hypotheses to knowledge graph
            for h in hypotheses:
                self.knowledge_graph.add_hypothesis(h)

            # Save updated knowledge graph with hypotheses
            assert self.store is not None
            self.store.save(
                ArtifactType.KNOWLEDGE_GRAPH,
                self.knowledge_graph.to_snapshot(),
            )

            # Save reasoning artifacts
            self.store.save(
                ArtifactType.LLM_SESSION,
                {
                    "analysis": analysis,
                    "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
                    "hypotheses_text": hypotheses_text,
                    "usage": client.usage.summary(),
                },
                name="strategist",
            )

            console.print(
                f"[green]Reasoning complete.[/green] "
                f"{len(hypotheses)} hypotheses added to graph. "
                f"Cost: ${client.usage.total_cost_usd:.4f}"
            )
        except Exception as e:
            logger.warning("Reasoning phase failed: %s", e)
            console.print(f"[yellow]Reasoning phase error: {e}[/yellow]")
        finally:
            await client.close()

    def _generate_report(self) -> None:
        """Generate the final report."""
        assert self.store is not None
        gen = ReportGenerator(self.run_path)
        snapshot = self.knowledge_graph.to_snapshot()

        html_path = gen.generate(
            graph=snapshot,
            target_url=self.config.scope.target_url,
            run_id=self.run_id,
        )
        console.print(f"[green]Report generated:[/green] {html_path}")

    def _save_state(self) -> None:
        """Save current state for resume capability."""
        if self.store:
            state = {
                "phase": self.phase.value,
                "run_id": self.run_id,
                "elapsed": time.time() - self.start_time,
            }
            self.store.save(ArtifactType.CONFIG, state, name="state")
            # Save knowledge graph
            self.store.save(
                ArtifactType.KNOWLEDGE_GRAPH,
                self.knowledge_graph.to_snapshot(),
            )

    def _set_phase(self, phase: OrchestratorPhase) -> None:
        self.phase = phase
        logger.info("Phase: %s", phase.value)
        console.print(f"[bold]Phase:[/bold] {phase.value}")

    def _check_time_limit(self) -> bool:
        elapsed_minutes = (time.time() - self.start_time) / 60
        return elapsed_minutes < self.config.time_limit_minutes
