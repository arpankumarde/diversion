"""Orchestrator — main state machine tying all phases together."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from nazitest.analysis.codebase_xref import CodebaseXRef, XRefResult
from nazitest.analysis.graph_builder import GraphBuilder
from nazitest.analysis.knowledge_graph import KnowledgeGraph
from nazitest.analysis.repo_fetcher import RepoFetcher
from nazitest.config import Settings
from nazitest.core.scope import ScopeEnforcer
from nazitest.exploitation.curl_exploit import CurlExploiter
from nazitest.exploitation.engine import ExploitationEngine
from nazitest.models.config import RunConfig
from nazitest.models.exploit import ExploitResult
from nazitest.models.graph import Hypothesis
from nazitest.models.types import ArtifactType, EdgeType, HttpMethod, NodeType, OrchestratorPhase
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
    """Main state machine: INIT -> CRAWL -> MODEL -> CODEBASE -> iterative REASON/SCOUT/EXPLOIT -> REPORT.

    Supports iterative pipeline with vulnerability chaining and web research.
    """

    def __init__(
        self,
        config: RunConfig,
        settings: Settings | None = None,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        self.config = config
        self.settings = settings or Settings.load(config.models_config_path)
        self.phase = OrchestratorPhase.INIT
        self.run_id: str = ""
        self.run_path: Path = Path()
        self._stop_event = stop_event

        # Core components
        self.run_manager = RunManager(config.output_dir)
        self.scope = ScopeEnforcer(config.scope)
        self.proxy_manager = ProxyManager(config.proxy)
        self.knowledge_graph = KnowledgeGraph()

        # Initialized during run
        self.store: ArtifactStore | None = None
        self.start_time: float = 0.0
        self.exploit_results: list[ExploitResult] = []
        self._usage_tracker: Any = None  # UsageTracker
        self._network_stats: dict[str, Any] = {}
        self._stage_timings: dict[str, dict[str, Any]] = {}
        self._xref_result: XRefResult | None = None

        # Iterative pipeline state
        self._tested_hypothesis_ids: set[str] = set()
        self._web_researcher: Any = None  # WebResearcher
        self._exploit_context: dict[str, Any] = {"confirmed_vulns": []}
        self._iterations_completed: int = 0
        self._chain_hypotheses_generated: int = 0

    async def run(self) -> str:
        """Execute the full scan pipeline with iterative REASON→EXPLOIT loop."""
        try:
            # INIT phase
            self._set_phase(OrchestratorPhase.INIT)
            self.run_id, self.run_path = self.run_manager.create_run(self.config)
            self.store = ArtifactStore(self.run_path)
            self.start_time = time.time()
            self._init_web_researcher()
            console.print(f"[green]Run created:[/green] {self.run_id}")

            # CRAWL + RECORD phase
            self._set_phase(OrchestratorPhase.CRAWL)
            t0 = time.time()
            await self._crawl()
            self._stage_timings["crawl"] = {
                "elapsed_seconds": round(time.time() - t0, 1),
            }

            # MODEL phase — build knowledge graph
            self._set_phase(OrchestratorPhase.MODEL)
            t0 = time.time()
            self._build_graph()
            self._stage_timings["model"] = {
                "elapsed_seconds": round(time.time() - t0, 1),
            }

            # CODEBASE phase — optional source code analysis
            if self.config.repo_url or self.config.codebase_path:
                self._set_phase(OrchestratorPhase.CODEBASE)
                t0 = time.time()
                await self._codebase_phase()
                self._stage_timings["codebase"] = {
                    "elapsed_seconds": round(time.time() - t0, 1),
                }

            # ITERATIVE REASON → SCOUT → EXPLOIT → CHAIN loop
            t0_loop = time.time()
            max_iterations = self.config.max_iterations

            for iteration in range(max_iterations):
                if not self._check_time_limit():
                    console.print("[yellow]Time limit reached — stopping iterations.[/yellow]")
                    break

                console.print(
                    f"\n[bold cyan]═══ Iteration {iteration + 1}/{max_iterations} ═══[/bold cyan]"
                )

                # REASON
                self._set_phase(OrchestratorPhase.REASON)
                t0 = time.time()
                new_hypotheses = await self._reason_iteration(iteration)
                self._stage_timings.setdefault(f"reason_iter{iteration}", {})[
                    "elapsed_seconds"
                ] = round(time.time() - t0, 1)

                if not new_hypotheses:
                    console.print("[yellow]No new hypotheses — stopping iterations.[/yellow]")
                    break

                # SCOUT (optional)
                if self.config.enable_scout:
                    t0 = time.time()
                    await self._scout_phase(new_hypotheses, iteration)
                    self._stage_timings.setdefault(f"scout_iter{iteration}", {})[
                        "elapsed_seconds"
                    ] = round(time.time() - t0, 1)

                # EXPLOIT
                self._set_phase(OrchestratorPhase.EXPLOIT)
                t0 = time.time()
                await self._exploit_iteration(new_hypotheses, iteration)
                self._stage_timings.setdefault(f"exploit_iter{iteration}", {})[
                    "elapsed_seconds"
                ] = round(time.time() - t0, 1)

                self._iterations_completed = iteration + 1

                # CHAIN ANALYSIS (skip on last iteration)
                if iteration < max_iterations - 1:
                    confirmed = [
                        h for h in self.knowledge_graph.get_confirmed_hypotheses()
                        if h.iteration == iteration
                    ]
                    if not confirmed:
                        console.print(
                            "[yellow]No confirmed vulns in this iteration "
                            "— stopping.[/yellow]"
                        )
                        break
                    chains = await self._chain_analysis(confirmed, iteration)
                    if not chains:
                        console.print("[yellow]No chain hypotheses — stopping.[/yellow]")
                        break

            self._stage_timings["iterative_loop"] = {
                "elapsed_seconds": round(time.time() - t0_loop, 1),
                "iterations_completed": self._iterations_completed,
            }

            # REPORT phase
            self._set_phase(OrchestratorPhase.REPORT)
            t0 = time.time()
            self._generate_report()
            self._stage_timings["report"] = {
                "elapsed_seconds": round(time.time() - t0, 1),
            }

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
        finally:
            if self._web_researcher:
                try:
                    await self._web_researcher.close()
                except Exception:
                    pass

        return self.run_id

    def _init_web_researcher(self) -> None:
        """Initialize web researcher if BrightData API key is available."""
        if self.settings.brightdata_api_key and self.config.enable_web_research:
            try:
                from nazitest.reasoning.web_research import WebResearcher, BrightDataClient
                if BrightDataClient is None:
                    console.print("[yellow]Web research disabled[/yellow] (brightdata package not installed — pip install brightdata)")
                    return
                self._web_researcher = WebResearcher(api_key=self.settings.brightdata_api_key)
                console.print("[green]Web research enabled[/green] (BrightData)")
            except Exception as e:
                console.print(f"[yellow]Web research disabled[/yellow] ({e})")
        else:
            console.print("[yellow]Web research disabled[/yellow] (no BRIGHTDATA_API_KEY)")

    def _create_openrouter_client(self) -> Any:
        """Create a fresh OpenRouterClient."""
        from nazitest.reasoning.openrouter import OpenRouterClient
        return OpenRouterClient(
            api_key=self.settings.openrouter_api_key,
            models=self.settings.models.models,
            base_url=self.settings.openrouter_base_url,
            budget_limit=self.settings.models.budget.max_cost_per_run_usd,
            warn_at=self.settings.models.budget.warn_at_usd,
        )

    def _merge_usage(self, client: Any) -> None:
        """Merge client usage into the global tracker."""
        from nazitest.reasoning.openrouter import UsageTracker
        if self._usage_tracker is None:
            self._usage_tracker = UsageTracker()
        self._usage_tracker.merge(client.usage)

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

            if self._stop_event:
                # Server mode: wait for stop signal from API
                console.print(
                    "\n[bold yellow]Browse the target in the browser window.[/bold yellow]"
                    "\n[bold yellow]Call POST /api/scans/{run_id}/stop when done.[/bold yellow]\n"
                )
                await self._stop_event.wait()
            else:
                # CLI mode: block until user presses ENTER
                console.print(
                    "\n[bold yellow]Browse the target in the browser window.[/bold yellow]"
                    "\n[bold yellow]Press ENTER here when done...[/bold yellow]\n"
                )
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
                logger.info("Cookies captured: %d", len(cookies) if cookies else 0)
                if cookies:
                    self.store.save(ArtifactType.COOKIE_JAR, {"cookies": cookies})
                    console.print(f"  [green]Saved {len(cookies)} cookies[/green]")
                    for c in cookies:
                        name = c.get("name", "?")
                        httponly = c.get("httpOnly", False)
                        logger.info("  Cookie: %s (httpOnly=%s)", name, httponly)
                else:
                    console.print("  [yellow]No cookies captured[/yellow]")
            except Exception as e:
                logger.error("Cookie capture failed: %s", e)
                console.print(f"  [red]Cookie capture failed: {e}[/red]")

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

    async def _reason_iteration(self, iteration: int) -> list[Hypothesis]:
        """Run LLM reasoning for a single iteration. Returns new hypotheses."""
        if not self.settings.openrouter_api_key:
            console.print(
                "[yellow]No OpenRouter API key configured. "
                "Skipping reasoning phase.[/yellow]"
            )
            return []

        if self.knowledge_graph.node_count == 0:
            console.print("[yellow]Empty knowledge graph. Skipping reasoning.[/yellow]")
            return []

        from nazitest.reasoning.agents import Strategist

        client = self._create_openrouter_client()

        try:
            strategist = Strategist(
                client, web_researcher=self._web_researcher,
            )
            graph_summary = self.knowledge_graph.to_snapshot().model_dump(mode="json")
            code_context = self._build_code_context()

            if iteration == 0:
                # First iteration: full analysis + hypothesis generation
                console.print("[blue]Strategist analyzing attack surface...[/blue]")
                analysis = await strategist.analyze(
                    graph_summary, code_context=code_context,
                )
                console.print("[green]Analysis complete.[/green]")

                console.print("[blue]Generating vulnerability hypotheses...[/blue]")
                hypotheses: list[Hypothesis] = []
                hypotheses_text = ""
                try:
                    hypotheses = await strategist.hypothesize_structured(
                        analysis, graph_summary,
                        code_context=code_context,
                        exploit_context=self._exploit_context if self._exploit_context.get(
                            "confirmed_vulns"
                        ) else None,
                    )
                    console.print(
                        f"[green]Structured hypotheses:[/green] "
                        f"{len(hypotheses)} generated"
                    )
                except Exception as e:
                    logger.warning(
                        "Structured output failed, falling back to text: %s", e,
                    )
                    hypotheses_text = await strategist.hypothesize(
                        analysis, graph_summary,
                    )
                    hypotheses = Strategist._parse_hypotheses(hypotheses_text)
                    console.print(
                        f"[green]Parsed hypotheses from text:[/green] "
                        f"{len(hypotheses)} found"
                    )
            else:
                # Iteration 1+: chain hypotheses were already added to graph
                # by _chain_analysis() in previous iteration — retrieve them
                hypotheses = [
                    h for h in self.knowledge_graph.get_all_hypotheses()
                    if h.iteration == iteration
                    and h.id not in self._tested_hypothesis_ids
                ]
                console.print(
                    f"[blue]Iteration {iteration + 1}:[/blue] "
                    f"{len(hypotheses)} chain hypotheses to test"
                )

            # Filter out already-tested hypotheses
            new_hypotheses = [
                h for h in hypotheses
                if h.id not in self._tested_hypothesis_ids
            ]

            # Add hypotheses to knowledge graph (iteration 0 only — chains already added)
            if iteration == 0:
                for h in new_hypotheses:
                    self.knowledge_graph.add_hypothesis(h)

            # Save updated knowledge graph
            assert self.store is not None
            self.store.save(
                ArtifactType.KNOWLEDGE_GRAPH,
                self.knowledge_graph.to_snapshot(),
            )

            # Save reasoning artifacts
            self.store.save(
                ArtifactType.LLM_SESSION,
                {
                    "iteration": iteration,
                    "hypotheses": [
                        h.model_dump(mode="json") for h in new_hypotheses
                    ],
                    "usage": client.usage.summary(),
                },
                name=f"strategist_iter{iteration}",
            )

            self._merge_usage(client)

            stage_key = f"reason_iter{iteration}"
            self._stage_timings.setdefault(stage_key, {})[
                "llm_cost_usd"
            ] = round(client.usage.total_cost_usd, 6)
            self._stage_timings.setdefault(stage_key, {})[
                "llm_calls"
            ] = len(client.usage.calls)

            console.print(
                f"[green]Reasoning complete.[/green] "
                f"{len(new_hypotheses)} new hypotheses."
            )
            return new_hypotheses

        except Exception as e:
            logger.warning("Reasoning phase failed: %s", e)
            console.print(f"[yellow]Reasoning phase error: {e}[/yellow]")
            return []
        finally:
            await client.close()

    async def _scout_phase(
        self, hypotheses: list[Hypothesis], iteration: int,
    ) -> None:
        """Scout investigates hypotheses concurrently, optionally cross-validates."""
        if not self.settings.openrouter_api_key:
            return

        from nazitest.reasoning.agents import CrossValidator, Scout
        from nazitest.reasoning.belief import BeliefRefinementLoop

        client = self._create_openrouter_client()
        belief_loop = BeliefRefinementLoop()
        concurrency = min(self.config.max_concurrent_connections, 5)

        try:
            scout = Scout(client, web_researcher=self._web_researcher)
            cross_validator = (
                CrossValidator(client) if self.config.enable_cross_validator else None
            )

            graph_summary = self.knowledge_graph.to_snapshot().model_dump(mode="json")

            async def _investigate_one(h: Hypothesis) -> None:
                if client.usage.budget_exceeded or not self._check_time_limit():
                    return
                h_dict = h.model_dump(mode="json")
                try:
                    scout_response = await scout.investigate(
                        h_dict, {"graph_summary": graph_summary},
                    )
                    scout_confidence = BeliefRefinementLoop.parse_confidence_from_llm(
                        scout_response,
                    )
                    if scout_confidence is not None:
                        old_conf = h.confidence
                        belief_loop.update_belief(h, scout_confidence)
                        console.print(
                            f"  [blue]Scout:[/blue] {h.title[:50]} "
                            f"→ {scout_confidence:.2f} ({old_conf:.2f} → {h.confidence:.2f})"
                        )
                    else:
                        console.print(
                            f"  [blue]Scout:[/blue] {h.title[:50]} → no confidence parsed"
                        )

                    if cross_validator and belief_loop.is_ready_for_cross_validation(h):
                        cv_response = await cross_validator.challenge(h_dict, {
                            "scout_response": scout_response,
                            "graph_summary": graph_summary,
                        })
                        cv_confidence = BeliefRefinementLoop.parse_confidence_from_llm(
                            cv_response,
                        )
                        if cv_confidence is not None:
                            old_conf = h.confidence
                            belief_loop.reconcile(h, cv_confidence)
                            console.print(
                                f"    CrossValidator: {cv_confidence:.2f} "
                                f"(adjusted → {h.confidence:.2f})"
                            )

                    self.knowledge_graph.add_hypothesis(h)
                except Exception as e:
                    logger.warning("Scout failed for %s: %s", h.id, e)

            # Process in concurrent batches
            console.print(
                f"  [blue]Scout investigating {len(hypotheses)} hypotheses "
                f"({concurrency} concurrent)...[/blue]"
            )
            sem = asyncio.Semaphore(concurrency)

            async def _limited(h: Hypothesis) -> None:
                async with sem:
                    await _investigate_one(h)

            await asyncio.gather(*[_limited(h) for h in hypotheses])

            self._merge_usage(client)

            stage_key = f"scout_iter{iteration}"
            self._stage_timings.setdefault(stage_key, {})[
                "llm_cost_usd"
            ] = round(client.usage.total_cost_usd, 6)
            self._stage_timings.setdefault(stage_key, {})[
                "llm_calls"
            ] = len(client.usage.calls)

        except Exception as e:
            logger.warning("Scout phase failed: %s", e)
            console.print(f"[yellow]Scout error: {e}[/yellow]")
        finally:
            await client.close()

    async def _exploit_iteration(
        self, hypotheses: list[Hypothesis], iteration: int,
    ) -> None:
        """Agentic exploitation for a specific set of hypotheses.

        For each hypothesis:
        1. Get baseline response (benign value)
        2. LLM generates 3-5 targeted payloads (with web research)
        3. Send payloads, collect response behavior
        4. Pattern-match for obvious signals (fast-path)
        5. Show results to LLM → verdict: confirmed/not/retry
        6. If retry: LLM adapts, generates new payloads
        7. Max 3 rounds per hypothesis
        """
        assert self.store is not None
        max_rounds = 3

        if not self.settings.openrouter_api_key:
            console.print("[yellow]No API key. Skipping exploit.[/yellow]")
            return

        if not hypotheses:
            console.print("[yellow]No hypotheses to exploit.[/yellow]")
            return

        # Load cookies from manual browse
        cookies: dict[str, str] = {}
        try:
            cookie_files = self.store.list_artifacts(ArtifactType.COOKIE_JAR)
            if cookie_files:
                cdata = self.store.load(ArtifactType.COOKIE_JAR, cookie_files[-1])
                for c in cdata.get("cookies", []):
                    if isinstance(c, dict) and "name" in c and "value" in c:
                        cookies[c["name"]] = c["value"]
                if iteration == 0:
                    console.print(
                        f"  [green]Loaded {len(cookies)} cookies: "
                        f"{', '.join(cookies.keys())}[/green]"
                    )
            elif iteration == 0:
                console.print(
                    "  [yellow]No cookies found — exploits may fail "
                    "on auth-required targets[/yellow]"
                )
        except Exception as e:
            logger.warning("Could not load cookies: %s", e)

        from nazitest.reasoning.agents import ExploitPlanner

        client = self._create_openrouter_client()
        proxy_url = self.proxy_manager.get_proxy_url("exploit")
        curl_exploiter = CurlExploiter(proxy_url=proxy_url)
        engine = ExploitationEngine(curl_exploiter=curl_exploiter, max_attempts=3)

        planner = ExploitPlanner(client, web_researcher=self._web_researcher)
        target_url = self.config.scope.target_url

        sorted_hyps = sorted(hypotheses, key=lambda h: h.confidence, reverse=True)
        total = len(sorted_hyps)

        try:
            for idx, h in enumerate(sorted_hyps, 1):
                if not self._check_time_limit():
                    console.print("[yellow]Time limit reached.[/yellow]")
                    break
                if client.usage.budget_exceeded:
                    console.print("[yellow]Budget exceeded.[/yellow]")
                    break

                console.print(
                    f"\n[bold][{idx}/{total}] {h.title}[/bold] ({h.vuln_type})"
                )
                h_dict = h.model_dump(mode="json")

                try:
                    # Determine HTTP method(s)
                    h_method_str = h_dict.get("http_method", "").upper()
                    if h_method_str == "POST":
                        exploit_methods = (HttpMethod.POST,)
                    elif h_method_str == "GET":
                        exploit_methods = (HttpMethod.GET,)
                    else:
                        exploit_methods = (HttpMethod.GET, HttpMethod.POST)

                    # Baseline
                    template = ExploitPlanner.build_strategy(
                        h_dict, "1", target_url, exploit_methods[0],
                    )
                    baseline = await engine.get_baseline(template, cookies or None)
                    baseline_info = ExploitPlanner.format_baseline_info(baseline)
                    console.print(f"  Baseline: {baseline_info}")

                    confirmed = False
                    evidence = ""
                    all_attempts: list[tuple[str, str, ExploitResult]] = []
                    payloads: list[str] = []

                    for round_num in range(max_rounds):
                        if confirmed or not self._check_time_limit():
                            break

                        # Generate payloads
                        if round_num == 0:
                            payloads = await planner.generate_payloads(
                                h_dict, baseline_info,
                            )
                            console.print(f"  Round 1: {len(payloads)} payloads")
                            for p in payloads:
                                console.print(f"    → {p[:70]}")

                        if not payloads:
                            console.print("  No payloads generated")
                            break

                        # Send payloads
                        for payload in payloads:
                            if confirmed:
                                break
                            for method in exploit_methods:
                                if confirmed:
                                    break
                                s = ExploitPlanner.build_strategy(
                                    h_dict, payload, target_url, method,
                                )
                                r = await engine.single_shot(
                                    s, cookies or None,
                                    vuln_type=h.vuln_type, baseline=baseline,
                                )
                                all_attempts.append((payload, method.value, r))
                                self.exploit_results.append(r)

                                if r.confirmed:
                                    confirmed = True
                                    evidence = r.evidence_summary
                                    self._log_confirmed(h, s, r)

                        if confirmed:
                            break

                        # LLM judges results
                        results_summary = ExploitPlanner.format_results_summary(
                            all_attempts, baseline,
                        )
                        judgment = await planner.judge_results(
                            h_dict, results_summary, baseline_info,
                        )

                        verdict = judgment["verdict"]
                        console.print(f"  LLM verdict: {verdict}")

                        if verdict == "confirmed":
                            confirmed = True
                            evidence = judgment["evidence"]
                            console.print(
                                f"  [bold green]LLM CONFIRMED[/bold green]: "
                                f"{evidence[:200]}"
                            )
                        elif verdict == "not_vulnerable":
                            console.print(
                                f"  LLM: not vulnerable — "
                                f"{judgment['evidence'][:100]}"
                            )
                            break
                        else:
                            payloads = judgment.get("next_payloads", [])
                            if not payloads:
                                break
                            console.print(
                                f"  Round {round_num + 2}: "
                                f"{len(payloads)} new payloads"
                            )
                            for p in payloads:
                                console.print(f"    → {p[:70]}")

                    # Update hypothesis
                    h.confirmed = confirmed
                    h.exploitation_attempted = True
                    self._tested_hypothesis_ids.add(h.id)

                    if confirmed:
                        h.confidence = 1.0
                        # Track in exploit context for chain analysis
                        self._exploit_context["confirmed_vulns"].append({
                            "id": h.id,
                            "title": h.title,
                            "vuln_type": h.vuln_type,
                            "target_endpoint": h.target_endpoint,
                            "target_parameter": h.target_parameter,
                            "evidence": evidence[:500],
                            "iteration": iteration,
                        })

                        poc = next(
                            (r for r in self.exploit_results
                             if r.hypothesis_id == h.id and r.confirmed),
                            None,
                        )
                        if poc:
                            self.store.save(
                                ArtifactType.POC,
                                {
                                    "hypothesis_id": h.id,
                                    "title": h.title,
                                    "poc_script": poc.poc_script,
                                    "evidence": poc.evidence_summary or evidence,
                                },
                                name=h.id,
                            )
                        elif evidence:
                            self.store.save(
                                ArtifactType.POC,
                                {
                                    "hypothesis_id": h.id,
                                    "title": h.title,
                                    "poc_script": "",
                                    "evidence": evidence,
                                },
                                name=h.id,
                            )
                    else:
                        console.print("  [yellow]Not confirmed[/yellow]")

                    # Save exploit artifacts
                    h_results = [
                        r for r in self.exploit_results if r.hypothesis_id == h.id
                    ]
                    for i, er in enumerate(h_results):
                        self.store.save(
                            ArtifactType.EXPLOIT_ATTEMPT,
                            er.model_dump(mode="json"),
                            name=f"{h.id}_{i}",
                        )

                    self.knowledge_graph.add_hypothesis(h)

                except Exception as e:
                    logger.warning("Hypothesis %s failed: %s", h.id, e)
                    console.print(f"  [red]Error: {e}[/red]")
                    self._tested_hypothesis_ids.add(h.id)
                    continue

            # Save final graph
            self.store.save(
                ArtifactType.KNOWLEDGE_GRAPH,
                self.knowledge_graph.to_snapshot(),
            )

            self._merge_usage(client)

            stage_key = f"exploit_iter{iteration}"
            self._stage_timings.setdefault(stage_key, {})[
                "llm_cost_usd"
            ] = round(client.usage.total_cost_usd, 6)
            self._stage_timings.setdefault(stage_key, {})[
                "llm_calls"
            ] = len(client.usage.calls)

            # Update network stats
            total_attempts = sum(len(r.attempts) for r in self.exploit_results)
            blocked_attempts = sum(
                sum(1 for a in r.attempts if a.blocked) for r in self.exploit_results
            )
            confirmed_count = sum(1 for r in self.exploit_results if r.confirmed)
            tested_hyps = len(self._tested_hypothesis_ids)
            self._network_stats = {
                "exploit_requests_sent": total_attempts,
                "exploit_requests_blocked": blocked_attempts,
                "hypotheses_tested": tested_hyps,
                "hypotheses_confirmed": confirmed_count,
            }

            console.print(
                f"\n[green]Exploitation iteration {iteration + 1} complete.[/green] "
                f"{len(sorted_hyps)} tested, {confirmed_count} total confirmed."
            )
        except Exception as e:
            logger.warning("Exploit phase failed: %s", e)
            console.print(f"[yellow]Exploit error: {e}[/yellow]")
        finally:
            await client.close()

    async def _chain_analysis(
        self, confirmed_hyps: list[Hypothesis], iteration: int,
    ) -> list[Hypothesis]:
        """Generate chain hypotheses from confirmed vulns."""
        if not self.settings.openrouter_api_key:
            return []

        from nazitest.reasoning.agents import Strategist

        client = self._create_openrouter_client()

        try:
            strategist = Strategist(client, web_researcher=self._web_researcher)
            graph_summary = self.knowledge_graph.to_snapshot().model_dump(mode="json")

            confirmed_dicts = [h.model_dump(mode="json") for h in confirmed_hyps]

            console.print(
                f"[blue]Chain analysis:[/blue] {len(confirmed_hyps)} confirmed vulns "
                f"→ generating follow-up hypotheses..."
            )

            chain_hypotheses = await strategist.generate_chain_hypotheses(
                confirmed_vulns=confirmed_dicts,
                graph_summary=graph_summary,
                exploit_context=self._exploit_context,
                iteration=iteration,
            )

            # Add to knowledge graph
            for h in chain_hypotheses:
                self.knowledge_graph.add_hypothesis(h)

            self._chain_hypotheses_generated += len(chain_hypotheses)
            self._merge_usage(client)

            console.print(
                f"[green]Chain analysis:[/green] {len(chain_hypotheses)} "
                f"follow-up hypotheses generated"
            )

            # Save chain artifacts
            assert self.store is not None
            self.store.save(
                ArtifactType.LLM_SESSION,
                {
                    "chain_from": [h.id for h in confirmed_hyps],
                    "iteration": iteration,
                    "chain_hypotheses": [
                        h.model_dump(mode="json") for h in chain_hypotheses
                    ],
                    "usage": client.usage.summary(),
                },
                name=f"chain_iter{iteration}",
            )

            return chain_hypotheses

        except Exception as e:
            logger.warning("Chain analysis failed: %s", e)
            console.print(f"[yellow]Chain analysis error: {e}[/yellow]")
            return []
        finally:
            await client.close()

    @staticmethod
    def _log_confirmed(
        h: Any, strategy: Any, result: ExploitResult
    ) -> None:
        console.print(
            f"  [bold green]CONFIRMED[/bold green] "
            f"{strategy.http_method.value} {strategy.url}"
        )
        if result.evidence_summary:
            console.print(
                f"  Evidence: "
                f"{result.evidence_summary[:200]}"
            )

    def _generate_report(self) -> None:
        """Generate the final report and meta.json."""
        assert self.store is not None
        gen = ReportGenerator(self.run_path)
        snapshot = self.knowledge_graph.to_snapshot()

        elapsed = time.time() - self.start_time
        usage_summary = (
            self._usage_tracker.summary()
            if self._usage_tracker
            else {}
        )

        html_path = gen.generate(
            graph=snapshot,
            exploit_results=self.exploit_results,
            target_url=self.config.scope.target_url,
            run_id=self.run_id,
        )

        # Build per-model cost breakdown
        per_model_costs: dict[str, Any] = {}
        if usage_summary:
            for model_id, mdata in usage_summary.get(
                "per_model", {}
            ).items():
                per_model_costs[model_id] = {
                    "input_tokens": mdata["input_tokens"],
                    "output_tokens": mdata["output_tokens"],
                    "total_tokens": (
                        mdata["input_tokens"]
                        + mdata["output_tokens"]
                    ),
                    "cost_usd": round(mdata["cost_usd"], 6),
                    "calls": mdata["calls"],
                }

        # Save meta.json
        meta = {
            "run_id": self.run_id,
            "target_url": self.config.scope.target_url,
            "generated_at": time.strftime(
                "%Y-%m-%dT%H:%M:%S%z"
            ),
            "total_elapsed_seconds": round(elapsed, 1),
            "stages": self._stage_timings,
            "llm_usage": {
                "total_input_tokens": usage_summary.get(
                    "total_input_tokens", 0
                ),
                "total_output_tokens": usage_summary.get(
                    "total_output_tokens", 0
                ),
                "total_tokens": (
                    usage_summary.get("total_input_tokens", 0)
                    + usage_summary.get(
                        "total_output_tokens", 0
                    )
                ),
                "total_cost_usd": round(
                    usage_summary.get("total_cost_usd", 0), 6
                ),
                "total_calls": usage_summary.get(
                    "total_calls", 0
                ),
                "budget_limit_usd": usage_summary.get(
                    "budget_limit", 10.0
                ),
                "per_model": per_model_costs,
            },
            "network": {
                "recon_pages_captured": len(
                    self.store.list_artifacts(
                        ArtifactType.DOM_SNAPSHOT
                    )
                ),
                "recon_har_files": len(
                    self.store.list_artifacts(ArtifactType.HAR)
                ),
                **self._network_stats,
            },
            "knowledge_graph": {
                "nodes": self.knowledge_graph.node_count,
                "edges": self.knowledge_graph.edge_count,
                "total_hypotheses": len(
                    self.knowledge_graph.get_all_hypotheses()
                ),
                "confirmed_vulnerabilities": len(
                    self.knowledge_graph
                    .get_confirmed_hypotheses()
                ),
                "exploitable": len(
                    self.knowledge_graph
                    .get_exploitable_hypotheses()
                ),
            },
            "iterative_pipeline": {
                "iterations_completed": self._iterations_completed,
                "chain_hypotheses_generated": self._chain_hypotheses_generated,
                "total_hypotheses_tested": len(self._tested_hypothesis_ids),
                "web_research_enabled": self._web_researcher is not None,
                "scout_enabled": self.config.enable_scout,
                "cross_validator_enabled": self.config.enable_cross_validator,
            },
        }
        gen.save_meta(meta)

        # Print cost summary
        if usage_summary:
            cost = usage_summary.get("total_cost_usd", 0)
            in_tok = usage_summary.get("total_input_tokens", 0)
            out_tok = usage_summary.get(
                "total_output_tokens", 0
            )
            console.print(
                f"[green]Report generated:[/green] {html_path}"
            )
            console.print(
                f"[blue]LLM usage:[/blue] "
                f"{in_tok:,} input + {out_tok:,} output "
                f"tokens = ${cost:.4f}"
            )
        else:
            console.print(
                f"[green]Report generated:[/green] {html_path}"
            )

    async def _codebase_phase(self) -> None:
        """Run source code analysis: clone repo if needed, then AST analysis."""
        assert self.store is not None
        loop = asyncio.get_event_loop()

        # Clone repo if repo_url given but no local codebase_path
        if self.config.repo_url and not self.config.codebase_path:
            console.print(f"[blue]Cloning repo:[/blue] {self.config.repo_url}")
            fetcher = RepoFetcher(cache_dir=self.config.repo_cache_dir)
            try:
                local_path = await loop.run_in_executor(
                    None, fetcher.fetch, self.config.repo_url,
                )
                self.config.codebase_path = local_path
                console.print(f"[green]Repo cached at:[/green] {local_path}")
            except Exception as e:
                logger.error("Repo clone failed: %s", e)
                console.print(f"[red]Repo clone failed: {e}[/red]")
                return

        if not self.config.codebase_path:
            return

        console.print(
            f"[blue]Analyzing codebase:[/blue] {self.config.codebase_path}"
        )

        xref = CodebaseXRef()
        try:
            self._xref_result = await loop.run_in_executor(
                None, xref.analyze, self.config.codebase_path,
            )
        except Exception as e:
            logger.error("Codebase analysis failed: %s", e)
            console.print(f"[red]Codebase analysis failed: {e}[/red]")
            return

        # Save artifact
        self.store.save(ArtifactType.CODEBASE_XREF, self._xref_result)

        # Inject into knowledge graph
        self._build_graph_phase3(self._xref_result)

        console.print(
            f"[green]Codebase analysis:[/green] "
            f"{len(self._xref_result.routes)} routes, "
            f"{len(self._xref_result.sink_flows)} sinks, "
            f"{len(self._xref_result.auth_patterns)} auth patterns, "
            f"languages: {', '.join(self._xref_result.languages_detected)}"
        )

    def _build_graph_phase3(self, xref: XRefResult) -> None:
        """Inject codebase cross-reference into knowledge graph (Phase 3).

        FIX 5: Uses source_module to find sinks in the handler's actual source file,
        not just sinks co-located with the route registration.
        """
        assert self.store is not None

        # Pre-index sinks by file for fast lookup
        sinks_by_file: dict[str, list] = {}
        for s in xref.sink_flows:
            sinks_by_file.setdefault(s.file_path, []).append(s)

        # Create CODE_HANDLER nodes for each route
        for route in xref.routes:
            handler_id = self.knowledge_graph.add_node(
                NodeType.CODE_HANDLER,
                f"{','.join(route.methods)} {route.path}",
                source_file=route.file_path,
                line_number=route.line_number,
                framework=route.framework,
                handler=route.handler,
            )

            # Try to correlate with existing ENDPOINT nodes by path
            for ep_id, ep_data in self.knowledge_graph.get_nodes_by_type(NodeType.ENDPOINT):
                ep_url = ep_data.get("url", "")
                ep_parsed = urlparse(ep_url)
                ep_path = ep_parsed.path.rstrip("/") or "/"
                route_path = route.path.rstrip("/") or "/"

                if ep_path == route_path:
                    self.knowledge_graph.add_edge(
                        ep_id, handler_id, EdgeType.HANDLED_BY,
                    )

            # FIX 5: Find sinks in the handler's actual source file
            # Priority 1: source_module (the imported handler file)
            # Priority 2: same file as route registration, within ±50 lines
            handler_files = set()
            if route.source_module:
                # source_module is like "routes/search" — try with extensions
                for ext in (".ts", ".js", ".py", ".java", ".go", ".rb", ".php", ""):
                    candidate = route.source_module + ext
                    if candidate in sinks_by_file:
                        handler_files.add(candidate)
                        break
            handler_files.add(route.file_path)

            nearby_sinks = []
            for hf in handler_files:
                for s in sinks_by_file.get(hf, []):
                    if hf == route.file_path:
                        # Same file: require proximity
                        if abs(s.line_number - route.line_number) <= 50:
                            nearby_sinks.append(s)
                    else:
                        # Handler source file: all sinks are relevant
                        nearby_sinks.append(s)

            if nearby_sinks:
                sink_types = sorted({s.sink_type for s in nearby_sinks})
                sink_details = [
                    f"{s.sink_type}: {s.sink} at {s.file_path}:{s.line_number}"
                    for s in nearby_sinks
                ]
                self.knowledge_graph._graph.nodes[handler_id]["nearby_sinks"] = sink_types
                self.knowledge_graph._graph.nodes[handler_id]["sink_details"] = sink_details

        # Save updated graph
        self.store.save(
            ArtifactType.KNOWLEDGE_GRAPH,
            self.knowledge_graph.to_snapshot(),
        )

    def _build_code_context(self) -> dict | None:
        """Build code context dict from xref result for LLM reasoning.

        FIX 6: Prioritizes security-relevant findings, deduplicates,
        and correlates routes with their nearby sinks.
        """
        if not self._xref_result:
            return None

        from nazitest.analysis.codebase_xref import SINK_DANGER_RANK

        xref = self._xref_result

        # Sort sinks by danger rank (sql/command first), deduplicate
        seen_sinks: set[str] = set()
        ranked_sinks = sorted(
            xref.sink_flows,
            key=lambda s: SINK_DANGER_RANK.get(s.sink_type, 0),
            reverse=True,
        )
        deduped_sinks: list[dict] = []
        for s in ranked_sinks:
            key = f"{s.sink}:{s.file_path}:{s.line_number}"
            if key not in seen_sinks:
                seen_sinks.add(key)
                deduped_sinks.append(s.model_dump(mode="json"))
            if len(deduped_sinks) >= 30:
                break

        # Build route-to-sink correlation map
        sinks_by_file: dict[str, list] = {}
        for s in xref.sink_flows:
            sinks_by_file.setdefault(s.file_path, []).append(s)

        # Score routes: routes with nearby sinks are more interesting
        def route_score(r: object) -> int:
            score = 0
            # Check for sinks in same file or source module
            for check_file in (r.file_path, r.source_module):
                if not check_file:
                    continue
                for ext in ("", ".ts", ".js", ".py"):
                    for s in sinks_by_file.get(check_file + ext, []):
                        score += SINK_DANGER_RANK.get(s.sink_type, 1)
            return score

        ranked_routes = sorted(xref.routes, key=route_score, reverse=True)

        # Build correlated route entries for LLM
        route_entries: list[dict] = []
        for r in ranked_routes[:30]:
            entry = r.model_dump(mode="json")
            # Add correlated sinks inline
            correlated = []
            for check_file in (r.file_path, r.source_module):
                if not check_file:
                    continue
                for ext in ("", ".ts", ".js", ".py"):
                    for s in sinks_by_file.get(check_file + ext, []):
                        correlated.append(f"{s.sink_type}: {s.sink} at {s.file_path}:{s.line_number}")
            if correlated:
                entry["correlated_sinks"] = correlated[:5]
            route_entries.append(entry)

        auth = xref.auth_patterns[:15]

        if not route_entries and not deduped_sinks and not auth:
            return None

        return {
            "routes": route_entries,
            "sinks": deduped_sinks,
            "auth_patterns": auth,
            "languages": xref.languages_detected,
        }

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
