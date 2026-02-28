"""Orchestrator — main state machine tying all phases together."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from nazitest.analysis.graph_builder import GraphBuilder
from nazitest.analysis.knowledge_graph import KnowledgeGraph
from nazitest.config import Settings
from nazitest.core.scope import ScopeEnforcer
from nazitest.exploitation.curl_exploit import CurlExploiter
from nazitest.exploitation.engine import ExploitationEngine
from nazitest.models.config import RunConfig
from nazitest.models.exploit import ExploitResult
from nazitest.models.types import ArtifactType, HttpMethod, OrchestratorPhase
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
        self.exploit_results: list[ExploitResult] = []
        self._usage_tracker: Any = None  # UsageTracker
        self._network_stats: dict[str, Any] = {}
        self._stage_timings: dict[str, dict[str, Any]] = {}

    async def run(self) -> str:
        """Execute the full scan pipeline. Returns the run ID."""
        try:
            # INIT phase
            self._set_phase(OrchestratorPhase.INIT)
            self.run_id, self.run_path = self.run_manager.create_run(self.config)
            self.store = ArtifactStore(self.run_path)
            self.start_time = time.time()
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

            # REASON phase — LLM hypothesis generation
            self._set_phase(OrchestratorPhase.REASON)
            t0 = time.time()
            await self._reason()
            self._stage_timings["reason"] = {
                "elapsed_seconds": round(time.time() - t0, 1),
            }

            # EXPLOIT phase
            self._set_phase(OrchestratorPhase.EXPLOIT)
            t0 = time.time()
            await self._exploit()
            self._stage_timings["exploit"] = {
                "elapsed_seconds": round(time.time() - t0, 1),
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

        return self.run_id

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

            # Accumulate usage for meta.json
            from nazitest.reasoning.openrouter import UsageTracker

            if self._usage_tracker is None:
                self._usage_tracker = UsageTracker()
            self._usage_tracker.merge(client.usage)

            # Save per-stage cost
            self._stage_timings.setdefault("reason", {})[
                "llm_cost_usd"
            ] = round(client.usage.total_cost_usd, 6)
            self._stage_timings.setdefault("reason", {})[
                "llm_calls"
            ] = len(client.usage.calls)

            console.print(
                f"[green]Reasoning complete.[/green] "
                f"{len(hypotheses)} hypotheses added to graph."
            )
        except Exception as e:
            logger.warning("Reasoning phase failed: %s", e)
            console.print(
                f"[yellow]Reasoning phase error: {e}[/yellow]"
            )
        finally:
            await client.close()

    async def _exploit(self) -> None:
        """Agentic exploitation — LLM-driven feedback loop.

        For each hypothesis:
        1. Get baseline response (benign value)
        2. LLM generates 3-5 targeted payloads
        3. Send payloads, collect response behavior
        4. Pattern-match for obvious signals (fast-path)
        5. Show results to LLM → verdict: confirmed/not/retry
        6. If retry: LLM adapts, generates new payloads
        7. Max 3 rounds per hypothesis

        No hardcoded payloads. No confidence scores.
        Binary outcome: confirmed=True or confirmed=False.
        """
        assert self.store is not None
        max_rounds = 3

        if not self.settings.openrouter_api_key:
            console.print(
                "[yellow]No API key. Skipping exploit.[/yellow]"
            )
            return

        hypotheses = self.knowledge_graph.get_all_hypotheses()
        if not hypotheses:
            console.print(
                "[yellow]No hypotheses to exploit.[/yellow]"
            )
            return

        # Load cookies from manual browse
        cookies: dict[str, str] = {}
        try:
            cookie_files = self.store.list_artifacts(
                ArtifactType.COOKIE_JAR
            )
            logger.info(
                "Cookie files found: %s", cookie_files
            )
            if cookie_files:
                cdata = self.store.load(
                    ArtifactType.COOKIE_JAR, cookie_files[-1]
                )
                for c in cdata.get("cookies", []):
                    if (
                        isinstance(c, dict)
                        and "name" in c
                        and "value" in c
                    ):
                        cookies[c["name"]] = c["value"]
                logger.info(
                    "Loaded %d cookies: %s",
                    len(cookies),
                    list(cookies.keys()),
                )
                console.print(
                    f"  [green]Loaded {len(cookies)} cookies: "
                    f"{', '.join(cookies.keys())}[/green]"
                )
            else:
                logger.warning("No cookie files found")
                console.print(
                    "  [yellow]No cookies found — "
                    "exploits may fail on auth-required "
                    "targets[/yellow]"
                )
        except Exception as e:
            logger.warning("Could not load cookies: %s", e)
            console.print(
                f"  [yellow]Cookie load error: {e}[/yellow]"
            )

        from nazitest.reasoning.agents import ExploitPlanner
        from nazitest.reasoning.openrouter import (
            OpenRouterClient,
        )

        client = OpenRouterClient(
            api_key=self.settings.openrouter_api_key,
            models=self.settings.models.models,
            base_url=self.settings.openrouter_base_url,
            budget_limit=(
                self.settings.models.budget
                .max_cost_per_run_usd
            ),
            warn_at=self.settings.models.budget.warn_at_usd,
        )

        proxy_url = self.proxy_manager.get_proxy_url("exploit")
        curl_exploiter = CurlExploiter(proxy_url=proxy_url)
        engine = ExploitationEngine(
            curl_exploiter=curl_exploiter,
            max_attempts=3,
        )

        planner = ExploitPlanner(client)
        target_url = self.config.scope.target_url

        sorted_hyps = sorted(
            hypotheses,
            key=lambda h: h.confidence,
            reverse=True,
        )
        total = len(sorted_hyps)

        try:
            for idx, h in enumerate(sorted_hyps, 1):
                if not self._check_time_limit():
                    console.print(
                        "[yellow]Time limit reached.[/yellow]"
                    )
                    break

                console.print(
                    f"\n[bold][{idx}/{total}] "
                    f"{h.title}[/bold] "
                    f"({h.vuln_type})"
                )
                h_dict = h.model_dump(mode="json")

                try:
                    # Determine HTTP method(s) from hypothesis
                    h_method_str = h_dict.get(
                        "http_method", ""
                    ).upper()
                    if h_method_str == "POST":
                        exploit_methods = (HttpMethod.POST,)
                    elif h_method_str == "GET":
                        exploit_methods = (HttpMethod.GET,)
                    else:
                        # Unknown — try both
                        exploit_methods = (
                            HttpMethod.GET,
                            HttpMethod.POST,
                        )

                    # ── Baseline ──
                    template = ExploitPlanner.build_strategy(
                        h_dict, "1", target_url,
                        exploit_methods[0],
                    )
                    baseline = await engine.get_baseline(
                        template, cookies or None,
                    )
                    baseline_info = (
                        ExploitPlanner.format_baseline_info(
                            baseline
                        )
                    )
                    console.print(
                        f"  Baseline: {baseline_info}"
                    )

                    confirmed = False
                    evidence = ""
                    # (payload, method_str, ExploitResult)
                    all_attempts: list[
                        tuple[str, str, ExploitResult]
                    ] = []

                    payloads: list[str] = []

                    for round_num in range(max_rounds):
                        if confirmed:
                            break
                        if not self._check_time_limit():
                            break

                        # ── Generate payloads ──
                        if round_num == 0:
                            payloads = (
                                await planner
                                .generate_payloads(
                                    h_dict, baseline_info,
                                )
                            )
                            console.print(
                                f"  Round 1: "
                                f"{len(payloads)} payloads"
                            )
                            for p in payloads:
                                console.print(
                                    f"    → {p[:70]}"
                                )

                        if not payloads:
                            console.print(
                                "  No payloads generated"
                            )
                            break

                        # ── Send payloads ──
                        for payload in payloads:
                            if confirmed:
                                break
                            for method in exploit_methods:
                                if confirmed:
                                    break
                                s = (
                                    ExploitPlanner
                                    .build_strategy(
                                        h_dict,
                                        payload,
                                        target_url,
                                        method,
                                    )
                                )
                                r = (
                                    await engine.single_shot(
                                        s,
                                        cookies or None,
                                        vuln_type=(
                                            h.vuln_type
                                        ),
                                        baseline=baseline,
                                    )
                                )
                                all_attempts.append((
                                    payload,
                                    method.value,
                                    r,
                                ))
                                self.exploit_results.append(r)

                                # Fast-path: pattern match
                                if r.confirmed:
                                    confirmed = True
                                    evidence = (
                                        r.evidence_summary
                                    )
                                    self._log_confirmed(
                                        h, s, r,
                                    )

                        if confirmed:
                            break

                        # ── LLM judges results ──
                        results_summary = (
                            ExploitPlanner
                            .format_results_summary(
                                all_attempts, baseline,
                            )
                        )
                        judgment = (
                            await planner.judge_results(
                                h_dict,
                                results_summary,
                                baseline_info,
                            )
                        )

                        verdict = judgment["verdict"]
                        console.print(
                            f"  LLM verdict: {verdict}"
                        )

                        if verdict == "confirmed":
                            confirmed = True
                            evidence = judgment["evidence"]
                            console.print(
                                f"  [bold green]LLM "
                                f"CONFIRMED[/bold green]: "
                                f"{evidence[:200]}"
                            )
                        elif verdict == "not_vulnerable":
                            console.print(
                                f"  LLM: not vulnerable — "
                                f"{judgment['evidence'][:100]}"
                            )
                            break
                        else:
                            # "continue" — new payloads
                            payloads = judgment.get(
                                "next_payloads", []
                            )
                            if not payloads:
                                break
                            console.print(
                                f"  Round {round_num + 2}: "
                                f"{len(payloads)} new "
                                f"payloads"
                            )
                            for p in payloads:
                                console.print(
                                    f"    → {p[:70]}"
                                )

                    # ── Update hypothesis ──
                    h.confirmed = confirmed
                    h.exploitation_attempted = True
                    if confirmed:
                        h.confidence = 1.0
                        poc = next(
                            (
                                r
                                for r in self.exploit_results
                                if r.hypothesis_id == h.id
                                and r.confirmed
                            ),
                            None,
                        )
                        if poc:
                            self.store.save(
                                ArtifactType.POC,
                                {
                                    "hypothesis_id": h.id,
                                    "title": h.title,
                                    "poc_script": (
                                        poc.poc_script
                                    ),
                                    "evidence": (
                                        poc.evidence_summary
                                        or evidence
                                    ),
                                },
                                name=h.id,
                            )
                        # Also mark confirmed for LLM-only
                        # confirmations (no pattern match)
                        if not poc and evidence:
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
                        console.print(
                            "  [yellow]Not confirmed"
                            "[/yellow]"
                        )

                    # Save exploit artifacts
                    h_results = [
                        r
                        for r in self.exploit_results
                        if r.hypothesis_id == h.id
                    ]
                    for i, er in enumerate(h_results):
                        self.store.save(
                            ArtifactType.EXPLOIT_ATTEMPT,
                            er.model_dump(mode="json"),
                            name=f"{h.id}_{i}",
                        )

                    self.knowledge_graph.add_hypothesis(h)

                except Exception as e:
                    logger.warning(
                        "Hypothesis %s failed: %s",
                        h.id, e,
                    )
                    console.print(
                        f"  [red]Error: {e}[/red]"
                    )
                    continue

            # Save final graph
            self.store.save(
                ArtifactType.KNOWLEDGE_GRAPH,
                self.knowledge_graph.to_snapshot(),
            )

            # Accumulate usage
            from nazitest.reasoning.openrouter import (
                UsageTracker,
            )
            if self._usage_tracker is None:
                self._usage_tracker = UsageTracker()
            self._usage_tracker.merge(client.usage)

            self._stage_timings.setdefault("exploit", {})[
                "llm_cost_usd"
            ] = round(client.usage.total_cost_usd, 6)
            self._stage_timings.setdefault("exploit", {})[
                "llm_calls"
            ] = len(client.usage.calls)

            # Network stats
            total_attempts = sum(
                len(r.attempts)
                for r in self.exploit_results
            )
            blocked_attempts = sum(
                sum(1 for a in r.attempts if a.blocked)
                for r in self.exploit_results
            )
            confirmed_count = sum(
                1 for r in self.exploit_results
                if r.confirmed
            )
            tested_hyps = len(set(
                r.hypothesis_id
                for r in self.exploit_results
            ))
            self._network_stats = {
                "exploit_requests_sent": total_attempts,
                "exploit_requests_blocked": blocked_attempts,
                "hypotheses_tested": tested_hyps,
                "hypotheses_confirmed": confirmed_count,
            }

            console.print(
                f"\n[green]Exploitation complete.[/green] "
                f"{tested_hyps} tested, "
                f"{total_attempts} requests, "
                f"{confirmed_count} confirmed."
            )
        except Exception as e:
            logger.warning("Exploit phase failed: %s", e)
            console.print(
                f"[yellow]Exploit error: {e}[/yellow]"
            )
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
