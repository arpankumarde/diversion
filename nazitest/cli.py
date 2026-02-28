"""Typer CLI — scan, resume, report, graph commands."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel

from nazitest import __version__

app = typer.Typer(
    name="nazitest",
    help="AI-powered autonomous penetration testing framework.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"nazitest v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", help="Show version and exit.", callback=version_callback),
    ] = None,
) -> None:
    """NAZITEST — AI-powered autonomous penetration testing framework."""


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target URL to scan.")],
    scope: Annotated[
        Optional[str],
        typer.Option("--scope", "-s", help="Allowed domain scope (comma-separated)."),
    ] = None,
    codebase: Annotated[
        Optional[Path],
        typer.Option("--codebase", "-c", help="Path to target source code."),
    ] = None,
    proxy: Annotated[
        Optional[str],
        typer.Option("--proxy", "-p", help="Proxy URL (e.g. socks5://host:port)."),
    ] = None,
    models: Annotated[
        Path,
        typer.Option("--models", "-m", help="Path to models.yaml config."),
    ] = Path("models.yaml"),
    depth: Annotated[int, typer.Option("--depth", help="Max crawl depth.")] = 5,
    pages: Annotated[int, typer.Option("--pages", help="Max pages to crawl.")] = 200,
    time_limit: Annotated[
        int, typer.Option("--time-limit", help="Time limit in minutes.")
    ] = 120,
    exploit_mode: Annotated[
        str,
        typer.Option("--exploit-mode", help="Exploit mode: confirm|safe|aggressive."),
    ] = "confirm",
    no_exploit: Annotated[
        bool, typer.Option("--no-exploit", help="Skip exploitation phase.")
    ] = False,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output directory.")
    ] = Path("./nazitest_runs"),
) -> None:
    """Start a new penetration test scan."""
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Scope:[/bold] {scope or 'auto-detect'}\n"
            f"[bold]Exploit mode:[/bold] {'disabled' if no_exploit else exploit_mode}\n"
            f"[bold]Depth:[/bold] {depth} | [bold]Pages:[/bold] {pages}\n"
            f"[bold]Time limit:[/bold] {time_limit} min",
            title="NAZITEST Scan",
            border_style="green",
        )
    )
    # Build RunConfig from CLI args
    from nazitest.config import Settings
    from nazitest.core.orchestrator import Orchestrator
    from nazitest.models.config import ProxyConfig, ProxyEntry, RunConfig, ScopeConfig

    # Auto-detect domain from target URL if no scope provided
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    allowed_domains = [d.strip() for d in scope.split(",")] if scope else [hostname]

    scope_config = ScopeConfig(
        target_url=target,
        allowed_domains=allowed_domains,
        max_crawl_depth=depth,
        max_crawl_pages=pages,
    )

    proxy_config = ProxyConfig()
    if proxy:
        proxy_config = ProxyConfig(
            proxy_list=[ProxyEntry(url=proxy)],
            enabled=True,
        )

    run_config = RunConfig(
        scope=scope_config,
        proxy=proxy_config,
        models_config_path=models,
        codebase_path=codebase,
        time_limit_minutes=time_limit,
        exploit_mode="none" if no_exploit else exploit_mode,
        output_dir=output,
    )

    settings = Settings.load(models)
    if proxy:
        settings.proxy_url = proxy

    orchestrator = Orchestrator(config=run_config, settings=settings)
    asyncio.run(orchestrator.run())


@app.command()
def resume(
    run_id: Annotated[str, typer.Argument(help="Run ID to resume.")],
) -> None:
    """Resume an interrupted scan."""
    console.print(f"[yellow]Resuming run {run_id}... (not yet implemented)[/yellow]")


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="Run ID to generate report for.")],
    format: Annotated[
        str, typer.Option("--format", "-f", help="Report format: html|pdf|json.")
    ] = "html",
) -> None:
    """Generate a report from a completed scan."""
    console.print(
        f"[yellow]Generating {format} report for {run_id}... (not yet implemented)[/yellow]"
    )


@app.command()
def graph(
    run_id: Annotated[str, typer.Argument(help="Run ID to export graph for.")],
    export: Annotated[
        Optional[Path],
        typer.Option("--export", "-e", help="Export path (e.g. graph.html)."),
    ] = None,
) -> None:
    """View or export the knowledge graph."""
    console.print(
        f"[yellow]Knowledge graph for {run_id}... (not yet implemented)[/yellow]"
    )
