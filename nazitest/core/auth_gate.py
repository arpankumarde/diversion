"""Authorization gate — blocks all activity until operator confirms authorization."""

from __future__ import annotations

import time
from pathlib import Path

import orjson
from rich.console import Console
from rich.panel import Panel

from nazitest.models.config import ScopeConfig

console = Console()


class AuthorizationGate:
    """Requires explicit authorization before any network activity."""

    def __init__(self, run_path: Path) -> None:
        self.run_path = run_path

    def require_authorization(self, target: str, scope: ScopeConfig) -> bool:
        """Display authorization prompt and require confirmation.

        Returns True if authorized, False otherwise.
        """
        console.print(
            Panel(
                f"[bold]Target:[/bold] {target}\n"
                f"[bold]Scope:[/bold]  {scope.summary()}\n"
                "\n"
                "[bold]By proceeding, you confirm:[/bold]\n"
                "  [dim]1.[/dim] Written authorization from asset owner\n"
                "  [dim]2.[/dim] Testing is within agreed scope\n"
                "  [dim]3.[/dim] You accept responsibility for all actions\n"
                "\n"
                "[bold red]UNAUTHORIZED TESTING IS ILLEGAL[/bold red]",
                title="AUTHORIZATION REQUIRED",
                border_style="red",
            )
        )

        try:
            confirmation = input("Type 'AUTHORIZED' to proceed: ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[red]Authorization aborted.[/red]")
            return False

        if confirmation.strip() != "AUTHORIZED":
            console.print("[red]Authorization not confirmed. Exiting.[/red]")
            return False

        self._log_authorization(target, scope)
        console.print("[green]Authorization confirmed.[/green]")
        return True

    def _log_authorization(self, target: str, scope: ScopeConfig) -> None:
        """Record authorization with timestamp."""
        auth_record = {
            "target": target,
            "scope": scope.model_dump(mode="json"),
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "confirmed": True,
        }
        auth_path = self.run_path / "authorization.sig"
        auth_path.write_bytes(orjson.dumps(auth_record, option=orjson.OPT_INDENT_2))

    def is_authorized(self) -> bool:
        """Check if authorization has already been recorded for this run."""
        auth_path = self.run_path / "authorization.sig"
        if not auth_path.exists():
            return False
        try:
            record = orjson.loads(auth_path.read_bytes())
            return record.get("confirmed", False)
        except Exception:
            return False
