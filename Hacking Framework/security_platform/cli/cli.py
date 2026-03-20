"""
Security Research Platform — Main CLI Entry Point

Usage:
  security --help
  security scan run example.com
  security scan discover example.com
  security scan analyze example.com
  security targets add example.com --name "My Domain" --type domain
  security targets list
  security report generate example.com --format html
  security report list
  security serve          — start the API server
  security worker start   — start a Celery worker

All commands require targets you are explicitly authorised to test.
"""

from __future__ import annotations

import logging

import typer
from rich.console import Console

from cli.commands.report_commands import app as report_app
from cli.commands.scan_commands import app as scan_app
from cli.commands.target_commands import app as targets_app

console = Console()

# ─── Root application ─────────────────────────────────────────────────────────

app = typer.Typer(
    name="security",
    help=(
        "[bold red]Security Research Platform[/bold red]\n\n"
        "Enterprise-grade security automation for authorised testing.\n\n"
        "[yellow]WARNING: Only use against systems you own or have explicit "
        "written authorisation to test.[/yellow]"
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# ── Sub-command groups ────────────────────────────────────────────────────────
app.add_typer(scan_app,    name="scan",    help="Run scans and discovery")
app.add_typer(targets_app, name="targets", help="Manage target assets")
app.add_typer(report_app,  name="report",  help="Generate and view reports")


# ─── Top-level convenience aliases ───────────────────────────────────────────

@app.command("discover")
def discover_alias(
    target: str = typer.Argument(..., help="Domain to enumerate"),
) -> None:
    """Shortcut for 'security scan discover <target>'."""
    from cli.commands.scan_commands import discover
    discover(target=target)


@app.command("analyze")
def analyze_alias(
    target: str = typer.Argument(..., help="Target to analyse"),
) -> None:
    """Shortcut for 'security scan analyze <target>'."""
    from cli.commands.scan_commands import analyze
    analyze(target=target)


# ─── Server management ────────────────────────────────────────────────────────

@app.command("serve")
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h"),
    port: int = typer.Option(8000, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload (dev only)"),
    log_level: str = typer.Option("info", "--log-level"),
) -> None:
    """Start the FastAPI REST API server."""
    import uvicorn
    console.print(
        f"\n[bold green]▶  Starting API server[/bold green] "
        f"on [cyan]http://{host}:{port}[/cyan]\n"
    )
    uvicorn.run(
        "api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
    )


@app.command("worker")
def start_worker(
    queues: str = typer.Option("scans,analysis,default", "--queues", "-q"),
    concurrency: int = typer.Option(4, "--concurrency", "-c"),
    loglevel: str = typer.Option("info", "--loglevel"),
) -> None:
    """Start a Celery worker process."""
    import subprocess
    import sys

    console.print(f"\n[bold green]▶  Starting Celery worker[/bold green]")
    console.print(f"   Queues:      [cyan]{queues}[/cyan]")
    console.print(f"   Concurrency: {concurrency}\n")

    cmd = [
        sys.executable, "-m", "celery",
        "-A", "workers.worker_manager",
        "worker",
        f"--loglevel={loglevel}",
        f"--concurrency={concurrency}",
        f"--queues={queues}",
    ]
    subprocess.run(cmd, check=False)


@app.command("flower")
def start_flower(
    port: int = typer.Option(5555, "--port", "-p"),
) -> None:
    """Start the Celery Flower monitoring dashboard."""
    import subprocess
    import sys

    console.print(f"\n[bold green]▶  Starting Flower[/bold green] on port {port}")
    cmd = [
        sys.executable, "-m", "celery",
        "-A", "workers.worker_manager",
        "flower",
        f"--port={port}",
    ]
    subprocess.run(cmd, check=False)


@app.command("version")
def show_version() -> None:
    """Print platform version information."""
    from config.settings import settings
    console.print(
        f"[bold]{settings.app_name}[/bold] v{settings.app_version} "
        f"(env: {settings.environment})"
    )


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    app()


if __name__ == "__main__":
    main()
