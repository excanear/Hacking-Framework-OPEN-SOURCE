"""
Scan CLI commands.

Usage:
  security scan example.com
  security discover example.com
  security analyze example.com
  security scan --modules subdomain_discovery,port_scanner example.com
"""

from __future__ import annotations

import asyncio
import json
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(name="scan", help="Run security scans and discovery.")
console = Console()


@app.command("run")
def run_scan(
    target: str = typer.Argument(..., help="Domain or IP to scan"),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m",
        help="Comma-separated module names (omit = all)"
    ),
    workflow: str = typer.Option(
        "full", "--workflow", "-w",
        help="Workflow profile: full | quick"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write JSON results to this file"
    ),
) -> None:
    """
    Run a security scan against a target.

    Example::

        security scan run example.com
        security scan run 192.168.1.0/24 --workflow quick
    """
    module_list = [m.strip() for m in modules.split(",")] if modules else None
    asyncio.run(_run_scan(target, module_list, workflow, output))


async def _run_scan(
    target: str,
    module_names: Optional[List[str]],
    workflow_type: str,
    output_file: Optional[str],
) -> None:
    from core.engine import SecurityEngine
    from core.workflow_engine import WorkflowEngine

    engine = SecurityEngine()
    await engine.startup()

    wf_engine = WorkflowEngine(engine)
    workflow = (
        wf_engine.build_quick_workflow()
        if workflow_type == "quick"
        else wf_engine.build_default_workflow()
    )

    console.print(f"\n[bold green]▶  Starting {workflow.name} scan[/bold green]")
    console.print(f"   Target:   [cyan]{target}[/cyan]")
    console.print(f"   Workflow: {workflow.name}\n")

    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        async for event in wf_engine.execute(workflow, target):
            if event.event_type == "step_start":
                task = progress.add_task(f"  {event.step_name} …", total=None)
            elif event.event_type == "step_done":
                progress.update(task, description=f"  ✓ {event.step_name}")
                progress.stop_task(task)
                results[event.step_name] = event.data
            elif event.event_type == "workflow_done":
                results = event.data.get("results", {})

    # Summary table
    table = Table(title="Scan Results Summary", header_style="bold cyan")
    table.add_column("Step", style="bold")
    table.add_column("Status")
    table.add_column("Findings")

    for step, data in results.items():
        findings = sum(
            len(v.get("data", {}).get("assets", []))
            for v in data.values()
            if isinstance(v, dict)
        )
        table.add_row(step, "[green]complete[/green]", str(findings))

    console.print(table)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[dim]Results saved to {output_file}[/dim]")

    console.print("\n[bold]Scan complete.[/bold]")


@app.command("discover")
def discover(
    target: str = typer.Argument(..., help="Domain to discover assets for"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Run discovery-only (subdomains + DNS) against a target."""
    asyncio.run(_run_module_set(
        target=target,
        modules=["subdomain_discovery", "dns_enumeration"],
        title="Asset Discovery",
        output_file=output,
    ))


@app.command("analyze")
def analyze(
    target: str = typer.Argument(..., help="Target to analyse"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Run network analysis + OSINT against a target."""
    asyncio.run(_run_module_set(
        target=target,
        modules=["port_scanner", "service_fingerprint", "dns_osint"],
        title="Network Analysis + OSINT",
        output_file=output,
    ))


@app.command("modules")
def list_modules() -> None:
    """List all registered security modules."""
    asyncio.run(_list_modules())


async def _list_modules() -> None:
    from core.engine import SecurityEngine

    engine = SecurityEngine()
    await engine.startup()
    modules = engine.list_modules()

    table = Table(title="Registered Security Modules", header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Version")
    table.add_column("Description", no_wrap=False, max_width=50)

    for m in sorted(modules, key=lambda x: (x["category"], x["name"])):
        table.add_row(m["name"], m["category"], m["version"], m["description"])

    console.print(table)


async def _run_module_set(
    target: str,
    modules: List[str],
    title: str,
    output_file: Optional[str],
) -> None:
    from core.engine import SecurityEngine

    engine = SecurityEngine()
    await engine.startup()

    console.print(f"\n[bold green]▶  {title}[/bold green]")
    console.print(f"   Target:  [cyan]{target}[/cyan]")
    console.print(f"   Modules: {', '.join(modules)}\n")

    all_results = {}
    for module_name in modules:
        console.print(f"  → Running [bold]{module_name}[/bold] …", end="")
        try:
            result = await engine.run_module(module_name, target)
            count = len(result.data.get("assets", []))
            console.print(f" [green]✓[/green] ({count} assets found)")
            all_results[module_name] = result.to_dict()
        except Exception as exc:
            console.print(f" [red]✗ {exc}[/red]")

    if output_file:
        import json
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
        console.print(f"\n[dim]Results saved to {output_file}[/dim]")

    console.print("\n[bold]Done.[/bold]\n")
