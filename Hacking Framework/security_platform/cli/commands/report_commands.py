"""
Report CLI commands.

Usage:
  security report generate <target>
  security report list
  security report show <report_id>
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="report", help="Generate and view security reports.")
console = Console()


@app.command("generate")
def generate_report(
    target: str = typer.Argument(..., help="Target domain or ID to report on"),
    format: str = typer.Option("json", "--format", "-f", help="json or html"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate a security report for a target's latest completed scan."""
    asyncio.run(_generate_report(target, format, output))


async def _generate_report(target: str, fmt: str, output_file: Optional[str]) -> None:
    from core.engine import SecurityEngine
    from database.database import get_db_session, init_database
    from database.models import ReportFormat, ScanResult, ScanStatus, Target
    from reports.report_generator import ReportGenerator
    from sqlalchemy import select

    await init_database()

    async with get_db_session() as db:
        # Resolve target
        result = await db.execute(
            select(Target).where(
                (Target.value == target) | Target.id.startswith(target)
            ).limit(1)
        )
        tgt = result.scalar_one_or_none()
        if not tgt:
            console.print(f"[red]Target not found: {target}[/red]")
            raise typer.Exit(code=1)

        # Get latest completed scan
        result = await db.execute(
            select(ScanResult)
            .where(
                ScanResult.target_id == tgt.id,
                ScanResult.status == ScanStatus.COMPLETED,
            )
            .order_by(ScanResult.completed_at.desc())
            .limit(1)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            console.print(f"[yellow]No completed scans found for target '{target}'.[/yellow]")
            console.print("[dim]Run a scan first: security scan run <target>[/dim]")
            raise typer.Exit(code=1)

        try:
            report_format = ReportFormat(fmt.lower())
        except ValueError:
            console.print(f"[red]Invalid format: {fmt}. Use 'json' or 'html'.[/red]")
            raise typer.Exit(code=1)

        console.print(f"\n[bold green]▶  Generating {fmt.upper()} report[/bold green]")
        console.print(f"   Target: [cyan]{tgt.value}[/cyan]")
        console.print(f"   Scan:   {scan.id}\n")

        gen = ReportGenerator()
        report = await gen.generate(
            scan_result=scan,
            target=tgt,
            report_format=report_format,
            title=f"Security Report — {tgt.value}",
            db=db,
        )

    out_path = output_file or f"report_{report.id[:8]}.{fmt}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report.content or "{}")

    console.print(f"[green]✓[/green] Report saved: [bold]{out_path}[/bold]")
    if report.risk_score is not None:
        level = _risk_level(report.risk_score)
        colour = {"critical": "red", "high": "red", "medium": "yellow",
                   "low": "green", "minimal": "green"}.get(level, "white")
        console.print(
            f"   Risk Score: [{colour}]{report.risk_score:.1f}/10 ({level})[/{colour}]"
        )


@app.command("list")
def list_reports() -> None:
    """List all generated reports."""
    asyncio.run(_list_reports())


async def _list_reports() -> None:
    from database.database import get_db_session, init_database
    from database.models import Report
    from sqlalchemy import select

    await init_database()
    async with get_db_session() as db:
        result = await db.execute(
            select(Report).order_by(Report.created_at.desc()).limit(100)
        )
        reports = result.scalars().all()

    table = Table(title="Generated Reports", header_style="bold cyan")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Title", width=40)
    table.add_column("Format", width=6)
    table.add_column("Risk Score", width=10)
    table.add_column("Created", width=12)

    for r in reports:
        score_str = f"{r.risk_score:.1f}" if r.risk_score is not None else "—"
        table.add_row(
            r.id[:8],
            r.title[:40],
            r.format.value,
            score_str,
            r.created_at.strftime("%Y-%m-%d"),
        )

    console.print(table)


def _risk_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "minimal"
