"""
Target management CLI commands.

Usage:
  security targets add example.com --type domain --name "My Domain"
  security targets list
  security targets show <target_id>
  security targets delete <target_id>
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="targets", help="Manage target assets.")
console = Console()


@app.command("add")
def add_target(
    value: str = typer.Argument(..., help="Domain, IP, CIDR or URL to track"),
    name: str = typer.Option(..., "--name", "-n", help="Human-readable label"),
    target_type: str = typer.Option("domain", "--type", "-t",
                                     help="Target type: domain|ip|network|cloud|url"),
    description: Optional[str] = typer.Option(None, "--desc", "-d"),
) -> None:
    """Register a new target for security research."""
    asyncio.run(_add_target(value, name, target_type, description))


async def _add_target(value: str, name: str, target_type: str, description: Optional[str]) -> None:
    from database.database import get_db_session, init_database
    from database.models import Target, TargetType, User
    from sqlalchemy import select

    await init_database()
    async with get_db_session() as db:
        # Use first user as owner for CLI operations
        result = await db.execute(select(User).limit(1))
        user = result.scalar_one_or_none()
        if not user:
            console.print("[red]No users found. Create a user first via the API.[/red]")
            raise typer.Exit(code=1)

        try:
            t_type = TargetType(target_type)
        except ValueError:
            console.print(f"[red]Invalid target type: {target_type}[/red]")
            raise typer.Exit(code=1)

        target = Target(
            name=name,
            value=value,
            target_type=t_type,
            description=description,
            owner_id=user.id,
        )
        db.add(target)
        await db.flush()

    console.print(f"[green]✓[/green] Target added: [bold]{value}[/bold] (ID: {target.id})")


@app.command("list")
def list_targets(
    target_type: Optional[str] = typer.Option(None, "--type", "-t"),
) -> None:
    """List all registered targets."""
    asyncio.run(_list_targets(target_type))


async def _list_targets(target_type: Optional[str]) -> None:
    from database.database import get_db_session, init_database
    from database.models import Target, TargetStatus, TargetType
    from sqlalchemy import select

    await init_database()
    async with get_db_session() as db:
        query = select(Target).where(Target.status != TargetStatus.ARCHIVED)
        if target_type:
            try:
                query = query.where(Target.target_type == TargetType(target_type))
            except ValueError:
                pass
        result = await db.execute(query.order_by(Target.created_at.desc()))
        targets = result.scalars().all()

    table = Table(title="Registered Targets", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Name", width=25)
    table.add_column("Value", width=35)
    table.add_column("Type", width=10)
    table.add_column("Status", width=10)
    table.add_column("Created", width=12)

    for t in targets:
        table.add_row(
            t.id[:8],
            t.name,
            t.value,
            t.target_type.value,
            t.status.value,
            t.created_at.strftime("%Y-%m-%d"),
        )

    console.print(table)


@app.command("show")
def show_target(
    target_id: str = typer.Argument(..., help="Target ID (partial IDs are accepted)"),
) -> None:
    """Show details for a single target."""
    asyncio.run(_show_target(target_id))


async def _show_target(target_id: str) -> None:
    from database.database import get_db_session, init_database
    from database.models import Target
    from sqlalchemy import select

    await init_database()
    async with get_db_session() as db:
        result = await db.execute(
            select(Target).where(Target.id.startswith(target_id))
        )
        target = result.scalar_one_or_none()

    if not target:
        console.print(f"[red]Target not found: {target_id}[/red]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Target Details[/bold cyan]")
    console.print(f"  ID:          {target.id}")
    console.print(f"  Name:        {target.name}")
    console.print(f"  Value:       {target.value}")
    console.print(f"  Type:        {target.target_type.value}")
    console.print(f"  Status:      {target.status.value}")
    console.print(f"  Description: {target.description or '—'}")
    console.print(f"  Tags:        {target.tags or {}}")
    console.print(f"  Created:     {target.created_at.isoformat()}")
    console.print()


@app.command("delete")
def delete_target(
    target_id: str = typer.Argument(..., help="Target ID to archive"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Archive (soft-delete) a target."""
    if not force:
        typer.confirm(f"Archive target {target_id}?", abort=True)
    asyncio.run(_delete_target(target_id))


async def _delete_target(target_id: str) -> None:
    from database.database import get_db_session, init_database
    from database.models import Target, TargetStatus
    from sqlalchemy import select

    await init_database()
    async with get_db_session() as db:
        result = await db.execute(
            select(Target).where(Target.id.startswith(target_id))
        )
        target = result.scalar_one_or_none()
        if not target:
            console.print(f"[red]Target not found: {target_id}[/red]")
            raise typer.Exit(code=1)
        target.status = TargetStatus.ARCHIVED

    console.print(f"[yellow]⚠[/yellow] Target archived: {target_id}")
