"""
Dashboard API — lightweight read-only endpoints that power the web dashboard.

Mount this router on the main FastAPI app with prefix="/dashboard".
All endpoints require a valid user session (JWT or API key).
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from database.database import get_db
from database.models import (
    ScanResult,
    ScanStatus,
    SeverityLevel,
    Target,
    Vulnerability,
    User,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Return platform-wide summary counts:
    - total targets
    - total scans (all statuses)
    - completed scans
    - total vulnerabilities
    - critical / high vulnerability counts
    - average risk score across completed scans
    """
    # Targets
    total_targets: int = (
        await db.execute(select(func.count()).select_from(Target))
    ).scalar_one()

    # Scans
    total_scans: int = (
        await db.execute(select(func.count()).select_from(ScanResult))
    ).scalar_one()
    completed_scans: int = (
        await db.execute(
            select(func.count())
            .select_from(ScanResult)
            .where(ScanResult.status == ScanStatus.COMPLETED)
        )
    ).scalar_one()

    # Vulnerabilities
    total_vulns: int = (
        await db.execute(select(func.count()).select_from(Vulnerability))
    ).scalar_one()
    critical_vulns: int = (
        await db.execute(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.severity == SeverityLevel.CRITICAL)
        )
    ).scalar_one()
    high_vulns: int = (
        await db.execute(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.severity == SeverityLevel.HIGH)
        )
    ).scalar_one()

    # Average risk score
    avg_risk = (
        await db.execute(
            select(func.avg(ScanResult.risk_score))
            .where(ScanResult.status == ScanStatus.COMPLETED)
            .where(ScanResult.risk_score.isnot(None))
        )
    ).scalar_one()

    return {
        "total_targets": total_targets,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": critical_vulns,
        "high_vulnerabilities": high_vulns,
        "average_risk_score": round(float(avg_risk), 2) if avg_risk else None,
    }


@router.get("/recent-scans", response_model=List[Dict[str, Any]])
async def get_recent_scans(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Return the *limit* most recent scan results across all targets."""
    limit = min(max(limit, 1), 100)  # clamp to [1, 100]

    rows = (
        await db.execute(
            select(ScanResult)
            .order_by(ScanResult.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()

    return [
        {
            "id": str(r.id),
            "target_id": str(r.target_id),
            "status": r.status.value,
            "risk_score": float(r.risk_score) if r.risk_score else None,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/risk-distribution", response_model=Dict[str, int])
async def get_risk_distribution(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Dict[str, int]:
    """Return vulnerability count grouped by severity level."""
    rows = (
        await db.execute(
            select(Vulnerability.severity, func.count().label("cnt"))
            .group_by(Vulnerability.severity)
        )
    ).all()

    distribution = {level.value: 0 for level in SeverityLevel}
    for severity, count in rows:
        key = severity.value if hasattr(severity, "value") else str(severity)
        distribution[key] = count

    return distribution


@router.get("/targets-overview", response_model=List[Dict[str, Any]])
async def get_targets_overview(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Return all targets with their latest scan risk score."""
    targets = (await db.execute(select(Target).order_by(Target.created_at.desc()))).scalars().all()

    result: List[Dict[str, Any]] = []
    for t in targets:
        latest_scan = (
            await db.execute(
                select(ScanResult)
                .where(ScanResult.target_id == t.id)
                .where(ScanResult.status == ScanStatus.COMPLETED)
                .order_by(ScanResult.completed_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        result.append(
            {
                "id": str(t.id),
                "value": t.value,
                "type": t.target_type.value if hasattr(t.target_type, "value") else t.target_type,
                "status": t.status.value if hasattr(t.status, "value") else t.status,
                "latest_risk_score": float(latest_scan.risk_score)
                if latest_scan and latest_scan.risk_score
                else None,
                "last_scanned": latest_scan.completed_at.isoformat()
                if latest_scan and latest_scan.completed_at
                else None,
                "created_at": t.created_at.isoformat(),
            }
        )

    return result
