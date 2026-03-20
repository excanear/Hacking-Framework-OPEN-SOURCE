"""
Reports API routes.

Endpoints:
  POST  /reports            — generate a report for a scan
  GET   /reports            — list all reports for the current user
  GET   /reports/{id}       — retrieve a specific report
  GET   /reports/{id}/download — download the report file (JSON or HTML)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from database.database import get_db
from database.models import Report, ReportFormat, ScanResult, Target, TargetStatus, User
from reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])

_report_gen = ReportGenerator()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    scan_result_id: str = Field(..., description="Scan to generate the report for")
    format: ReportFormat = Field(default=ReportFormat.JSON)
    title: Optional[str] = None


class ReportResponse(BaseModel):
    id: str
    target_id: str
    scan_result_id: Optional[str]
    title: str
    format: ReportFormat
    risk_score: Optional[float]
    summary: Optional[Dict[str, Any]]
    created_at: str


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a security report",
)
async def generate_report(
    payload: ReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportResponse:
    """Generate a structured security report from a completed scan."""
    # Validate scan ownership
    stmt = (
        select(ScanResult)
        .join(Target, ScanResult.target_id == Target.id)
        .where(
            ScanResult.id == payload.scan_result_id,
            Target.owner_id == current_user.id,
        )
    )
    result = await db.execute(stmt)
    scan: Optional[ScanResult] = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{payload.scan_result_id}' not found.",
        )

    target = await db.get(Target, scan.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    title = payload.title or f"Security Report — {target.value}"

    # Generate report content
    try:
        report_record = await _report_gen.generate(
            scan_result=scan,
            target=target,
            report_format=payload.format,
            title=title,
            db=db,
        )
    except Exception as exc:
        logger.exception("Report generation failed.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        )

    await db.flush()
    await db.refresh(report_record)
    return _to_response(report_record)


@router.get(
    "",
    response_model=List[ReportResponse],
    summary="List all reports",
)
async def list_reports(
    target_id: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ReportResponse]:
    query = (
        select(Report)
        .join(Target, Report.target_id == Target.id)
        .where(Target.owner_id == current_user.id)
    )
    if target_id:
        query = query.where(Report.target_id == target_id)
    query = query.order_by(Report.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()
    return [_to_response(r) for r in reports]


@router.get(
    "/{report_id}",
    response_model=Dict[str, Any],
    summary="Get a single report with full content",
)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    report = await _get_owned_report(report_id, current_user.id, db)
    resp = _to_response(report)
    return {**resp.model_dump(), "content": report.content}


@router.get(
    "/{report_id}/download",
    summary="Download report file",
)
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Return the raw report content as a downloadable file."""
    report = await _get_owned_report(report_id, current_user.id, db)
    if not report.content:
        raise HTTPException(status_code=404, detail="Report content not available.")

    if report.format == ReportFormat.HTML:
        media_type = "text/html"
        filename = f"report_{report_id}.html"
    else:
        media_type = "application/json"
        filename = f"report_{report_id}.json"

    return Response(
        content=report.content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_owned_report(
    report_id: str, user_id: str, db: AsyncSession
) -> Report:
    result = await db.execute(
        select(Report)
        .join(Target, Report.target_id == Target.id)
        .where(Report.id == report_id, Target.owner_id == user_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    return report


def _to_response(report: Report) -> ReportResponse:
    return ReportResponse(
        id=report.id,
        target_id=report.target_id,
        scan_result_id=report.scan_result_id,
        title=report.title,
        format=report.format,
        risk_score=report.risk_score,
        summary=report.summary,
        created_at=report.created_at.isoformat(),
    )
