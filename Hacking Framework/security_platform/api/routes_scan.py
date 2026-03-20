"""
Scan management API routes.

Endpoints:
  POST   /scan              — initiate a new scan
  GET    /scan              — list scans for the current user
  GET    /scan/{id}         — get scan status and results
  DELETE /scan/{id}         — cancel a running scan
  GET    /scan/{id}/stream  — stream live scan progress via WebSocket

Also exposes:
  GET    /modules           — list all registered security modules
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from core.engine import get_engine
from core.scheduler import Scheduler
from core.workflow_engine import WorkflowEngine
from database.database import get_db
from database.models import ScanResult, ScanStatus, Target, TargetStatus, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Scans"])

_scheduler = Scheduler()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_id: str = Field(..., description="ID of the target to scan")
    scan_type: str = Field(default="full", description="'full', 'quick', or custom")
    module_names: Optional[List[str]] = Field(
        None, description="Explicit module list; omit for all registered modules"
    )


class ScanResponse(BaseModel):
    id: str
    target_id: str
    scan_type: str
    status: ScanStatus
    celery_task_id: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    risk_score: Optional[float]
    error_message: Optional[str]
    created_at: str


class ModuleInfo(BaseModel):
    name: str
    category: str
    description: str
    version: str


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate a new security scan",
)
async def start_scan(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResponse:
    """
    Queue a security scan for the specified target.

    The scan runs asynchronously via Celery workers.
    Poll GET /scan/{id} for status updates, or stream
    progress via the WebSocket endpoint.
    """
    # Validate target ownership
    result = await db.execute(
        select(Target).where(
            Target.id == payload.target_id,
            Target.owner_id == current_user.id,
            Target.status == TargetStatus.ACTIVE,
        )
    )
    target: Optional[Target] = result.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Active target '{payload.target_id}' not found.",
        )

    # Create ScanResult record in PENDING state
    scan = ScanResult(
        target_id=target.id,
        user_id=current_user.id,
        scan_type=payload.scan_type,
        status=ScanStatus.PENDING,
        modules_used={"requested": payload.module_names or []},
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Enqueue the Celery task
    try:
        task_id = _scheduler.enqueue_scan(
            target_id=target.id,
            target_value=target.value,
            scan_result_id=scan.id,
            module_names=payload.module_names,
        )
        scan.celery_task_id = task_id
        await db.flush()
    except Exception as exc:
        logger.error("Failed to enqueue scan task: %s", exc)
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)

    logger.info(
        "Scan queued: id=%s target=%s by user=%s",
        scan.id, target.value, current_user.username,
    )
    return _scan_to_response(scan)


@router.get(
    "/scan",
    response_model=List[ScanResponse],
    summary="List scans for the current user",
)
async def list_scans(
    target_id: Optional[str] = Query(None),
    scan_status: Optional[ScanStatus] = Query(None, alias="status"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ScanResponse]:
    query = (
        select(ScanResult)
        .join(Target, ScanResult.target_id == Target.id)
        .where(Target.owner_id == current_user.id)
    )
    if target_id:
        query = query.where(ScanResult.target_id == target_id)
    if scan_status:
        query = query.where(ScanResult.status == scan_status)

    query = query.order_by(ScanResult.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()
    return [_scan_to_response(s) for s in scans]


@router.get(
    "/scan/results",
    response_model=List[ScanResponse],
    summary="Alias: list all scan results",
)
async def list_scan_results(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ScanResponse]:
    return await list_scans(db=db, current_user=current_user)


@router.get(
    "/scan/{scan_id}",
    response_model=Dict[str, Any],
    summary="Get full scan status and results",
)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    scan = await _get_owned_scan(scan_id, current_user.id, db)

    # If scan is still running, poll Celery for live status
    if scan.status == ScanStatus.RUNNING and scan.celery_task_id:
        try:
            task_status = _scheduler.get_task_status(scan.celery_task_id)
        except Exception:
            task_status = {}
    else:
        task_status = {}

    resp = _scan_to_response(scan)
    return {
        **resp.model_dump(),
        "results": scan.results,
        "task_status": task_status,
    }


@router.delete(
    "/scan/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel a running scan",
)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    scan = await _get_owned_scan(scan_id, current_user.id, db)
    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not in a cancellable state.",
        )
    if scan.celery_task_id:
        _scheduler.revoke_task(scan.celery_task_id, terminate=True)
    scan.status = ScanStatus.CANCELLED
    logger.info("Scan cancelled: %s by user %s", scan_id, current_user.username)


# ─── WebSocket live stream ────────────────────────────────────────────────────

@router.websocket("/scan/{scan_id}/stream")
async def stream_scan_progress(
    scan_id: str,
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    WebSocket endpoint that streams live workflow events back to the client.

    The client must send `{"token": "<jwt_or_api_key>"}` as the first message
    to authenticate before scan data is streamed.
    """
    await websocket.accept()
    try:
        # Receive authentication message
        auth_msg = await websocket.receive_json()
        token = auth_msg.get("token", "")
        if not token:
            await websocket.send_json({"error": "Authentication required."})
            await websocket.close(code=4001)
            return

        # Lightweight token validation without full DB user lookup
        from api.auth import decode_access_token
        try:
            _ = decode_access_token(token)
        except Exception:
            await websocket.send_json({"error": "Invalid token."})
            await websocket.close(code=4001)
            return

        # Retrieve scan from DB
        scan = await db.get(ScanResult, scan_id)
        if not scan:
            await websocket.send_json({"error": f"Scan '{scan_id}' not found."})
            await websocket.close(code=4004)
            return

        # Get target value
        target = await db.get(Target, scan.target_id)
        target_value = target.value if target else scan_id

        # Execute workflow and stream events
        engine = get_engine()
        await engine.startup()
        wf_engine = WorkflowEngine(engine)
        workflow = wf_engine.build_default_workflow()

        async for event in wf_engine.execute(workflow, target_value, scan_id=scan_id):
            await websocket.send_json(event.to_dict())

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected: scan_id=%s", scan_id)
    except Exception as exc:
        logger.error("WebSocket error for scan %s: %s", scan_id, exc)
        try:
            await websocket.send_json({"error": str(exc)})
        except Exception:
            pass


# ─── Modules endpoint ─────────────────────────────────────────────────────────

@router.get(
    "/modules",
    response_model=List[ModuleInfo],
    summary="List all registered security modules",
)
async def list_modules(
    current_user: User = Depends(get_current_user),
) -> List[ModuleInfo]:
    engine = get_engine()
    await engine.startup()
    return [ModuleInfo(**m) for m in engine.list_modules()]


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_owned_scan(
    scan_id: str, user_id: str, db: AsyncSession
) -> ScanResult:
    result = await db.execute(
        select(ScanResult)
        .join(Target, ScanResult.target_id == Target.id)
        .where(ScanResult.id == scan_id, Target.owner_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return scan


def _scan_to_response(scan: ScanResult) -> ScanResponse:
    return ScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        scan_type=scan.scan_type,
        status=scan.status,
        celery_task_id=scan.celery_task_id,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        risk_score=scan.risk_score,
        error_message=scan.error_message,
        created_at=scan.created_at.isoformat(),
    )
