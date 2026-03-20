"""
Target management API routes.

Endpoints:
  POST   /targets          — create a new target
  GET    /targets          — list all targets owned by the current user
  GET    /targets/{id}     — get a single target
  PATCH  /targets/{id}     — update target metadata
  DELETE /targets/{id}     — soft-delete (archive) a target
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from database.database import get_db
from database.models import Target, TargetStatus, TargetType, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/targets", tags=["Targets"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    name: str = Field(..., max_length=255, description="Human-readable label")
    value: str = Field(..., max_length=512, description="Domain, IP, CIDR, or URL")
    target_type: TargetType
    description: Optional[str] = None
    tags: Optional[dict] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    status: Optional[TargetStatus] = None
    tags: Optional[dict] = None


class TargetResponse(BaseModel):
    id: str
    name: str
    value: str
    target_type: TargetType
    status: TargetStatus
    description: Optional[str]
    tags: Optional[dict]
    owner_id: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new target",
)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Target:
    """Register a new target asset for security research."""
    # Check for duplicate within this user's scope
    existing = await db.execute(
        select(Target).where(
            Target.value == payload.value,
            Target.owner_id == current_user.id,
            Target.status != TargetStatus.ARCHIVED,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target '{payload.value}' already exists.",
        )

    target = Target(
        name=payload.name,
        value=payload.value,
        target_type=payload.target_type,
        description=payload.description,
        tags=payload.tags,
        owner_id=current_user.id,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    logger.info("Target created: %s (%s) by user %s", target.value, target.id, current_user.username)
    return _to_response(target)


@router.get(
    "",
    response_model=List[TargetResponse],
    summary="List all targets",
)
async def list_targets(
    target_type: Optional[TargetType] = Query(None),
    status_filter: Optional[TargetStatus] = Query(None, alias="status"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[TargetResponse]:
    """Return the authenticated user's targets with optional filtering."""
    query = select(Target).where(Target.owner_id == current_user.id)
    if target_type:
        query = query.where(Target.target_type == target_type)
    if status_filter:
        query = query.where(Target.status == status_filter)
    else:
        query = query.where(Target.status != TargetStatus.ARCHIVED)

    query = query.order_by(Target.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    targets = result.scalars().all()
    return [_to_response(t) for t in targets]


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Get a single target",
)
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TargetResponse:
    target = await _get_owned_target(target_id, current_user.id, db)
    return _to_response(target)


@router.patch(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Update target metadata",
)
async def update_target(
    target_id: str,
    payload: TargetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TargetResponse:
    target = await _get_owned_target(target_id, current_user.id, db)
    if payload.name is not None:
        target.name = payload.name
    if payload.description is not None:
        target.description = payload.description
    if payload.status is not None:
        target.status = payload.status
    if payload.tags is not None:
        target.tags = payload.tags
    await db.flush()
    await db.refresh(target)
    return _to_response(target)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archive (soft-delete) a target",
)
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    target = await _get_owned_target(target_id, current_user.id, db)
    target.status = TargetStatus.ARCHIVED
    logger.info("Target archived: %s by user %s", target_id, current_user.username)


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_owned_target(
    target_id: str, owner_id: str, db: AsyncSession
) -> Target:
    result = await db.execute(
        select(Target).where(
            Target.id == target_id,
            Target.owner_id == owner_id,
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target_id}' not found.",
        )
    return target


def _to_response(target: Target) -> TargetResponse:
    return TargetResponse(
        id=target.id,
        name=target.name,
        value=target.value,
        target_type=target.target_type,
        status=target.status,
        description=target.description,
        tags=target.tags,
        owner_id=target.owner_id,
        created_at=target.created_at.isoformat(),
        updated_at=target.updated_at.isoformat(),
    )
