
"""
Audit log query API — paginated, filterable read access to auth events.

Only superusers can access this endpoint. Results are sorted newest-first.
Tenant admins see only their own tenant's events (tenant_id filter is enforced
on the server side — callers cannot widen the scope).
"""

import uuid
from datetime import datetime
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.identity.password import fastapi_users
from app.models.audit import AuditLog
from app.models.user import User

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/admin/audit", tags=["Admin"])

current_superuser = fastapi_users.current_user(active=True, superuser=True)

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500


class AuditEntry(BaseModel):
    id: str
    event: str
    tenant_id: str | None
    actor_id: str | None
    subject_id: str | None
    ip_address: str | None
    user_agent: str | None
    created_at: datetime


class AuditPage(BaseModel):
    items: list[AuditEntry]
    total: int
    page: int
    limit: int
    has_more: bool


@router.get("", response_model=AuditPage)
async def query_audit_log(
    tenant_id: str | None = Query(None, description="Filter by tenant UUID"),
    event: str | None = Query(None, description="Filter by event type (exact match or prefix with *)"),
    subject_id: str | None = Query(None, description="Filter by subject user UUID"),
    actor_id: str | None = Query(None, description="Filter by actor user UUID"),
    since: datetime | None = Query(None, description="Return events after this timestamp (ISO 8601)"),
    until: datetime | None = Query(None, description="Return events before this timestamp (ISO 8601)"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT, description="Items per page"),
    user: User = Depends(current_superuser),
    db: AsyncSession = Depends(get_session),
):
    """
    Query the audit log with pagination and optional filters.
    Requires superuser — results scoped to user's tenant if non-null.
    """
    filters = []

    # Superusers without a tenant can query globally; otherwise scope to their tenant
    if user.tenant_id:
        effective_tenant = user.tenant_id
        if tenant_id:
            try:
                requested = uuid.UUID(tenant_id)
            except ValueError:
                raise HTTPException(400, "Invalid tenant_id UUID")
            if requested != effective_tenant:
                raise HTTPException(403, "Cannot query another tenant's audit log")
        filters.append(AuditLog.tenant_id == effective_tenant)
    elif tenant_id:
        try:
            filters.append(AuditLog.tenant_id == uuid.UUID(tenant_id))
        except ValueError:
            raise HTTPException(400, "Invalid tenant_id UUID")

    if event:
        if event.endswith("*"):
            filters.append(AuditLog.event.startswith(event[:-1]))
        else:
            filters.append(AuditLog.event == event)

    if subject_id:
        try:
            filters.append(AuditLog.subject_id == uuid.UUID(subject_id))
        except ValueError:
            raise HTTPException(400, "Invalid subject_id UUID")

    if actor_id:
        try:
            filters.append(AuditLog.actor_id == uuid.UUID(actor_id))
        except ValueError:
            raise HTTPException(400, "Invalid actor_id UUID")

    if since:
        filters.append(AuditLog.created_at >= since)
    if until:
        filters.append(AuditLog.created_at <= until)

    where_clause = and_(*filters) if filters else True

    # Count total for pagination metadata
    count_result = await db.execute(
        select(AuditLog.id).where(where_clause)
    )
    total = len(count_result.all())

    # Fetch the requested page (newest first)
    offset = (page - 1) * limit
    rows_result = await db.execute(
        select(AuditLog)
        .where(where_clause)
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = rows_result.scalars().all()

    return AuditPage(
        items=[
            AuditEntry(
                id=str(row.id),
                event=row.event,
                tenant_id=str(row.tenant_id) if row.tenant_id else None,
                actor_id=str(row.actor_id) if row.actor_id else None,
                subject_id=str(row.subject_id) if row.subject_id else None,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                created_at=row.created_at,
            )
            for row in rows
        ],
        total=total,
        page=page,
        limit=limit,
        has_more=(offset + limit) < total,
    )
