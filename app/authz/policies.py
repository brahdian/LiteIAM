
"""
Admin API helpers for runtime role/permission management.

All mutations go through SafeCasbinEnforcer (which holds the asyncio.Lock),
then broadcast PG NOTIFY so every other worker reloads the updated policy.
"""


import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.authz.enforcer import casbin_enforcer
from app.authz.watcher import notify_policy_updated
from app.core.config import settings
from app.identity.password import fastapi_users

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin/policies", tags=["Admin"])

current_superuser = fastapi_users.current_user(active=True, superuser=True)


class PolicyIn(BaseModel):
    subject: str       # user ID or role name
    domain: str        # tenant ID (hex)
    object: str        # resource, e.g. "crm:leads"
    action: str        # "read", "write", "delete", "*"


class RoleAssignIn(BaseModel):
    user_id: str
    role: str
    domain: str        # tenant ID (hex)


@router.post("/", status_code=201)
async def add_policy(body: PolicyIn, _: object = Depends(current_superuser)):
    ok = await casbin_enforcer.safe_add_policy(
        body.subject, body.domain, body.object, body.action
    )
    if not ok:
        raise HTTPException(409, "Policy already exists")
    await notify_policy_updated(settings.DATABASE_URL)
    return {"status": "created"}


@router.delete("/")
async def remove_policy(body: PolicyIn, _: object = Depends(current_superuser)):
    ok = await casbin_enforcer.safe_remove_policy(
        body.subject, body.domain, body.object, body.action
    )
    if not ok:
        raise HTTPException(404, "Policy not found")
    await notify_policy_updated(settings.DATABASE_URL)
    return {"status": "removed"}


@router.post("/roles")
async def assign_role(body: RoleAssignIn, _: object = Depends(current_superuser)):
    ok = await casbin_enforcer.safe_add_role_for_user(body.user_id, body.role, body.domain)
    if not ok:
        raise HTTPException(409, "Role already assigned")
    await notify_policy_updated(settings.DATABASE_URL)
    return {"status": "assigned"}
