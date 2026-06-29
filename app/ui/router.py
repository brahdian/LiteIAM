from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(prefix="/ui", tags=["ui"])


def _ctx(request: Request, **extra) -> dict:
    return {"request": request, "year": datetime.utcnow().year, **extra}


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    tenant_id: str = Query(default=""),
    next: str = Query(default=""),
    registered: str = Query(default=""),
):
    return templates.TemplateResponse(
        "auth/login.html",
        _ctx(request, tenant_id=tenant_id, next=next),
    )


@router.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    tenant_id: str = Query(default=""),
):
    return templates.TemplateResponse(
        "auth/register.html",
        _ctx(request, tenant_id=tenant_id),
    )


@router.get("/totp/verify", response_class=HTMLResponse)
async def totp_verify_page(
    request: Request,
    user_id: str = Query(default=""),
    token: str = Query(default=""),
    tenant_id: str = Query(default=""),
    next: str = Query(default=""),
):
    if not user_id:
        return RedirectResponse("/ui/login", status_code=302)
    return templates.TemplateResponse(
        "auth/totp_verify.html",
        _ctx(request, user_id=user_id, token=token, tenant_id=tenant_id, next=next),
    )


@router.get("/totp/enroll", response_class=HTMLResponse)
async def totp_enroll_page(
    request: Request,
    user_id: str = Query(default=""),
    token: str = Query(default=""),
    next: str = Query(default=""),
):
    if not user_id:
        return RedirectResponse("/ui/login", status_code=302)
    return templates.TemplateResponse(
        "auth/totp_enroll.html",
        _ctx(request, user_id=user_id, token=token, next=next),
    )


@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    return templates.TemplateResponse("auth/account.html", _ctx(request))


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email_page(
    request: Request,
    token: str = Query(default=""),
):
    return templates.TemplateResponse("auth/verify_email.html", _ctx(request, token=token))


@router.get("/accept-invite", response_class=HTMLResponse)
async def accept_invite_page(
    request: Request,
    token: str = Query(default=""),
):
    return templates.TemplateResponse("auth/accept_invite.html", _ctx(request, token=token))


@router.get("/magic-link", response_class=HTMLResponse)
async def magic_link_page(
    request: Request,
    token: str = Query(default=""),
):
    return templates.TemplateResponse("auth/magic_link.html", _ctx(request, token=token))


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("auth/forgot_password.html", _ctx(request))


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    token: str = Query(default=""),
):
    return templates.TemplateResponse(
        "auth/reset_password.html",
        _ctx(request, token=token),
    )


@router.get("/error", response_class=HTMLResponse)
async def error_page(
    request: Request,
    status_code: int = Query(default=500),
    title: str = Query(default="Something went wrong"),
    detail: str = Query(default=""),
    back_url: str = Query(default=""),
    back_label: str = Query(default="Go back"),
):
    return templates.TemplateResponse(
        "auth/error.html",
        _ctx(
            request,
            status_code=status_code,
            title=title,
            detail=detail,
            back_url=back_url,
            back_label=back_label,
        ),
        status_code=status_code,
    )


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request):
    return templates.TemplateResponse("auth/admin_users.html", _ctx(request))


@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_log_page(request: Request):
    return templates.TemplateResponse("auth/audit_log.html", _ctx(request))


@router.get("/oauth/consent", response_class=HTMLResponse)
async def consent_page(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="openid"),
    state: str = Query(default=""),
    code_challenge: str = Query(default=""),
    code_challenge_method: str = Query(default="S256"),
    nonce: str = Query(default=""),
):
    return templates.TemplateResponse(
        "auth/consent.html",
        _ctx(
            request,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            scope_list=scope.split(),
        ),
    )


@router.get("/", response_class=HTMLResponse)
async def ui_root(request: Request):
    return RedirectResponse("/ui/login", status_code=302)
