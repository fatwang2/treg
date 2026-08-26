"""Authentication HTTP routes and presentation helpers."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..application import auth as auth_use_cases
from ..application import signup
from ..application.auth import (
    CLI_TOKEN_TTL,
    EMAIL_CODE_TTL,
    MAX_OTP_ATTEMPTS,
    OTP_NS,
    OTP_START_MAX_PER_EMAIL,
    OTP_START_MAX_PER_IP,
    OTP_START_NS,
    OTP_START_WINDOW_S,
)
from ..domain.identity import session as sess
from ..models import User
from .auth_helpers import _is_https


# The app alias preserves the moved handlers' original @app.post decorator text byte-for-byte.
app = APIRouter()
email_router = app


# ---- human login via email one-time code (the third identity door) ------------------------
# OTP code + its brute-force counter, and the /auth/email/start throttle, live in the DB (treg.ratestore
# over the Ephemeral table) — NOT per-process dicts — so a restart can't reset them and they stay correct
# across instances (backlog #3). The 'otp' namespace holds {code_hash, attempts} keyed by email; the
# 'otp_start' namespace holds the per-email + per-IP sliding windows (email-bomb + brute-force guard).


class EmailStartIn(BaseModel):
    email: str


class EmailVerifyIn(BaseModel):
    email: str
    code: str


_EMAIL_HTTP_ERRORS = {
    "demo_address": (400, "that's a demo address — pick a real email"),
    "machine_identity": (403, "this address cannot be used to sign in"),
    "rate_limited": (429, "too many code requests — please wait a few minutes"),
    "invalid_code": (401, "invalid code"),
    "suspended": (403, "account suspended"),
}


def _email_http_error(exc: auth_use_cases.EmailAuthError) -> HTTPException:
    status_code, detail = _EMAIL_HTTP_ERRORS[exc.kind]
    return HTTPException(status_code=status_code, detail=detail)


@app.post("/auth/email/start")
async def auth_email_start(
    request: Request, body: EmailStartIn,
) -> dict:
    """Prove ownership of an email: mint a 6-digit code. With no mail sender yet, dev mode returns
    + logs it (so dummy emails are testable); prod will email it instead. Throttled per-email AND per-IP
    (sliding window) so this open endpoint can't be used to email-bomb an inbox or reset the OTP
    brute-force counter at will. All this state is in the DB (survives restart, correct multi-instance)."""
    try:
        return await auth_use_cases.start_email_login(body.email, _client_ip(request))
    except auth_use_cases.EmailAuthError as exc:
        raise _email_http_error(exc) from exc


@app.post("/auth/email/verify")
async def auth_email_verify(
    request: Request, body: EmailVerifyIn,
) -> JSONResponse:
    """Check the code → find-or-create the user → mint an identity token AND set a browser session
    cookie. The CLI reads the token from the body; the dashboard just reloads into session mode
    (same path as GitHub login) — one endpoint serves both clients."""
    try:
        verified = await auth_use_cases.verify_email_login(body.email, body.code)
    except auth_use_cases.EmailAuthError as exc:
        raise _email_http_error(exc) from exc
    resp = JSONResponse({"token": verified.token, "email": verified.email})
    resp.set_cookie(sess.COOKIE, verified.session_cookie, httponly=True,
                    samesite="lax", secure=_is_https(request), max_age=sess.TTL_SECONDS)
    return resp


async def _find_or_create_user(db: AsyncSession, email: str) -> User:
    """Find a user by email, else register them — the user ONLY, **no auto personal org**. The shared
    core of every identity door (GitHub / Google / email OTP). A brand-new user therefore lands with
    zero teams and is asked to NAME + CREATE their first team (the dashboard's mandatory welcome, or
    `treg org create`) — we never spawn a throwaway personal org they didn't ask for. Their identity
    token is user-scoped, so it works before they have any org (org chosen per-request via X-Treg-Org).
    Caller commits."""
    try:
        return await signup.find_or_create_user(db, email)
    except signup.MachineIdentityError as exc:
        raise HTTPException(status_code=403, detail="this address cannot be used to sign in") from exc


def _client_ip(request: Request) -> str:
    """Best-effort client IP — first hop of X-Forwarded-For behind the reverse proxy (Render), else the socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"
