"""Authentication HTTP routes and presentation helpers."""

from __future__ import annotations

import hmac
import secrets as _secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import crypto, demo as demo_seed, email as email_sender, ratestore
from ..config import get_settings
from ..db import get_session
from ..domain.identity import session as sess
from ..domain.identity.access import _is_machine_email, _norm_email
from ..models import User
from .auth_helpers import _is_https


# The app alias preserves the moved handlers' original @app.post decorator text byte-for-byte.
app = APIRouter()
email_router = app


CLI_TOKEN_TTL = 30 * 24 * 3600      # identity token lifetime for the CLI


# ---- human login via email one-time code (the third identity door) ------------------------
# OTP code + its brute-force counter, and the /auth/email/start throttle, live in the DB (treg.ratestore
# over the Ephemeral table) — NOT per-process dicts — so a restart can't reset them and they stay correct
# across instances (backlog #3). The 'otp' namespace holds {code_hash, attempts} keyed by email; the
# 'otp_start' namespace holds the per-email + per-IP sliding windows (email-bomb + brute-force guard).
EMAIL_CODE_TTL = 10 * 60  # seconds a code stays valid
MAX_OTP_ATTEMPTS = 5  # invalidate a code after this many wrong guesses (brute-force guard)
OTP_NS = "otp"
OTP_START_NS = "otp_start"
OTP_START_WINDOW_S = 900      # 15 minutes
OTP_START_MAX_PER_EMAIL = 5   # code requests for one inbox per window (caps bombing a single victim)
OTP_START_MAX_PER_IP = 30     # code requests from one IP per window (looser — offices/NAT share an IP)


class EmailStartIn(BaseModel):
    email: str


class EmailVerifyIn(BaseModel):
    email: str
    code: str


@app.post("/auth/email/start")
async def auth_email_start(
    request: Request, body: EmailStartIn, db: AsyncSession = Depends(get_session)
) -> dict:
    """Prove ownership of an email: mint a 6-digit code. With no mail sender yet, dev mode returns
    + logs it (so dummy emails are testable); prod will email it instead. Throttled per-email AND per-IP
    (sliding window) so this open endpoint can't be used to email-bomb an inbox or reset the OTP
    brute-force counter at will. All this state is in the DB (survives restart, correct multi-instance)."""
    email = _norm_email(body.email)
    if email.endswith("@" + demo_seed.DEMO_DOMAIN):  # fake onboarding teammates are roster-only — never a login
        raise HTTPException(status_code=400, detail="that's a demo address — pick a real email")
    if _is_machine_email(email):  # agents / the public token act by token only — same rule, said early
        raise HTTPException(status_code=403, detail="this address cannot be used to sign in")
    await ratestore.sweep(db, OTP_START_NS)  # bound the namespace before we add to it
    if not await ratestore.rate_check(
        db, OTP_START_NS,
        [(f"e:{email}", OTP_START_MAX_PER_EMAIL), (f"i:{_client_ip(request)}", OTP_START_MAX_PER_IP)],
        OTP_START_WINDOW_S,
    ):
        await db.commit()  # persist the pruning/sweep even on reject
        raise HTTPException(status_code=429, detail="too many code requests — please wait a few minutes")
    code = f"{_secrets.randbelow(1_000_000):06d}"
    await ratestore.kv_put(db, OTP_NS, email,
                           {"hash": crypto.hash_token(code), "attempts": MAX_OTP_ATTEMPTS}, EMAIL_CODE_TTL)
    await db.commit()
    resp = {"sent": True, "email": email}
    if get_settings().expose_dev_code:  # local sqlite only — never leaks the code on a real (Postgres) deploy
        print(f"[email-otp] {email} -> {code}")  # surfaces in the server log
        resp["dev_code"] = code
    else:
        await email_sender.send_otp(email, code, ttl_minutes=EMAIL_CODE_TTL // 60)  # best-effort; never raises
    return resp


@app.post("/auth/email/verify")
async def auth_email_verify(
    request: Request, body: EmailVerifyIn, db: AsyncSession = Depends(get_session)
) -> JSONResponse:
    """Check the code → find-or-create the user → mint an identity token AND set a browser session
    cookie. The CLI reads the token from the body; the dashboard just reloads into session mode
    (same path as GitHub login) — one endpoint serves both clients."""
    email = _norm_email(body.email)
    entry = await ratestore.kv_get(db, OTP_NS, email)  # None if missing OR expired (kv_get drops expired)
    if entry is None:
        await db.commit()  # persist the lazy delete of an expired code, if any
        raise HTTPException(status_code=401, detail="invalid code")
    if not hmac.compare_digest(entry["hash"], crypto.hash_token(body.code.strip())):
        entry["attempts"] -= 1  # a wrong guess burns an attempt; the code dies after MAX_OTP_ATTEMPTS
        if entry["attempts"] <= 0:
            await ratestore.kv_pop(db, OTP_NS, email)
        else:
            await ratestore.kv_put(db, OTP_NS, email, entry, ttl_s=None)  # keep the code's original expiry
        await db.commit()
        raise HTTPException(status_code=401, detail="invalid code")
    await ratestore.kv_pop(db, OTP_NS, email)  # one-time
    user = await _find_or_create_user(db, email)
    if user.suspended:  # a banned account may prove its email but must not receive a live token
        raise HTTPException(status_code=403, detail="account suspended")
    await db.commit()
    resp = JSONResponse({"token": sess.make(user.id, CLI_TOKEN_TTL, user.token_version), "email": user.email})
    resp.set_cookie(sess.COOKIE, sess.make(user.id, token_version=user.token_version), httponly=True,
                    samesite="lax", secure=_is_https(request), max_age=sess.TTL_SECONDS)
    return resp


async def _find_or_create_user(db: AsyncSession, email: str) -> User:
    """Find a user by email, else register them — the user ONLY, **no auto personal org**. The shared
    core of every identity door (GitHub / Google / email OTP). A brand-new user therefore lands with
    zero teams and is asked to NAME + CREATE their first team (the dashboard's mandatory welcome, or
    `treg org create`) — we never spawn a throwaway personal org they didn't ask for. Their identity
    token is user-scoped, so it works before they have any org (org chosen per-request via X-Treg-Org).
    Caller commits."""
    email = _norm_email(email)
    # Machine identities (agents, the published demo token) are minted by an admin and act ONLY by
    # their token. This is the single choke point every identity door shares, so blocking here means
    # no door — GitHub, Google, email OTP, invite sign-in — can hand a human an agent's identity.
    # (The domains are unroutable, so a code could never be delivered anyway; this makes it explicit.)
    if _is_machine_email(email):
        raise HTTPException(status_code=403, detail="this address cannot be used to sign in")
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        user = User(email=email)
        db.add(user)
        try:
            await db.flush()  # surfaces the unique-email violation on a concurrent first-login race
        except IntegrityError:
            await db.rollback()  # another worker just created this same new user — reuse theirs
            return (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    return user


def _client_ip(request: Request) -> str:
    """Best-effort client IP — first hop of X-Forwarded-For behind the reverse proxy (Render), else the socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"
