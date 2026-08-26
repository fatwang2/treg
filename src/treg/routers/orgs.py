"""Team signup and governance HTTP routes."""

import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import crypto, demo as demo_seed, email as email_sender, health
from ..application import signup as signup_use_cases
from ..db import get_session
from ..domain.governance import teams
from ..domain.identity.access import Caller, _norm_email, _role_at_least, require_identity, require_member
from ..models import Bundle, Invite, Membership, Org, Project, Tool, User
from ..timeutil import as_naive as _as_naive
from ..timeutil import utcnow_naive as _utcnow_naive
from .auth_helpers import _is_https
from .signup_cookies import REFERRAL_COOKIE


INVITE_TTL_DAYS = 7  # invite codes are one-time AND expire after this many days


class UserIn(BaseModel):
    email: str
    webhook_url: str | None = None


class OrgIn(BaseModel):
    name: str


class InviteIn(BaseModel):
    email: str
    role: str = "member"
    expires_days: int = INVITE_TTL_DAYS
    # Access to seed onto the membership on accept: tool_access None = all tools, a list = the allowed
    # tool names; local_run may be turned off. Both default to the unrestricted state.
    tool_access: list[str] | None = None
    project_access: list[str | int] | None = None  # None = the whole org; slugs/ids = the scoped set
    local_run_enabled: bool = True
    landing: str | None = None  # a shared detail page ("/app/skills/<name>") to land on after sign-in


# Landing must be one of OUR detail paths — a path-only allowlist so an emailed invite link can never
# become an open redirect (no scheme, no host, no traversal, single trailing name segment).
_LANDING_RE = re.compile(r"^/app/(skills|tools)/[A-Za-z0-9][A-Za-z0-9._%-]*$")


class AcceptIn(BaseModel):
    code: str
    email: str


def _require_admin_of(org_id: int, caller: Caller) -> None:
    """The caller must be acting with THIS org's token (token = a membership) and be admin+."""
    if caller.org_id != org_id or not _role_at_least(caller.role, "admin"):
        raise HTTPException(status_code=403, detail="admin role in this org is required")


async def _known_tool_names(org_id: int, db: AsyncSession) -> set[str]:
    rows = (await db.execute(select(Tool.name).where(Tool.org_id == org_id))).all()
    return {r[0] for r in rows}


async def _known_access_names(org_id: int, db: AsyncSession) -> set[str]:
    """Everything an access list may name: tool names (the call/run gate) plus bundle names (the
    skill-visibility gate) — so a recipe-only skill can be granted even though it has no tool."""
    bundles = (await db.execute(select(Bundle.name).where(Bundle.org_id == org_id))).all()
    return await _known_tool_names(org_id, db) | {r[0] for r in bundles}


def _normalize_tool_access(names: list[str] | None, known: set[str]) -> list[str] | None:
    """Validate a requested access list against the org's tools + skills. None → None (all). A list
    must name only real tools/skills (else 422). A list covering EVERYTHING collapses to None."""
    if names is None:
        return None
    unknown = [t for t in names if t not in known]
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown tool/skill(s): {', '.join(sorted(set(unknown)))}")
    chosen = set(names)
    return None if chosen >= known and known else sorted(chosen)  # everything checked → 'all' (NULL)


async def _normalize_project_access(
    refs: list[str | int] | None, org_id: int, db: AsyncSession
) -> list[int] | None:
    """Turn slugs/ids into the stored list of project IDS, mirroring `_normalize_tool_access`:
    validate against the org's own projects (422 on unknown — never silently ignore a typo) and
    **collapse an all-projects selection back to NULL**, so a fully-scoped member keeps
    auto-inheriting projects created later."""
    if refs is None:
        return None
    known = (await db.execute(select(Project).where(Project.org_id == org_id))).scalars().all()
    by_slug = {p.slug: p.id for p in known}
    by_id = {p.id for p in known}
    ids: set[int] = set()
    for ref in refs:
        if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
            pid = int(ref)
            if pid not in by_id:
                raise HTTPException(status_code=422, detail=f"unknown project {ref!r} in this team")
            ids.add(pid)
        elif ref in by_slug:
            ids.add(by_slug[ref])
        else:
            raise HTTPException(status_code=422, detail=f"unknown project {ref!r} in this team")
    if known and ids >= by_id:
        return None  # every project selected = unrestricted, so store it as such
    return sorted(ids)


_SIGNUP_HTTP_ERRORS = {
    "machine_identity": (403, "this address cannot be used to sign in"),
    "unsafe_webhook": (422, "webhook_url must be a public http(s) URL"),
    "email_exists": (409, "email already registered"),
    "sandbox_user": (403, (
        "the demo sandbox can't create a real team — sign in with GitHub, Google, or email to make one"
    )),
    "slug_conflict": (409, "could not allocate a unique org slug — retry"),
}


def _signup_http_error(exc: signup_use_cases.SignupError) -> HTTPException:
    status_code, detail = _SIGNUP_HTTP_ERRORS[exc.kind]
    return HTTPException(status_code=status_code, detail=detail)


# The app alias preserves the handlers' @app decorators and the ordered attachment convention.
app = APIRouter()
signup_router = app


@app.post("/users")
async def register_user(body: UserIn, request: Request) -> dict:
    try:
        return await signup_use_cases.register_user(
            email=body.email,
            webhook_url=body.webhook_url,
            ad_cookie=request.cookies.get("treg_ad") or "",
            utm_cookie=request.cookies.get("treg_utm") or "",
            referral_cookie=request.cookies.get(REFERRAL_COOKIE) or "",
        )
    except signup_use_cases.SignupError as exc:
        raise _signup_http_error(exc) from exc


@app.post("/orgs")
async def create_org(
    body: OrgIn, request: Request,
    user: User = Depends(require_identity),
) -> dict:
    try:
        return await signup_use_cases.create_org(
            user=user,
            name=body.name,
            ad_cookie=request.cookies.get("treg_ad") or "",
            utm_cookie=request.cookies.get("treg_utm") or "",
            referral_cookie=request.cookies.get(REFERRAL_COOKIE) or "",
        )
    except signup_use_cases.SignupError as exc:
        raise _signup_http_error(exc) from exc


app = APIRouter()
org_entry_router = app


@app.get("/orgs")
async def list_orgs(
    user: User = Depends(require_identity),
    x_treg_token: str = Header(default=""),
    x_treg_org: str = Header(default=""),
    db: AsyncSession = Depends(get_session),
) -> list[dict]:
    return await teams.list_user_orgs(
        user_id=user.id,
        x_treg_token=x_treg_token,
        x_treg_org=x_treg_org,
        db=db,
    )


app = APIRouter()
invite_entry_router = app


@app.post("/orgs/{org_id}/invites")
async def create_invite(
    org_id: int, body: InviteIn, request: Request,
    caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session),
) -> dict:
    _require_admin_of(org_id, caller)
    if body.role not in ("viewer", "member", "admin"):
        raise HTTPException(status_code=422, detail="role must be 'viewer', 'member', or 'admin'")
    # Role assignment is owner-only (see set_member_role); the invite door must honour the same
    # boundary or an admin could mint fellow admins that they can't otherwise create.
    if body.role == "admin" and caller.role != "owner":
        raise HTTPException(status_code=403, detail="only an owner can invite an admin")
    email = _norm_email(body.email)
    # An email already in the org can't accept a new invite (accept would 409) — reject the dead-end up front.
    existing_user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing_user is not None:
        m = (await db.execute(select(Membership).where(
            Membership.user_id == existing_user.id, Membership.org_id == org_id
        ))).scalar_one_or_none()
        if m is not None:
            raise HTTPException(status_code=409, detail="that email is already a member of this org")
    # Supersede any prior pending invite for this email so there's exactly one live code per invitee
    # (re-inviting used to stack duplicate pending rows that all point at the same seat).
    for prior in (await db.execute(select(Invite).where(
        Invite.org_id == org_id, Invite.email == email, Invite.status == "pending"
    ))).scalars().all():
        await db.delete(prior)
    days = max(1, min(body.expires_days, 3650))  # clamp BOTH ends — a huge value overflows datetime → 500
    expires_at = _utcnow_naive() + timedelta(days=days)
    tool_access = _normalize_tool_access(body.tool_access, await _known_access_names(org_id, db))
    project_access = await _normalize_project_access(body.project_access, org_id, db)
    if body.landing is not None and not _LANDING_RE.match(body.landing):
        raise HTTPException(status_code=422, detail="landing must be a detail path like /app/skills/<name>")
    code = crypto.new_token()
    # A SECOND secret for the email link only. The admin gets `code` back (out-of-band relay) so the
    # code can never be a sign-in factor; `email_token` is never returned here — only the inbox sees
    # it, which is what lets /auth/invite-signin treat it like an emailed OTP and mint a session.
    email_token = crypto.new_token()
    invite = Invite(
        org_id=org_id, email=email, role=body.role,
        code_hash=crypto.hash_token(code), email_token_hash=crypto.hash_token(email_token),
        invited_by=caller.email, expires_at=expires_at,
        tool_access=tool_access, project_access=project_access,
        local_run_enabled=body.local_run_enabled, landing=body.landing,
    )
    db.add(invite)
    await db.commit()
    org = await db.get(Org, org_id)  # for the invite email's team name
    if not email.endswith("@" + demo_seed.DEMO_DOMAIN):  # don't email the onboarding's fake teammate domain
        scheme = "https" if _is_https(request) else request.url.scheme
        host = request.headers.get("host", "")
        shared = ""  # share-born invite → the email leads with what was shared
        if body.landing:
            kind, _, name = body.landing.removeprefix("/app/").partition("/")
            shared = f'the {"skill" if kind == "skills" else "tool"} “{name}”'
        await email_sender.send_invite(  # best-effort; the code is also returned for out-of-band relay
            email, caller.email, (org.name if org else email), body.role, code, email_token,
            expires_at.isoformat(), link_base=(f"{scheme}://{host}" if host else ""), shared=shared,
        )
    return {"code": code, "email": email, "role": body.role, "org_id": org_id,
            "expires_at": expires_at.isoformat()}  # email_token deliberately NOT returned (inbox-only)


@app.post("/invites/accept")
async def accept_invite(body: AcceptIn, db: AsyncSession = Depends(get_session)) -> dict:
    # Open endpoint, protected by the unguessable one-time code. Registers the user if new,
    # joins them to the org, and mints their own org-scoped token (the admin never sees it).
    invite = (
        await db.execute(select(Invite).where(Invite.code_hash == crypto.hash_token(body.code)))
    ).scalar_one_or_none()
    email = _norm_email(body.email)
    if invite is None or invite.status != "pending":
        raise HTTPException(status_code=404, detail="invalid or already-used invite code")
    if invite.expires_at is not None and _as_naive(invite.expires_at) < _utcnow_naive():
        raise HTTPException(status_code=410, detail="invite code expired")
    if invite.email != email:
        raise HTTPException(status_code=403, detail="this invite is for a different email")
    org = await db.get(Org, invite.org_id)
    if org is not None and org.suspended:  # don't let anyone join a platform-locked org
        raise HTTPException(status_code=403, detail="org suspended")
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is not None and user.suspended:  # a banned user must not accrue new memberships
        raise HTTPException(status_code=403, detail="account suspended")
    if user is None:
        # Brand-new user → create the user only. Accepting the invite below IS their first team
        # (no auto personal org — consistent with the login doors).
        user = User(email=email)
        db.add(user)
        await db.flush()
    existing = (
        await db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.org_id == invite.org_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="already a member of this org")
    token = crypto.new_token()
    db.add(Membership(user_id=user.id, org_id=invite.org_id, role=invite.role, token_hash=crypto.hash_token(token),
                      tool_access=invite.tool_access, project_access=invite.project_access,
                      local_run_enabled=invite.local_run_enabled))
    invite.status = "accepted"
    try:
        await db.commit()  # a concurrent double-accept trips uq_membership_user_org — 409, not 500
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="already a member of this org")
    org = await db.get(Org, invite.org_id)
    return {"org": org.slug, "org_id": org.id, "name": org.name, "role": invite.role, "token": token}


@app.get("/invites/mine")
async def my_invites(
    user: User = Depends(require_identity), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    """Every pending invite addressed to MY email — the code-free door. Proving my email (via any
    login method) is enough to see these; the invite code becomes a shortcut, not a requirement."""
    rows = (
        await db.execute(select(Invite).where(Invite.email == user.email, Invite.status == "pending")
                         .order_by(Invite.created_at.desc()))  # newest first — the invite you just clicked
    ).scalars().all()
    now = _utcnow_naive()
    orgs = {  # batch the org lookup (was one db.get per invite)
        o.id: o for o in (await db.execute(
            select(Org).where(Org.id.in_([inv.org_id for inv in rows]))
        )).scalars().all()
    }
    out = []
    for inv in rows:
        if inv.expires_at is not None and _as_naive(inv.expires_at) < now:
            continue
        org = orgs.get(inv.org_id)
        if org is None or org.suspended:  # a platform-locked org isn't joinable — don't surface it
            continue
        out.append({
            "id": inv.id, "org": org.slug, "org_id": org.id, "name": org.name, "role": inv.role,
            "invited_by": inv.invited_by, "landing": inv.landing,
            "expires_at": inv.expires_at.isoformat() if inv.expires_at else None,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
        })
    return out


app = APIRouter()
invite_management_router = app


@app.post("/invites/{invite_id}/accept")
async def accept_my_invite(
    invite_id: int, user: User = Depends(require_identity), db: AsyncSession = Depends(get_session)
) -> dict:
    """Accept an invite addressed to my already-proven email — no code needed (the identity token
    proves the email). The code path (`POST /invites/accept`) stays for out-of-band joins."""
    invite = await db.get(Invite, invite_id)
    if invite is None or invite.status != "pending":
        raise HTTPException(status_code=404, detail="invalid or already-used invite")
    if invite.email != user.email:
        raise HTTPException(status_code=403, detail="this invite is for a different email")
    if invite.expires_at is not None and _as_naive(invite.expires_at) < _utcnow_naive():
        raise HTTPException(status_code=410, detail="invite expired")
    org = await db.get(Org, invite.org_id)
    if org is not None and org.suspended:  # don't let anyone join a platform-locked org
        raise HTTPException(status_code=403, detail="org suspended")
    existing = (
        await db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.org_id == invite.org_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="already a member of this org")
    token = crypto.new_token()  # return the org-scoped token (was minted-then-discarded → an unusable membership)
    db.add(Membership(
        user_id=user.id, org_id=invite.org_id, role=invite.role, token_hash=crypto.hash_token(token),
        tool_access=invite.tool_access, project_access=invite.project_access,
        local_run_enabled=invite.local_run_enabled,
    ))
    invite.status = "accepted"
    try:
        await db.commit()  # a concurrent double-accept trips uq_membership_user_org — 409, not 500
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="already a member of this org")
    org = await db.get(Org, invite.org_id)
    return {"org": org.slug, "org_id": org.id, "name": org.name, "role": invite.role, "token": token}


@app.get("/orgs/{org_id}/invites")
async def list_invites(
    org_id: int, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    _require_admin_of(org_id, caller)
    await health.gc_expired_invites(db, org_id)  # purge dead codes so the list shows only live ones
    await db.commit()
    rows = (
        await db.execute(select(Invite).where(Invite.org_id == org_id, Invite.status == "pending"))
    ).scalars().all()
    return [
        {
            "id": i.id, "email": i.email, "role": i.role, "invited_by": i.invited_by,
            "expires_at": i.expires_at.isoformat() if i.expires_at else None,
            "created_at": i.created_at.isoformat(),
        }
        for i in rows
    ]


@app.delete("/orgs/{org_id}/invites/{invite_id}")
async def revoke_invite(
    org_id: int, invite_id: int, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    _require_admin_of(org_id, caller)
    invite = await db.get(Invite, invite_id)
    if invite is None or invite.org_id != org_id or invite.status != "pending":
        raise HTTPException(status_code=404, detail="invite not found")  # can't "revoke" an accepted/consumed one
    await db.delete(invite)  # the code can no longer be accepted
    await db.commit()
    return {"revoked_invite": invite_id}
