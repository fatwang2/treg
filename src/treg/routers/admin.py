"""Cross-tenant admin read and reconciliation routes."""

from __future__ import annotations

from datetime import timedelta
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import reconcile
from ..config import get_settings
from ..db import get_session, session_maker
from ..models import Bundle, CallRecord, Membership, Org, Referral, Secret, Tool, User
from ..timeutil import as_naive as _as_naive
from ..timeutil import utcnow_naive as _utcnow_naive
from ..domain.identity.access import require_superadmin


# The app alias preserves the moved handlers' original @app.get decorator text byte-for-byte.
app = APIRouter()
reads_router = app


def _tally(items) -> dict:
    d: dict[str, int] = {}
    for k in items:
        d[k] = d.get(k, 0) + 1
    return d


@app.get("/admin/stats")
async def admin_stats(_: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)) -> dict:
    async def n(model) -> int:
        return (await db.execute(select(func.count()).select_from(model))).scalar() or 0

    tools = (await db.execute(select(Tool))).scalars().all()
    secrets = (await db.execute(select(Secret))).scalars().all()
    # THREE COLUMNS, not the whole row. This is an unbounded read of the largest table in the
    # database (tens of thousands of rows), and every one of them was being materialised as a full
    # ORM object to count three fields. It matters more now that `callrecord` carries the failure
    # evidence columns, which are wide and are read by nothing here.
    calls = (await db.execute(
        select(CallRecord.org_id, CallRecord.created_at, CallRecord.status_code))).all()
    users = (await db.execute(select(User))).scalars().all()
    orgs = (await db.execute(select(Org))).scalars().all()
    # Sandbox onboarding data isn't real platform usage — exclude the demo footprint from totals so
    # metrics stay honest (fake teammates, demo teams, and everything scoped to them).
    demo_org_ids = {o.id for o in orgs if o.demo}
    users = [u for u in users if not u.demo]
    orgs = [o for o in orgs if not o.demo]
    tools = [t for t in tools if t.org_id not in demo_org_ids]
    secrets = [s for s in secrets if s.org_id not in demo_org_ids]
    calls = [c for c in calls if c.org_id not in demo_org_ids]
    now = _utcnow_naive()

    def since(rows, days, pred=lambda r: True):
        cut = now - timedelta(days=days)
        return sum(1 for r in rows if _as_naive(r.created_at) >= cut and pred(r))

    ok = sum(1 for c in calls if c.status_code < 400)
    return {
        "totals": {
            "users": len(users), "orgs": len(orgs), "tools": len(tools),
            "secrets": len(secrets), "bundles": await n(Bundle), "calls": len(calls),
            "superadmins": sum(1 for u in users if u.is_superadmin),
            "suspended_orgs": sum(1 for o in orgs if o.suspended),
        },
        "tools_by_injector": _tally(b.get("injector", "?") for t in tools for b in t.bindings),
        "tools_by_host": _tally(t.host for t in tools),
        "credential_health": _tally(s.health_status for s in secrets),
        "calls": {
            "last_7d": since(calls, 7), "last_30d": since(calls, 30), "total": len(calls),
            "success_rate": round(ok / len(calls), 3) if calls else None,
        },
        "growth": {
            "new_users_7d": since(users, 7), "new_users_30d": since(users, 30),
            "new_orgs_7d": since(orgs, 7), "new_orgs_30d": since(orgs, 30),
        },
    }


@app.get("/admin/orgs")
async def admin_orgs(_: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)) -> list[dict]:
    orgs = (await db.execute(select(Org))).scalars().all()

    async def _counts(model) -> dict[int, int]:  # one grouped COUNT instead of one-per-org (was O(orgs) queries)
        rows = await db.execute(select(model.org_id, func.count()).group_by(model.org_id))
        return {oid: n for oid, n in rows.all()}

    mems: dict[int, list] = {}
    for m in (await db.execute(select(Membership))).scalars().all():
        mems.setdefault(m.org_id, []).append(m)
    tool_n, secret_n, bundle_n = await _counts(Tool), await _counts(Secret), await _counts(Bundle)
    # Was 1 + 4N serial queries (401 at 100 orgs); now a constant ~4 regardless of tenant count.
    return [
        {
            "id": o.id, "slug": o.slug, "name": o.name, "suspended": o.suspended,
            "members": len(mems.get(o.id, [])), "roles": _tally(m.role for m in mems.get(o.id, [])),
            "tools": tool_n.get(o.id, 0), "secrets": secret_n.get(o.id, 0), "bundles": bundle_n.get(o.id, 0),
            "created_at": o.created_at.isoformat(),
        }
        for o in orgs
    ]


@app.get("/admin/orgs/{org_id}")
async def admin_org_detail(
    org_id: int, _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)
) -> dict:
    org = await db.get(Org, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="org not found")
    mem = (await db.execute(select(Membership).where(Membership.org_id == org_id))).scalars().all()
    umap = {u.id: u for u in (await db.execute(
        select(User).where(User.id.in_([m.user_id for m in mem]))
    )).scalars().all()}  # batched (was one db.get per member)
    members = [{"user_id": m.user_id, "email": umap[m.user_id].email if m.user_id in umap else None, "role": m.role}
               for m in mem]
    tools = (await db.execute(select(Tool).where(Tool.org_id == org_id))).scalars().all()
    secrets = (await db.execute(select(Secret).where(Secret.org_id == org_id))).scalars().all()
    recent = (
        await db.execute(select(CallRecord).where(CallRecord.org_id == org_id).order_by(CallRecord.id.desc()).limit(20))
    ).scalars().all()
    return {
        "id": org.id, "slug": org.slug, "name": org.name, "suspended": org.suspended,
        "members": members,
        "tools": [{"id": t.id, "name": t.name, "host": t.host, "owner": t.owner,
                   "injectors": [b.get("injector") for b in t.bindings]} for t in tools],
        "secrets": [{"id": s.id, "name": s.name, "kind": s.kind, "health": s.health_status, "owner": s.owner} for s in secrets],
        "recent_calls": [{"tool": c.tool_name, "method": c.method, "status": c.status_code,
                          "user": c.user_email, "at": c.created_at.isoformat()} for c in recent],
    }


@app.get("/admin/users")
async def admin_users(_: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)) -> list[dict]:
    users = (await db.execute(select(User))).scalars().all()
    mems_by_user: dict[int, list] = {}  # all memberships in one query, grouped (was one query per user)
    for m in (await db.execute(select(Membership))).scalars().all():
        mems_by_user.setdefault(m.user_id, []).append(m)
    omap = {o.id: o for o in (await db.execute(  # all referenced orgs in one query (was one db.get per membership)
        select(Org).where(Org.id.in_({m.org_id for ms in mems_by_user.values() for m in ms}))
    )).scalars().all()}
    return [
        {
            "id": u.id, "email": u.email, "is_superadmin": u.is_superadmin, "suspended": u.suspended,
            "orgs": [{"slug": omap[m.org_id].slug if m.org_id in omap else None, "role": m.role}
                     for m in mems_by_user.get(u.id, [])],
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]


@app.get("/admin/tools")
async def admin_tools(_: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)) -> list[dict]:
    tools = (await db.execute(select(Tool))).scalars().all()
    omap = {o.id: o for o in (await db.execute(  # batched (was one db.get per tool)
        select(Org).where(Org.id.in_({t.org_id for t in tools}))
    )).scalars().all()}
    return [{"id": t.id, "name": t.name, "org": omap[t.org_id].slug if t.org_id in omap else None,
             "host": t.host, "owner": t.owner, "injectors": [b.get("injector") for b in t.bindings]} for t in tools]


@app.get("/admin/calls")
async def admin_calls(
    limit: int = 50, _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    limit = max(1, min(limit, 1000))
    rows = (await db.execute(select(CallRecord).order_by(CallRecord.id.desc()).limit(limit))).scalars().all()
    return [{"id": c.id, "org_id": c.org_id, "user": c.user_email, "tool": c.tool_name,
             "method": c.method, "status": c.status_code, "at": c.created_at.isoformat()} for c in rows]


_ERROR_EVIDENCE_TTL_DAYS = 14
_ERROR_EVIDENCE_EXPIRED = "<expired>"


@app.get("/admin/errors")
async def admin_errors(
    days: int = 7, limit: int = 100, provider: str | None = None, status: int | None = None,
    tier: str | None = None,
    _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session),
) -> dict:
    """Failed calls with the evidence to explain them — the caller's request and the provider's own
    answer (see models.CallRecord.error_request).

    Superadmin-only and deliberately not mirrored on `/calls`: the rows hold customers' request
    content, so v1 keeps them behind the same door as every other cross-tenant view.

    Ageing happens HERE rather than on the request path. There is no scheduler in this app by design
    (see the comment above `_claim_idempotent`), and the obvious lazy hook — a marker written on the
    request session — cannot work: `get_session` never commits, so the marker would roll back and the
    purge would then run on every single failed call. Doing it on this route costs one UPDATE to the
    person who came to read errors, which is exactly who wants the stale ones gone.
    """
    purged = await _purge_expired_error_evidence()
    since = _utcnow_naive() - timedelta(days=max(1, min(days, 90)))
    q = (select(CallRecord)
         .where(CallRecord.created_at >= since,
                or_(CallRecord.error_request.is_not(None), CallRecord.error_response.is_not(None)))
         .order_by(CallRecord.id.desc()).limit(max(1, min(limit, 500))))
    if provider:
        q = q.where(CallRecord.provider == provider)
    if status is not None:
        q = q.where(CallRecord.status_code == status)
    if tier is not None:
        q = q.where(CallRecord.credential_tier.is_(None) if tier == ""
                    else CallRecord.credential_tier == tier)
    rows = (await db.execute(q)).scalars().all()
    omap = {o.id: o for o in (await db.execute(
        select(Org).where(Org.id.in_({c.org_id for c in rows if c.org_id is not None})))).scalars().all()}
    return {
        "since": since.isoformat(), "days": days, "retention_days": _ERROR_EVIDENCE_TTL_DAYS,
        "expired_rows_purged": purged,
        "errors": [{
            "id": c.id, "call_ref": c.call_ref, "at": c.created_at.isoformat(),
            "org": omap[c.org_id].slug if c.org_id in omap else None,
            # `method` is already on the row and is the whole diagnosis for a real failure class:
            # 47 of apollo.people.enrich's failures were a GET at a POST endpoint. Omitting a field
            # we already store, in the view built to explain failures, was a free loss.
            "endpoint_id": c.endpoint_id, "provider": c.provider, "tier": c.credential_tier,
            "status": c.status_code,
            "method": c.method, "refused_by": c.refused_by, "duration_ms": c.duration_ms,
            # An aged-out row holds the sentinel, which is a STATE, not content. Returning it as the
            # request/response would have a reader treat the word `<expired>` as the provider's
            # answer; `expired` says the same thing without pretending to be evidence.
            "request": None if c.error_request == _ERROR_EVIDENCE_EXPIRED else c.error_request,
            "response": None if c.error_response == _ERROR_EVIDENCE_EXPIRED else c.error_response,
            "expired": c.error_response == _ERROR_EVIDENCE_EXPIRED,
        } for c in rows],
    }


async def _purge_expired_error_evidence() -> int:
    """Blank the evidence columns past the retention window; returns how many rows were cleared.

    An UPDATE, not a DELETE: `callrecord` is the audit trail and the rest of the row must survive.
    The sentinel rather than NULL keeps "captured, then aged out" distinguishable from "never
    captured" — without it an old failure and a successful call look identical. Runs on its own
    session because the request's session is not committed for us.
    """
    cutoff = _utcnow_naive() - timedelta(days=_ERROR_EVIDENCE_TTL_DAYS)
    try:
        async with session_maker() as db:
            result = await db.execute(
                update(CallRecord)
                # `coalesce`, not a bare `!=`: SQL three-valued logic makes `error_response !=
                # '<expired>'` UNKNOWN when that column is NULL, so a row carrying request-only
                # evidence would never age out — excluded by the very predicate meant only to skip
                # rows already purged.
                .where(CallRecord.created_at < cutoff,
                       or_(CallRecord.error_request.is_not(None),
                           CallRecord.error_response.is_not(None)),
                       or_(func.coalesce(CallRecord.error_request, "") != _ERROR_EVIDENCE_EXPIRED,
                           func.coalesce(CallRecord.error_response, "") != _ERROR_EVIDENCE_EXPIRED))
                .values(error_request=_ERROR_EVIDENCE_EXPIRED,
                        error_response=_ERROR_EVIDENCE_EXPIRED))
            await db.commit()
            return int(result.rowcount or 0)
    except Exception as exc:  # noqa: BLE001 — retention housekeeping must not break the view
        logging.getLogger("treg").warning("error-evidence purge failed: %s", exc)
        return 0


@app.get("/admin/health")
async def admin_health(_: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session)) -> list[dict]:
    rows = (await db.execute(select(Secret).where(Secret.health_status != "ok"))).scalars().all()
    omap = {o.id: o for o in (await db.execute(  # batched (was one db.get per secret)
        select(Org).where(Org.id.in_({s.org_id for s in rows}))
    )).scalars().all()}
    out: list[dict] = []
    for s in rows:
        org = omap.get(s.org_id)
        out.append({"secret_id": s.id, "name": s.name, "org": org.slug if org else None,
                    "kind": s.kind, "status": s.health_status, "detail": s.health_detail})
    return out


# Rebind app so the second block keeps its decorator text and remains a separate attach point.
app = APIRouter()
reports_router = app


# ---- reconciliation: is the money real? ----------------------------------------------------
# Cross-org aggregates over platform spend, so `require_superadmin` and nothing weaker — an org admin
# may see their own bill (`/orgs/{id}/balance`), never the platform's margin. See reconcile.py.
@app.get("/admin/reconcile/drift")
async def admin_reconcile_drift(
    since_days: int = 30, min_calls: int = 3,
    _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session),
) -> dict:
    """Endpoints whose observed cost has wandered from the catalog's estimate. Only the providers that
    report their own charge in-band appear (see `reconcile.price_drift`)."""
    since = reconcile.window_start(since_days)
    rows = await reconcile.price_drift(db, since, max(1, min_calls))
    return {"since": since.isoformat(), "since_days": since_days, "min_calls": min_calls,
            "tolerance": reconcile.DRIFT_TOLERANCE,
            "flagged": [r for r in rows if r["flagged"]], "endpoints": rows}


@app.get("/admin/reconcile/spend")
async def admin_reconcile_spend(
    since_days: int = 30, _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session),
) -> dict:
    """Settled platform spend per provider — the number to hold next to the provider's own invoice."""
    since = reconcile.window_start(since_days)
    return {"since": since.isoformat(), "since_days": since_days,
            **await reconcile.provider_spend(db, since)}


@app.get("/admin/reconcile/repeats")
async def admin_reconcile_repeats(
    since_days: int = 30, top: int = 10,
    _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session),
) -> dict:
    """How much of the bill was the same query twice — the cache-worthiness measurement."""
    since = reconcile.window_start(since_days)
    return {"since": since.isoformat(), "since_days": since_days,
            **await reconcile.repeat_rate(db, since, top=top)}


@app.get("/admin/referrals")
async def admin_referrals(
    status: str = "", limit: int = Query(200, ge=1, le=1000),
    _: str = Depends(require_superadmin), db: AsyncSession = Depends(get_session),
) -> dict:
    """Every referral, across every team — who invited whom, what it cost, and what is still owed.

    Cross-org, so `require_superadmin` and nothing weaker, exactly like the reconcile trio above.
    Read-only: it pays nothing and refuses nothing. `pending_payout_micro` is what the sweep will
    grant once holds elapse, and it is the number that says whether this program is affordable
    before the money leaves — the same job `provider_spend` does for provider bills.

    This is also the report the influencer tier will read when it lands: a cash payout run is this
    list, filtered to partners on a contract, exported.
    """
    s = get_settings()
    q = select(Referral).order_by(Referral.created_at.desc()).limit(limit)
    if status:
        q = q.where(Referral.status == status)
    rows = (await db.execute(q)).scalars().all()

    emails: dict[int, str] = {}
    for uid in {r.referrer_user_id for r in rows} | {r.referred_user_id for r in rows}:
        u = await db.get(User, uid)
        if u is not None:
            emails[uid] = u.email

    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    pending = sum(int(s.referral_referrer_micro) + int(s.referral_referred_micro)
                  for r in rows if r.status == "qualified")
    paid = sum(r.referrer_reward_micro + r.referred_reward_micro for r in rows if r.status == "paid")
    return {
        "counts": by_status,
        "paid_micro": paid,
        "pending_payout_micro": pending,
        "referrals": [{
            "id": r.id, "code": r.code, "status": r.status, "reason": r.reject_reason,
            "referrer": emails.get(r.referrer_user_id, ""),
            "referred": emails.get(r.referred_user_id, ""),
            "referred_org_id": r.referred_org_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "qualified_at": r.qualified_at.isoformat() if r.qualified_at else None,
            "paid_at": r.paid_at.isoformat() if r.paid_at else None,
            "paid_micro": r.referrer_reward_micro + r.referred_reward_micro,
        } for r in rows],
    }
