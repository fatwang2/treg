"""Authentication use cases and their transaction boundaries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import hmac
import secrets as _secrets
from urllib.parse import quote

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import crypto, db as database, demo as demo_seed, email as email_sender, ratestore
from ..config import get_settings
from ..domain.identity import session as sess
from ..domain.identity.access import (
    _is_machine_email,
    _membership_by_token,
    _norm_email,
    _resolve_org,
    _user_from_identity_token,
    _user_from_session,
)
from ..models import Membership, Org, Tool, User
from ..timeutil import utcnow_naive as _utcnow_naive
from . import signup


CLI_TOKEN_TTL = 30 * 24 * 3600      # identity token lifetime for the CLI
EMAIL_CODE_TTL = 10 * 60  # seconds a code stays valid
MAX_OTP_ATTEMPTS = 5  # invalidate a code after this many wrong guesses (brute-force guard)
OTP_NS = "otp"
OTP_START_NS = "otp_start"
OTP_START_WINDOW_S = 900      # 15 minutes
OTP_START_MAX_PER_EMAIL = 5   # code requests for one inbox per window (caps bombing a single victim)
OTP_START_MAX_PER_IP = 30     # code requests from one IP per window (looser — offices/NAT share an IP)


# In-memory handshake state for `treg login` (single-instance; short-lived, fine to lose on restart).
# Both carry a created-at so abandoned handshakes (unauthenticated, attacker-chosen keys) are swept
# rather than accumulating forever — the results map holds live 30-day tokens, so it must not leak.
_cli_states: dict[str, tuple[str, datetime]] = {}   # oauth state -> (login_id, created_at)
_cli_results: dict[str, tuple[dict, datetime]] = {}  # login_id -> (result, created_at) — a completed login
# login_id -> (pairing_code, attempts_left, created_at). Created by POST /auth/cli/start; the browser must
# echo the code back at approve time (validated server-side) before a token is issued. This is the phishing
# guard: a login the user didn't start has no matching code, and the poll endpoint carries no code to
# brute-force. The code is shown ONLY in the terminal, never in the /login URL.
_cli_pending: dict[str, tuple[str, int, datetime]] = {}
HANDSHAKE_TTL = 600                  # seconds an abandoned login handshake lingers before eviction
CLI_APPROVE_MAX_TRIES = 8           # wrong pairing-code attempts before a pending login is discarded
_PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # unambiguous (no O/0/I/1); matches the CLI's charset


def _prune_handshakes() -> None:
    cutoff = _utcnow_naive() - timedelta(seconds=HANDSHAKE_TTL)
    for k in [k for k, (_, t) in _cli_states.items() if t < cutoff]:
        _cli_states.pop(k, None)
    for k in [k for k, (_, t) in _cli_results.items() if t < cutoff]:
        _cli_results.pop(k, None)
    for k in [k for k, (_, _, t) in _cli_pending.items() if t < cutoff]:
        _cli_pending.pop(k, None)


class EmailAuthError(Exception):
    """A framework-neutral email-auth refusal translated by the HTTP router."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(kind)


class CliPairingError(Exception):
    """A framework-neutral CLI pairing refusal translated by the HTTP router."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(kind)


class SocialLoginError(Exception):
    """A framework-neutral social-login outcome translated by the HTTP router."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(kind)


class IdentityLookupError(Exception):
    """The presented browser or token identity did not resolve to an active user."""


@dataclass(frozen=True)
class VerifiedEmail:
    token: str
    email: str
    session_cookie: str


@dataclass(frozen=True)
class SocialLoginStart:
    state: str
    url: str


@dataclass(frozen=True)
class SocialLoginProof:
    user: User
    cli_state: tuple | None


@dataclass(frozen=True)
class CurrentIdentity:
    email: str
    is_superadmin: bool
    onboarded: bool
    github: bool
    org_id: int | None = None
    org: str | None = None
    role: str | None = None


async def start_email_login(email: str, client_ip: str) -> dict:
    """Issue and deliver an email OTP, committing its rate and one-time state atomically."""
    email = _norm_email(email)
    if email.endswith("@" + demo_seed.DEMO_DOMAIN):
        raise EmailAuthError("demo_address")
    if _is_machine_email(email):
        raise EmailAuthError("machine_identity")

    async with database.session_maker() as db:
        await ratestore.sweep(db, OTP_START_NS)
        if not await ratestore.rate_check(
            db, OTP_START_NS,
            [(f"e:{email}", OTP_START_MAX_PER_EMAIL), (f"i:{client_ip}", OTP_START_MAX_PER_IP)],
            OTP_START_WINDOW_S,
        ):
            await db.commit()
            raise EmailAuthError("rate_limited")
        code = f"{_secrets.randbelow(1_000_000):06d}"
        await ratestore.kv_put(
            db, OTP_NS, email,
            {"hash": crypto.hash_token(code), "attempts": MAX_OTP_ATTEMPTS}, EMAIL_CODE_TTL,
        )
        await db.commit()

    result = {"sent": True, "email": email}
    if get_settings().expose_dev_code:
        print(f"[email-otp] {email} -> {code}")
        result["dev_code"] = code
    else:
        await email_sender.send_otp(email, code, ttl_minutes=EMAIL_CODE_TTL // 60)
    return result


async def verify_email_login(email: str, code: str) -> VerifiedEmail:
    """Consume an email OTP and return both CLI and browser credentials for the proven identity."""
    email = _norm_email(email)
    async with database.session_maker() as db:
        entry = await ratestore.kv_get(db, OTP_NS, email)
        if entry is None:
            await db.commit()
            raise EmailAuthError("invalid_code")
        if not hmac.compare_digest(entry["hash"], crypto.hash_token(code.strip())):
            entry["attempts"] -= 1
            if entry["attempts"] <= 0:
                await ratestore.kv_pop(db, OTP_NS, email)
            else:
                await ratestore.kv_put(db, OTP_NS, email, entry, ttl_s=None)
            await db.commit()
            raise EmailAuthError("invalid_code")
        await ratestore.kv_pop(db, OTP_NS, email)
        try:
            user = await signup.find_or_create_user(db, email)
        except signup.MachineIdentityError as exc:
            raise EmailAuthError("machine_identity") from exc
        if user.suspended:
            raise EmailAuthError("suspended")
        await db.commit()
        token = sess.make(user.id, CLI_TOKEN_TTL, user.token_version)
        session_cookie = sess.make(user.id, token_version=user.token_version)
        return VerifiedEmail(token=token, email=user.email, session_cookie=session_cookie)


def _norm_pair_code(code: str | None) -> str:
    """Normalise a login pairing code for comparison: strip, uppercase, drop separators/whitespace so
    `7f3k`, `7F3K`, ` 7F3K ` all match. Empty stays empty (an empty code never matches)."""
    return "".join((code or "").split()).replace("-", "").upper()


async def start_cli_login() -> dict:
    """Mint and retain the server side of a CLI pairing handshake."""
    _prune_handshakes()
    login_id = _secrets.token_urlsafe(18)
    code = "".join(_secrets.choice(_PAIR_ALPHABET) for _ in range(4))
    _cli_pending[login_id] = (code, CLI_APPROVE_MAX_TRIES, _utcnow_naive())
    return {"login_id": login_id, "code": code}


async def poll_cli_login(login_id: str) -> dict:
    """Return a completed handshake exactly once, otherwise report it pending."""
    _prune_handshakes()  # sweep abandoned results (they hold live tokens) so the map can't leak
    entry = _cli_results.pop(login_id, None)
    return entry[0] if entry is not None else {"status": "pending"}


async def _orgs_brief(user: User, db: AsyncSession) -> list[dict]:
    """The user's teams for the /login picker: slug, name, role, tool_count, personal. Sorted so the
    team a CLI login should default to sits first (a real team over the personal org, then most tools).
    `personal` mirrors the dashboard's rule: the auto-created org named after the user's email."""
    memberships = (await db.execute(
        select(Membership).where(Membership.user_id == user.id))).scalars().all()
    org_ids = [m.org_id for m in memberships]
    if not org_ids:
        return []
    orgs = {o.id: o for o in (await db.execute(
        select(Org).where(Org.id.in_(org_ids)))).scalars().all()}
    counts = dict((await db.execute(
        select(Tool.org_id, func.count(Tool.id)).where(Tool.org_id.in_(org_ids)).group_by(Tool.org_id))).all())
    out = []
    for m in memberships:
        o = orgs.get(m.org_id)
        if o is None:
            continue
        out.append({"slug": o.slug, "name": o.name, "role": m.role,
                    "tool_count": counts.get(o.id, 0), "personal": o.name == user.email})
    out.sort(key=lambda r: (r["personal"], -r["tool_count"], r["name"].lower()))
    return out


async def cli_orgs(session_cookie: str) -> dict:
    async with database.session_maker() as db:
        user = await _user_from_session(session_cookie, db)
        if user is None:
            return {"email": None, "orgs": []}
        return {"email": user.email, "orgs": await _orgs_brief(user, db)}


async def approve_cli_login(
    session_cookie: str, login_id: str, code: str | None, requested_org: str | None,
) -> dict:
    async with database.session_maker() as db:
        user = await _user_from_session(session_cookie, db)
        if user is None:
            raise CliPairingError("no_session")
        # The pairing code proves the approver is the same person who ran `treg login` (the code is
        # shown only in that terminal). Validate it after session resolution and before org lookup so
        # a phished login link cannot complete and the poll endpoint stays codeless.
        pending = _cli_pending.get(login_id)
        if pending is None:
            raise CliPairingError("expired")
        expected, tries_left, started_at = pending
        typed = _norm_pair_code(code)
        if not typed or not hmac.compare_digest(expected.encode(), typed.encode()):
            if tries_left <= 1:  # discard first when the final permitted miss is consumed
                _cli_pending.pop(login_id, None)
                raise CliPairingError("too_many_wrong_codes")
            _cli_pending[login_id] = (expected, tries_left - 1, started_at)
            raise CliPairingError("wrong_code")
        active_org: str | None = None
        if requested_org:
            org = await _resolve_org(requested_org, db)
            membership = (await db.execute(select(Membership).where(
                Membership.user_id == user.id,
                Membership.org_id == org.id,
            ))).scalar_one_or_none() if org else None
            if org is None or membership is None:
                raise CliPairingError("not_member")
            active_org = org.slug
        _cli_pending.pop(login_id, None)  # code matched, so consume the pending login before publishing
        result = {"token": sess.make(user.id, CLI_TOKEN_TTL, user.token_version), "email": user.email}
        if active_org:
            result["active_org"] = active_org
        _cli_results[login_id] = (result, _utcnow_naive())
        return {"ok": True, "email": user.email, "active_org": active_org}


async def cli_session_email(session_cookie: str) -> str | None:
    async with database.session_maker() as db:
        user = await _user_from_session(session_cookie, db)
        return user.email if user else None


def start_github_login(cli: str, callback_base: Callable[[], str]) -> SocialLoginStart:
    s = get_settings()
    if not s.github_client_id:
        raise SocialLoginError("github_not_configured")
    redirect = f"{callback_base()}/auth/github/callback"
    state = crypto.new_token()
    if cli:  # this is a `treg login` handshake, not a browser session
        _prune_handshakes()  # evict abandoned handshakes so this map can't grow unbounded
        _cli_states[state] = (cli, _utcnow_naive())
    url = (f"{s.github_authorize_url}?client_id={s.github_client_id}"
           f"&redirect_uri={quote(redirect, safe='')}&scope={quote('read:user user:email')}&state={state}")
    return SocialLoginStart(state=state, url=url)


def start_google_login(cli: str, callback_base: Callable[[], str]) -> SocialLoginStart:
    s = get_settings()
    if not s.google_client_id:
        raise SocialLoginError("google_not_configured")
    redirect = f"{callback_base()}/auth/google/callback"
    state = crypto.new_token()
    if cli:  # a `treg login` handshake, not a browser session
        _prune_handshakes()
        _cli_states[state] = (cli, _utcnow_naive())
    url = (f"{s.google_authorize_url}?client_id={s.google_client_id}"
           f"&redirect_uri={quote(redirect, safe='')}&response_type=code"
           f"&scope={quote('openid email profile')}&state={state}&prompt=select_account")
    return SocialLoginStart(state=state, url=url)


async def _provision_social_user(email: str, state: str) -> SocialLoginProof:
    async with database.session_maker() as db:
        try:
            user = await signup.find_or_create_user(db, email)  # first login = registration (user only; no auto org)
        except signup.MachineIdentityError as exc:
            raise SocialLoginError("machine_identity") from exc
        if user.suspended:  # a banned account may prove its email but must not receive a live session
            raise SocialLoginError("suspended")
        await db.commit()
        # Browser session OR `treg login` handshake — both go through the /login team picker now.
        return SocialLoginProof(user=user, cli_state=_cli_states.pop(state, None))


async def complete_github_login(
    client, code: str, state: str, cookie_state: str, callback_base: Callable[[], str],
) -> SocialLoginProof:
    if not code or not state or state != cookie_state:
        raise SocialLoginError("bad_state")
    s = get_settings()
    try:
        tok = (await client.post(
            s.github_token_url, headers={"Accept": "application/json"},
            data={"client_id": s.github_client_id, "client_secret": s.github_client_secret,
                  "code": code, "redirect_uri": f"{callback_base()}/auth/github/callback"},
        )).json()
        access = tok.get("access_token")
        if not access:
            raise SocialLoginError("github_no_access_token")
        gh = {"Authorization": f"Bearer {access}", "Accept": "application/json", "User-Agent": "treg"}
        prof = (await client.get(f"{s.github_api_url}/user", headers=gh)).json()
        email = prof.get("email")
        if not email:
            emails = (await client.get(f"{s.github_api_url}/user/emails", headers=gh)).json()
            if isinstance(emails, list):
                email = (next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
                         or next((e["email"] for e in emails if e.get("verified")), None))
        if not email:
            raise SocialLoginError("github_no_verified_email")
    except SocialLoginError:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[auth] github callback error: {exc}")  # keep internals server-side, not in the response
        raise SocialLoginError("callback_failed") from exc
    return await _provision_social_user(email, state)


async def complete_google_login(
    client, code: str, state: str, cookie_state: str, callback_base: Callable[[], str],
) -> SocialLoginProof:
    if not code or not state or state != cookie_state:
        raise SocialLoginError("bad_state")
    s = get_settings()
    try:
        tok = (await client.post(
            s.google_token_url, headers={"Accept": "application/json"},
            data={"client_id": s.google_client_id, "client_secret": s.google_client_secret,
                  "code": code, "grant_type": "authorization_code",
                  "redirect_uri": f"{callback_base()}/auth/google/callback"},
        )).json()
        access = tok.get("access_token")
        if not access:
            raise SocialLoginError("google_no_access_token")
        prof = (await client.get(
            s.google_userinfo_url,
            headers={"Authorization": f"Bearer {access}", "Accept": "application/json"})).json()
        email = prof.get("email")
        if not email:
            raise SocialLoginError("google_no_email")
        # Identity is keyed by email, so we must only trust a VERIFIED one — else an unverified Google
        # address equal to a victim's registered email would resolve to the victim (account takeover).
        # (Google's userinfo returns email_verified; the GitHub door already filters for verified.)
        if not prof.get("email_verified"):
            raise SocialLoginError("google_unverified_email")
    except SocialLoginError:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[auth] google callback error: {exc}")  # keep internals server-side, not in the response
        raise SocialLoginError("callback_failed") from exc
    return await _provision_social_user(email, state)


async def current_identity(x_treg_token: str, session_cookie: str) -> CurrentIdentity:
    async with database.session_maker() as db:
        membership = None
        if x_treg_token:
            membership = await _membership_by_token(x_treg_token, db)
            user = (await db.get(User, membership.user_id) if membership
                    else await _user_from_identity_token(x_treg_token, db))
            if user is not None and user.suspended:
                user = None
        else:
            user = await _user_from_session(session_cookie, db)
        if user is None:
            raise IdentityLookupError
        org_id = None
        org_slug = None
        role = None
        if membership is not None:
            # The org this token IS. A machine identity cannot call GET /orgs — `require_identity`
            # refuses it on purpose, since `create_org` hangs off that dependency and an agent could
            # otherwise mint an org it owns. But it still has to learn its OWN org id to reach any
            # /orgs/{id}/... route, and being unable to told `treg balance` there was "no active org".
            org = await db.get(Org, membership.org_id)
            org_id = membership.org_id
            org_slug = org.slug if org else None
            role = membership.role
        return CurrentIdentity(
            email=user.email,
            is_superadmin=user.is_superadmin,
            onboarded=user.onboarded,
            github=bool(get_settings().github_client_id),
            org_id=org_id,
            org=org_slug,
            role=role,
        )
