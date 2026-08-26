"""Authentication HTTP routes and presentation helpers."""

from __future__ import annotations

import hmac
import re
import secrets as _secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

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
from ..config import get_settings
from ..db import get_session
from ..domain.identity import session as sess
from ..domain.identity.access import _resolve_org, _user_from_session
from ..models import Membership, Org, Tool, User
from ..timeutil import utcnow_naive as _utcnow_naive
from .auth_helpers import _is_https, _same_origin


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


_AUTH_HEAD = (
    '<!doctype html><html><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1"><title>tools-registry</title>'
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link href="https://fonts.googleapis.com/css2?family=Geist+Pixel&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">'
    "<style>"
    ':root{--bg:#151412;--panel:#1c1b19;--ink:#f2efe8;--muted:rgba(242,239,232,.55);'
    '--line:rgba(255,255,255,.1);--accent:#19D0E8;'
    '--mono:"DM Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace}'
    "html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);font-family:var(--mono)}"
    "body{background:radial-gradient(90% 50% at 50% -10%,rgba(255,255,255,.04),transparent 60%),var(--bg)}"
    ".wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}"
    ".card{background:linear-gradient(180deg,#201f1d,#171614);border:1px solid var(--line);border-radius:20px;"
    "padding:34px 40px;max-width:440px;text-align:center;"
    "box-shadow:rgba(255,255,255,.08) 0 1px 0 inset, 0 30px 70px rgba(0,0,0,.5)}"
    ".logo{color:var(--accent);font-size:15px;letter-spacing:.5px;margin-bottom:18px}"
    ".mark{font-size:34px;line-height:1;margin-bottom:14px}"
    'h1{font-family:"Geist Pixel",var(--mono);font-size:22px;margin:0 0 8px;font-weight:400;letter-spacing:0}'
    "p{color:var(--muted);font-size:13.5px;line-height:1.55;margin:0}"
    ".pbtn{display:inline-block;background:linear-gradient(180deg,#fdfcf7,#eae7de);color:#1c1b19;border:0;"
    "border-radius:999px;padding:12px 24px;font:500 14px var(--mono);cursor:pointer;"
    "box-shadow:rgba(178,168,165,.2) -1.3px -1.3px 2.5px 0, rgba(0,0,0,.4) 2px 2px 1.5px 0}"
    "</style></head>"
)


# Bound by api.py until the shared social-login presentation helper moves with that journey.
_auth_page = None


# The app alias preserves the moved handlers' original @app decorators byte-for-byte.
app = APIRouter()
cli_router = app


def _norm_pair_code(code: str | None) -> str:
    """Normalise a login pairing code for comparison: strip, uppercase, drop separators/whitespace so
    `7f3k`, `7F3K`, ` 7F3K ` all match. Empty stays empty (an empty code never matches)."""
    return "".join((code or "").split()).replace("-", "").upper()


@app.post("/auth/cli/start")
async def auth_cli_start() -> dict:
    """`treg login` calls this FIRST. The SERVER mints both the login_id and a short pairing code and
    remembers them (pending approval). The code is shown only in that terminal; the browser must echo it
    back at approve time, where it's validated server-side, before any token is issued. So a login the
    user didn't start (a phished /login?cli=<id> link) can't be completed, and the poll endpoint carries
    no code to brute-force. Unauthenticated — on its own it grants nothing."""
    _prune_handshakes()
    login_id = _secrets.token_urlsafe(18)
    code = "".join(_secrets.choice(_PAIR_ALPHABET) for _ in range(4))
    _cli_pending[login_id] = (code, CLI_APPROVE_MAX_TRIES, _utcnow_naive())
    return {"login_id": login_id, "code": code}


@app.get("/auth/cli/poll")
async def auth_cli_poll(login_id: str = "") -> dict:
    """The CLI polls this after opening the browser; returns the identity token once, then forgets it.
    A token only lands here after auth_cli_approve validated the terminal pairing code, so a login the
    user didn't approve never yields one — there is nothing here to brute-force (no code parameter)."""
    _prune_handshakes()  # sweep abandoned results (they hold live tokens) so the map can't leak
    entry = _cli_results.pop(login_id, None)
    return entry[0] if entry is not None else {"status": "pending"}


# `treg login` mints the login_id with token_urlsafe(18) (24 chars); anything outside this shape is
# not one of ours. It's echoed into the /login page's JS, so the whitelist is also the XSS guard.
_LOGIN_ID_RE = re.compile(r"[A-Za-z0-9_-]{8,128}")


class CliApproveIn(BaseModel):
    login_id: str
    code: str | None = None  # the pairing code the user copied from their terminal (phishing guard)
    org: str | None = None  # the team slug the user picked in the /login org picker (optional)


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


@app.get("/auth/cli/orgs")
async def auth_cli_orgs(treg_session: str = Cookie(default=""), db: AsyncSession = Depends(get_session)) -> dict:
    """The /login page fetches this (session-cookie authed) to render the team picker before completing
    a `treg login` handshake. Returns the signed-in user's teams; empty list if no session."""
    user = await _user_from_session(treg_session, db)
    if user is None:
        return {"email": None, "orgs": []}
    return {"email": user.email, "orgs": await _orgs_brief(user, db)}


@app.post("/auth/cli/approve")
async def auth_cli_approve(
    request: Request, body: CliApproveIn,
    treg_session: str = Cookie(default=""), db: AsyncSession = Depends(get_session),
) -> dict:
    """Complete a `treg login` handshake from an EXISTING browser session (the "Continue as" button
    on /login, and the email door after /auth/email/verify sets the cookie). Deliberately a POST with
    a same-origin check — auto-completing on a GET would let a phisher mail out /login?cli=<their-id>
    and poll the victim's identity token straight out of /auth/cli/poll.

    `org` (optional) is the team slug the user picked in the /login org picker; it's validated to be
    one of the user's memberships and passed back to the CLI so it lands on the RIGHT team instead of
    guessing (`_pick_active_org`)."""
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="cross-origin approve rejected")
    if not _LOGIN_ID_RE.fullmatch(body.login_id or ""):
        raise HTTPException(status_code=400, detail="bad login_id")
    user = await _user_from_session(treg_session, db)
    if user is None:
        raise HTTPException(status_code=401, detail="no session")
    # The pairing code proves the approver is the same person who ran `treg login` (the code is shown only
    # in that terminal, via POST /auth/cli/start). Validate it HERE — where we have a session + a same-
    # origin check — so a phished /login?cli=<attacker_id> link (whose code the victim doesn't have) can
    # never complete, a mistyped code fails immediately in the browser, and the poll endpoint stays codeless.
    pending = _cli_pending.get(body.login_id)
    if pending is None:
        raise HTTPException(status_code=400, detail="this login has expired — run `treg login` again")
    expected, tries_left, started_at = pending
    typed = _norm_pair_code(body.code)
    if not typed or not hmac.compare_digest(expected.encode(), typed.encode()):
        if tries_left <= 1:  # out of attempts → discard the pending login so the code can't be ground down
            _cli_pending.pop(body.login_id, None)
            raise HTTPException(status_code=400, detail="too many wrong codes — run `treg login` again")
        _cli_pending[body.login_id] = (expected, tries_left - 1, started_at)
        raise HTTPException(status_code=400, detail="that code doesn't match the one in your terminal")
    active_org: str | None = None
    if body.org:
        org = await _resolve_org(body.org, db)
        m = (await db.execute(select(Membership).where(
            Membership.user_id == user.id, Membership.org_id == org.id))).scalar_one_or_none() if org else None
        if org is None or m is None:
            raise HTTPException(status_code=403, detail="not a member of that team")
        active_org = org.slug
    _cli_pending.pop(body.login_id, None)  # code matched → consume the pending login
    result = {"token": sess.make(user.id, CLI_TOKEN_TTL, user.token_version), "email": user.email}
    if active_org:
        result["active_org"] = active_org
    _cli_results[body.login_id] = (result, _utcnow_naive())
    return {"ok": True, "email": user.email, "active_org": active_org}


@app.get("/login", include_in_schema=False)
async def login_page(cli: str = "", treg_session: str = Cookie(default=""), db: AsyncSession = Depends(get_session)):
    """The universal sign-in page `treg login` opens: reuses an existing dashboard session with one
    click ("Continue as …"), else offers every configured door — GitHub, Google, email one-time code.
    The email door is always present, so login works even with no OAuth app configured."""
    if not cli:
        return RedirectResponse("/app", status_code=302)  # a bare visit belongs on the dashboard
    if not _LOGIN_ID_RE.fullmatch(cli):
        return _auth_page("Login failed", "Bad login link. Run <code>treg login</code> again.", ok=False, status=400)
    s = get_settings()
    user = await _user_from_session(treg_session, db)
    return HTMLResponse(_login_page_html(
        cli, session_email=user.email if user else None,
        github=bool(s.github_client_id), google=bool(s.google_client_id)))


def _login_page_html(login_id: str, *, session_email: str | None, github: bool, google: bool) -> str:
    """Server-rendered /login card. login_id is whitelist-validated by the caller; the session email
    is HTML-escaped (it's the only other interpolated value)."""
    from html import escape

    # A pairing-code block sits above everything: whichever door the user takes, approve() won't complete
    # the CLI handshake until the code shown in their own terminal is echoed back (phishing guard — a
    # login they didn't start has no matching code). A `treg login` link carries the code in the URL
    # fragment, so the JS swaps this input for a read-only display the user just visually confirms;
    # the typed input remains the fallback for links without one. #orgpick is ALWAYS present (filled by loadOrgs when a
    # session exists at load, and after the email door signs in). #doors holds the sign-in options; the
    # divider only shows when a session pre-exists.
    parts: list[str] = [
        '<div id="pcbox"><div class="pklabel">Enter the code shown in your terminal:</div>'
        '<input id="paircode" autocomplete="off" autocapitalize="characters" spellcheck="false" '
        'inputmode="latin" placeholder="e.g. 7F3K" maxlength="9"></div>',
        '<div id="orgpick"></div>',
    ]
    # With a live session the doors are noise — the user is one click from done. Collapse them behind
    # the divider (an accordion); a click expands. No session → no divider, doors always visible.
    if session_email:
        parts.append('<div class="div acc" id="other-acct" onclick="toggleDoors()" role="button" tabindex="0" '
                     'onkeydown="if(event.key===\'Enter\')toggleDoors()">'
                     'use a different account <span id="acc-caret">▸</span></div>')
    doors: list[str] = []
    if github:
        doors.append(f'<a class="btn" href="/auth/github?cli={login_id}">Sign in with GitHub</a>')
    if google:
        doors.append(f'<a class="btn" href="/auth/google?cli={login_id}">Sign in with Google</a>')
    doors.append(
        '<div id="email-door">'
        '<div id="email-row"><input id="em" type="email" placeholder="you@company.com" autocomplete="email">'
        '<button class="btn" onclick="sendCode()">Email me a code</button></div>'
        '<div id="code-row" style="display:none"><input id="code" inputmode="numeric" placeholder="6-digit code">'
        '<button class="btn primary" onclick="verifyCode()">Verify</button></div>'
        '<div class="hint" id="hint"></div></div>')
    doors_style = ' style="display:none"' if session_email else ''
    parts.append(f'<div id="doors" class="stack"{doors_style}>{"".join(doors)}</div>')
    has_session = "true" if session_email else "false"
    return (
        f"{_AUTH_HEAD.replace('</style>', _LOGIN_CSS + '</style>')}"
        f'<body><div class="wrap"><div class="card" id="card">'
        f'<div class="logo">▚ tools-registry</div><h1>Sign in</h1>'
        f'<p>to connect the <b>treg</b> CLI to your account</p>'
        f'<div class="stack">{"".join(parts)}</div><div class="err" id="err"></div>'
        f"</div></div>"
        f"<script>const HAS_SESSION={has_session};{_LOGIN_JS.replace('__LOGIN_ID__', login_id)}</script></body></html>"
    )


_LOGIN_CSS = (
    ".btn{display:block;width:100%;box-sizing:border-box;padding:11px 14px;border-radius:9px;"
    "border:1px solid var(--line);background:#332d23;color:var(--ink);font-family:var(--mono);"
    "font-size:13.5px;cursor:pointer;text-decoration:none;text-align:center}"
    ".btn:hover{border-color:var(--accent)}"
    ".btn.primary{background:var(--accent);border-color:var(--accent);color:#211d16;font-weight:700}"
    ".stack{display:flex;flex-direction:column;gap:10px;margin-top:18px}"
    ".stack>div{display:flex;flex-direction:column;gap:10px}"
    ".div{display:flex;flex-direction:row!important;align-items:center;gap:10px;color:var(--muted);font-size:12px;margin:6px 0 0}"
    ".div:before,.div:after{content:'';flex:1;border-top:1px solid var(--line)}"
    ".div.acc{cursor:pointer;user-select:none}.div.acc:hover{color:var(--ink)}"
    "#email-row,#code-row{display:flex;flex-direction:column;gap:10px}"
    "input{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:9px;border:1px solid var(--line);"
    "background:#1c1913;color:var(--ink);font-family:var(--mono);font-size:13.5px}"
    ".err{color:#d78f6c;font-size:12.5px;margin-top:10px;min-height:1em}"
    ".hint{color:var(--muted);font-size:12px}"
    ".muted{color:var(--muted)}"
    ".team{display:flex;justify-content:space-between;align-items:center;gap:10px;text-align:left}"
    ".team .tn{display:flex;flex-direction:column;gap:2px;min-width:0}"
    ".team .tnm{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}"
    ".team .tm{font-size:11px;color:var(--muted)}"
    ".team.primary .tm{color:#211d16;opacity:.8}"
    ".pklabel{font-size:12px;color:var(--muted);margin:2px 0 2px}"
    "#paircode-show{font-size:22px;font-weight:700;letter-spacing:8px;text-align:center;color:var(--accent);"
    "padding:10px 12px 10px 20px;border:1px dashed var(--line);border-radius:9px;background:#1c1913}"
)

# The page's whole brain: every door funnels into approve(), which completes the CLI handshake.
# done() builds DOM via textContent (the email came over JSON — never trust it into innerHTML).
_LOGIN_JS = """
const LID='__LOGIN_ID__';
// `treg login` puts the pairing code in the URL FRAGMENT (#code=…) — it never reaches the server on
// the GET. When present, show it read-only for a visual match against the terminal instead of making
// the user type it; approve() still sends it for full server-side validation. No fragment (an old CLI,
// or a link someone stripped it from) → the typed-input fallback below stays.
const PAIR=(()=>{const m=/[#&]code=([A-Za-z0-9-]{1,16})/.exec(location.hash||'');return m?m[1].toUpperCase():''})();
if(PAIR){const box=document.getElementById('pcbox');if(box){box.innerHTML='';
 const l=document.createElement('div');l.className='pklabel';l.textContent='Check this code matches your terminal:';box.appendChild(l);
 const c=document.createElement('div');c.id='paircode-show';c.textContent=PAIR;box.appendChild(c);}}
const pairCode=()=>PAIR||((document.getElementById('paircode')||{}).value||'');
// Signed-in users see the doors collapsed behind the "use a different account" divider.
function toggleDoors(){const d=document.getElementById('doors');if(!d)return;
 const open=d.style.display==='none';d.style.display=open?'':'none';
 const c=document.getElementById('acc-caret');if(c)c.textContent=open?'\\u25be':'\\u25b8'}
const err=m=>{document.getElementById('err').textContent=m||''};
async function post(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
 let d={};try{d=await r.json()}catch(e){}
 if(!r.ok)throw new Error(d.detail||('error '+r.status));return d}
function done(email){const c=document.getElementById('card');c.innerHTML='';
 const mk=(t,cls,txt)=>{const e=document.createElement(t);if(cls)e.className=cls;if(txt)e.textContent=txt;c.appendChild(e);return e};
 mk('div','logo','\\u259a tools-registry');mk('div','mark','\\u2705');
 mk('h1',null,email?('Logged in as '+email):'Logged in');
 mk('p',null,'Return to your terminal. The CLI is finishing up.');
 // Don't strand the tab: the approve() above set a session cookie, so /app works. Count down to
 // Getting started, but let a click beat the clock — and a second click on "stay" cancel it.
 const row=mk('p','hint','');let left=10;
 const go=document.createElement('a');go.href='/app#start';go.textContent='Open Getting started now \\u2192';
 go.style.color='var(--accent)';row.appendChild(go);
 const cnt=document.createElement('span');row.appendChild(cnt);
 const stay=document.createElement('a');stay.href='#';stay.textContent='stay here';stay.className='muted';
 stay.style.marginLeft='8px';stay.style.textDecoration='underline';row.appendChild(stay);
 const tick=()=>{cnt.textContent=' \\u00b7 auto in '+left+'s \\u00b7 '};tick();
 const timer=setInterval(()=>{left--;if(left<=0){clearInterval(timer);location.href='/app#start'}else tick()},1000);
 stay.onclick=e=>{e.preventDefault();clearInterval(timer);row.textContent='';
  const a=document.createElement('a');a.href='/app#start';a.textContent='Open Getting started \\u2192';
  a.style.color='var(--accent)';row.appendChild(a)}}
async function approve(org){err('');
 const pc=pairCode();
 if(!pc.trim()){err('Enter the code shown in your terminal to continue.');const el=document.getElementById('paircode');if(el)el.focus();return}
 try{const b={login_id:LID,code:pc};if(org)b.org=org;const d=await post('/auth/cli/approve',b);done(d.email)}catch(e){err(e.message)}}
let CREATED_ORG=null;  // remember a just-created team so a retry (e.g. after a wrong code) reuses it, never makes a 2nd
async function createTeam(){err('');
 const pc=pairCode();
 if(!pc.trim()){err('Enter the code shown in your terminal to continue.');const el=document.getElementById('paircode');if(el)el.focus();return}
 const inp=document.getElementById('newteam');const name=(inp&&inp.value||'').trim();if(!name)return err('give your team a name');
 try{if(!CREATED_ORG){const o=await post('/orgs',{name:name});CREATED_ORG=o.org;}await approve(CREATED_ORG);}catch(e){err(e.message)}}
// Render the team picker into #orgpick once a session exists (fetched, so it also runs after the
// email door signs in). One team → a single "Continue as" button; many → a labelled list.
async function loadOrgs(){const box=document.getElementById('orgpick');if(!box)return;
 let d;try{d=await(await fetch('/auth/cli/orgs',{credentials:'include'})).json()}catch(e){return}
 const orgs=d.orgs||[];box.innerHTML='';
 if(!orgs.length){  // brand-new user: no team yet → make them NAME one (never finish the CLI login team-less)
  const l=document.createElement('div');l.className='pklabel';l.textContent='Name your team to finish signing in'+(d.email?(' ('+d.email+')'):'')+':';box.appendChild(l);
  const inp=document.createElement('input');inp.id='newteam';inp.placeholder='Team name, e.g. Superdesign';inp.autocomplete='off';box.appendChild(inp);
  const b=document.createElement('button');b.className='btn primary';b.textContent='Create team \\u2192';b.onclick=createTeam;box.appendChild(b);
  inp.addEventListener('keyup',e=>{if(e.key==='Enter')createTeam()});inp.focus();return}
 if(orgs.length>1){const l=document.createElement('div');l.className='pklabel';l.textContent='Continue as '+d.email+' — pick a team:';box.appendChild(l)}
 orgs.forEach((o,i)=>{const b=document.createElement('button');b.className='btn team'+((i===0&&orgs.length>1)?' primary':'');b.onclick=()=>approve(o.slug);
  const tn=document.createElement('div');tn.className='tn';
  const nm=document.createElement('div');nm.className='tnm';nm.textContent=o.name+(o.personal?' (personal)':'');
  const mt=document.createElement('div');mt.className='tm';mt.textContent=o.role+' · '+o.tool_count+' tool'+(o.tool_count===1?'':'s');
  tn.appendChild(nm);tn.appendChild(mt);b.appendChild(tn);
  if(orgs.length===1){const c=document.createElement('span');c.textContent='→';b.appendChild(c)}
  box.appendChild(b)});
 if(orgs.length===1){box.firstChild.classList.add('primary')}}
async function sendCode(){err('');const em=document.getElementById('em').value.trim();if(!em)return err('enter your email');
 try{const d=await post('/auth/email/start',{email:em});
  document.getElementById('code-row').style.display='';
  document.getElementById('hint').textContent=d.dev_code?('dev code: '+d.dev_code):('code sent to '+d.email);
 }catch(e){err(e.message)}}
async function verifyCode(){err('');const em=document.getElementById('em').value.trim(),co=document.getElementById('code').value.trim();
 if(!co)return err('enter the code');
 try{await post('/auth/email/verify',{email:em,code:co});
  // The email door just set a session cookie — hide the doors and show the team picker.
  const d=document.getElementById('doors');if(d)d.style.display='none';
  const o=document.getElementById('other-acct');if(o)o.style.display='none';
  await loadOrgs();
 }catch(e){err(e.message)}}
if(HAS_SESSION)loadOrgs();
"""
