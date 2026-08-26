"""Secret, tool, skill, and bundle HTTP routes."""

import json
import sys
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import crypto, health, injectors, localrun, sandbox as demo_sandbox
from .. import providers as _providers
from ..config import get_settings
from ..db import get_session
from ..domain.identity.access import (
    Caller,
    _can_manage,
    _require_can_register,
    _role_at_least,
    require_member,
)
from ..models import Bundle, Secret, Tool
from .orgs import _resolve_project


# The app alias preserves the moved handlers' original decorator text byte-for-byte.
app = APIRouter()
crud_router = app

# Moved helpers retain their api.py-relative provider import while Stage 3 preserves source bytes.
sys.modules.setdefault("treg.routers.providers", _providers)


class SecretIn(BaseModel):
    name: str
    value: str
    kind: str = "env"
    bundle_id: int | None = None


class SecretUpdate(BaseModel):
    name: str | None = None
    value: str | None = None
    kind: str | None = None


async def _visible_secret_ids(caller: Caller, db: AsyncSession) -> set[int] | None:
    """The secret ids a tool-restricted member may SEE: the ones wired into their allowed tools
    (HTTP bindings + cli.inject). None = unrestricted (owner / NULL tool_access) — show all. The
    ACL isn't just a call gate: listings must not reveal credentials the member can't use."""
    if caller.role == "owner" or caller.membership.tool_access is None:
        return None
    tools = (await db.execute(select(Tool).where(Tool.org_id == caller.org_id))).scalars().all()
    ids: set[int] = set()
    for t in tools:
        if not _tool_usable(caller, t):
            continue
        ids |= {b.get("secret_id") for b in (t.bindings or []) if b.get("secret_id") is not None}
        ids |= {e.get("secret_id") for e in ((t.cli or {}).get("inject") or []) if e.get("secret_id") is not None}
    return ids


@app.post("/secrets")
async def create_secret(
    body: SecretIn, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    _require_can_register(caller)
    await _enforce_sandbox_cap(caller, Secret, demo_sandbox.MAX_SECRETS, "secrets", db)
    await _validate_bundle_id(body.bundle_id, caller.org_id, db)
    secret = Secret(
        org_id=caller.org_id, name=body.name, owner=caller.email, kind=body.kind,
        value=crypto.encrypt(body.value), bundle_id=body.bundle_id,
    )
    db.add(secret)
    await db.commit()
    return _secret_view(secret)


@app.get("/secrets")
async def list_secrets(
    caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (await db.execute(select(Secret).where(Secret.org_id == caller.org_id))).scalars().all()
    visible = await _visible_secret_ids(caller, db)
    if visible is not None:  # tool-restricted member: only the keys wired into their allowed tools
        rows = [s for s in rows if s.id in visible]
    return [_secret_view(s) for s in rows]


@app.patch("/secrets/{secret_id}")
async def update_secret(
    secret_id: int,
    body: SecretUpdate,
    caller: Caller = Depends(require_member),
    db: AsyncSession = Depends(get_session),
) -> dict:
    secret = await db.get(Secret, secret_id)
    if secret is None or secret.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="secret not found")
    if not _can_manage(caller, secret):
        raise HTTPException(status_code=403, detail="only the creator or an admin can edit this secret")
    _require_not_live_demo_secret(caller, secret)
    fields = body.model_dump(exclude_unset=True)
    for k in ("name", "value", "kind"):  # these map to NOT-NULL columns; explicit null is a 422, not a 500
        if k in fields and fields[k] is None:
            raise HTTPException(status_code=422, detail=f"{k} cannot be null")
    # A kind change drives refresh + health + extraction shape; validate a JSON-kind actually has a
    # JSON value (else the tool silently 502s later) and reset the now-meaningless health verdict.
    if "kind" in fields and fields["kind"] != secret.kind:
        if fields["kind"] in ("oauth", "secret_file"):
            raw = fields["value"] if "value" in fields else crypto.decrypt(secret.value)
            try:
                json.loads(raw)
            except (ValueError, TypeError):
                raise HTTPException(status_code=422, detail=f"kind {fields['kind']!r} needs a JSON value")
        secret.health_status, secret.health_detail, secret.health_checked_at = "unknown", "", None
    if "value" in fields:
        fields["value"] = crypto.encrypt(fields["value"])  # re-encrypt on rotate
        # The value is exactly what health measures — a rotation invalidates the prior verdict.
        secret.health_status, secret.health_detail, secret.health_checked_at = "unknown", "", None
    for k, v in fields.items():
        setattr(secret, k, v)
    await db.commit()
    return _secret_view(secret)


@app.delete("/secrets/{secret_id}")
async def delete_secret(
    secret_id: int, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    secret = await db.get(Secret, secret_id)
    if secret is None or secret.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="secret not found")
    if not _can_manage(caller, secret):
        raise HTTPException(status_code=403, detail="only the creator or an admin can delete this secret")
    _require_not_live_demo_secret(caller, secret)
    # bindings live in a JSON column — scan tools IN THIS ORG (registry-scale N is small).
    tools = (await db.execute(select(Tool).where(Tool.org_id == caller.org_id))).scalars().all()
    if any(b.get("secret_id") == secret_id for t in tools for b in t.bindings):
        raise HTTPException(status_code=409, detail="secret is referenced by a tool binding")
    # a secret used only by a local-run inject (not an HTTP binding) would otherwise be silently
    # deletable, breaking `treg run` — guard those references too.
    if any((e.get("secret_id") == secret_id) for t in tools for e in ((t.cli or {}).get("inject") or [])):
        raise HTTPException(status_code=409, detail="secret is referenced by a tool's local-run (cli) profile")
    await db.delete(secret)
    await db.commit()
    return {"deleted": secret_id}


def _require_not_live_demo_secret(caller: Caller, secret: Secret) -> None:
    """Companion guard for the seeded STRIPE_KEY the live tool is bound to."""
    if (demo_sandbox.is_sandbox(caller.org) and get_settings().demo_stripe_key
            and secret.name == "STRIPE_KEY"):
        raise HTTPException(status_code=403, detail=(
            "STRIPE_KEY powers the live stripe demo — add your own keys instead"))


async def _validate_bundle_id(bundle_id: int | None, org_id: int, db: AsyncSession) -> None:
    """A resource may only attach to a bundle in its OWN org — else it'd be counted by, rendered in,
    and swept up by a foreign org's bundle view/delete (org-scoping leak)."""
    if bundle_id is None:
        return
    bundle = await db.get(Bundle, bundle_id)
    if bundle is None or bundle.org_id != org_id:
        raise HTTPException(status_code=422, detail=f"bundle_id {bundle_id} not found in this org")


def _secret_view(s: Secret) -> dict:
    return {"id": s.id, "name": s.name, "kind": s.kind, "owner": s.owner, "bundle_id": s.bundle_id}


class ToolIn(BaseModel):
    name: str
    base_url: str
    bundle_id: int | None = None
    # Multi-binding (explicit) — each: {secret_id, injector, location, name, format, secret_field}
    bindings: list[dict] | None = None
    # Single-binding sugar (the common case): provide secret_id + placement, get one binding.
    secret_id: int | None = None
    injector: str = "env"
    auth_in: str = "header"
    auth_name: str = "Authorization"
    auth_format: str = "Bearer {secret}"
    secret_field: str = "access_token"
    health_check: dict | None = None  # {method, path, expect_status}
    examples: list[dict] | None = None  # [{method, path, note}]
    cli: dict | None = None  # local-run profile for `treg run` (docs/CLI-RUN-PLAN.md)
    project: str | int | None = None  # project slug or id; None = org-wide (the default)


class ToolUpdate(BaseModel):
    base_url: str | None = None
    bindings: list[dict] | None = None
    health_check: dict | None = None
    examples: list[dict] | None = None
    cli: dict | None = None  # set/replace the local-run profile; explicit null clears it
    project: str | int | None = None  # move between projects; explicit null makes it org-wide


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except ValueError:  # e.g. unbalanced IPv6 brackets "http://[::1" → don't 500, reject the input
        raise HTTPException(status_code=422, detail="base_url is not a valid URL")


def _normalize_scheme(rest: str) -> str:
    """A path param collapses `https://` to `https:/`; restore it."""
    for sch in ("https:/", "http:/"):
        if rest.startswith(sch) and not rest.startswith(sch + "/"):
            return sch + "/" + rest[len(sch):]
    return rest


def _flat_binding(body: ToolIn) -> dict:
    return {
        "secret_id": body.secret_id,
        "injector": body.injector,
        "location": body.auth_in,
        "name": body.auth_name,
        "format": body.auth_format,
        "secret_field": body.secret_field,
    }


def _require_not_live_demo_tool(caller: Caller, tool: Tool) -> None:
    """The sandbox's seeded live-wire tool (`stripe`, pinned base) is the demo's centerpiece —
    editing or removing it would break the visitor's own live pane, so refuse. Only the seeded
    name is frozen; visitor-created tools stay fully editable. No-op outside sandboxes / with
    the wire off."""
    if (demo_sandbox.is_sandbox(caller.org) and get_settings().demo_stripe_key
            and tool.name == "stripe" and demo_sandbox.is_live_tool(tool)):
        raise HTTPException(status_code=403, detail=(
            "the live stripe demo endpoint is part of the sandbox — add your own endpoints instead"))


def _require_public_base_url(base_url: str) -> None:
    """A tool's base_url is fetched server-side by the proxy — reject internal / loopback / cloud-metadata
    targets so a member can't turn `treg call` into an SSRF (e.g. base_url=169.254.169.254). Reuses the
    same block-list the webhook path already uses. DNS names are allowed (best-effort)."""
    if not health.safe_webhook_url(base_url):
        raise HTTPException(status_code=422, detail=(
            "base_url must be a public http(s) address — loopback, private, link-local, and cloud-"
            "metadata hosts are refused"))


async def _require_secret_ownership(secret: Secret, caller: Caller) -> None:
    """A member may bind/inject only a secret they OWN; admins/owners may use any team secret (they set
    up shared tools). Without this, a member could attach a teammate's key to a tool they control and
    exfiltrate it — via the proxy (an attacker `base_url`) or `/grant` on a local-run tool."""
    if not (secret.owner == caller.email or _role_at_least(caller.role, "admin")):
        raise HTTPException(
            status_code=403,
            detail=f"you can only bind a secret you own — secret {secret.id} belongs to another member "
                   "(ask an org admin to wire up a shared-key tool)")


async def _validate_bindings(bindings: list[dict], caller: Caller, db: AsyncSession,
                             grandfather: frozenset = frozenset()) -> None:
    org_id = caller.org_id
    for b in bindings:
        # A `platform_setting` binding injects one of TREG's own credentials (a tier-4 provider key, the
        # Google Ads developer token) — relay resolves it from settings and never looks at secret_id, so
        # a caller-supplied one would be a straight read of our key through any tool they register.
        # Only the server builds these (_provider_bindings / _platform_bindings); user input never may.
        if b.get("platform_setting"):
            raise HTTPException(status_code=422, detail=(
                "a binding may not name a platform_setting — treg's own credentials are server-managed "
                "(they are attached by `connections connect`, or injected by the marketplace ladder)"))
        injector = b.get("injector", "env")
        if injector not in injectors.INJECTORS:  # unknown injector 500s the proxy at call time — reject now
            raise HTTPException(status_code=422, detail=f"unknown injector {injector!r}")
        fmt = b.get("format", "{secret}")  # rendered as fmt.format(secret=…) on the hot path
        if not isinstance(fmt, str):
            raise HTTPException(status_code=422, detail="binding format must be a string")
        try:
            fmt.format(secret="x")  # an unexpected placeholder / literal brace would KeyError/ValueError → 500
        except (KeyError, IndexError, ValueError):
            raise HTTPException(status_code=422, detail=f"invalid binding format {fmt!r} — use only {{secret}}")
        # name/secret_field, if present, feed httpx header/param setters and the JSON extractor —
        # a null or non-string there AttributeErrors on the hot path; location must be header|query.
        for key in ("name", "secret_field"):
            if key in b and not (isinstance(b[key], str) and b[key]):
                raise HTTPException(status_code=422, detail=f"binding {key} must be a non-empty string")
        loc = b.get("location", "header")
        if loc not in ("header", "query"):
            raise HTTPException(status_code=422, detail="binding location must be 'header' or 'query'")
        sid = b.get("secret_id")
        secret = await db.get(Secret, sid) if sid is not None else None
        if secret is None or secret.org_id != org_id:
            raise HTTPException(status_code=422, detail=f"binding secret_id {sid} not found")
        if sid not in grandfather:  # a binding already on the tool is grandfathered (don't lock the owner out on edit)
            await _require_secret_ownership(secret, caller)  # can't ADD a teammate's secret
    # Two bindings with the same target name silently overwrite each other at call time (the first
    # credential is dropped) — reject the collision at registration, for BOTH query and header
    # (header names are case-insensitive; `httpx.Headers[name]=…` overwrites just like a query param).
    qnames = [b.get("name", "Authorization") for b in bindings if b.get("location", "header") == "query"]
    qdupes = sorted({n for n in qnames if qnames.count(n) > 1})
    if qdupes:
        raise HTTPException(status_code=422, detail=f"duplicate query binding name(s): {qdupes}")
    hnames = [b.get("name", "Authorization").lower() for b in bindings if b.get("location", "header") == "header"]
    hdupes = sorted({n for n in hnames if hnames.count(n) > 1})
    if hdupes:
        raise HTTPException(status_code=422, detail=f"duplicate header binding name(s): {hdupes}")


def _validate_cli_profile(cli: dict | None) -> None:
    """422 (not a write-through) for a malformed local-run profile — a bad deny regex or inject shape
    must fail HERE, never at grant time (localrun.check_deny skips uncompilable legacy patterns)."""
    if cli is None:
        return
    try:
        localrun.validate_cli_profile(cli)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


async def _validate_cli_secrets(cli: dict | None, caller: Caller, db: AsyncSession,
                                grandfather: frozenset = frozenset()) -> None:
    """Ownership check for secrets a cli.inject entry names by secret_id — same rule as bindings, so a
    member can't launder a teammate's secret into a local-run tool and extract it via /grant."""
    if not cli:
        return
    for e in cli.get("inject") or []:
        sid = e.get("secret_id")
        if sid is None:
            continue
        secret = await db.get(Secret, sid)
        if secret is None or secret.org_id != caller.org_id:
            raise HTTPException(status_code=422, detail=f"cli.inject secret_id {sid} not found")
        if sid not in grandfather:
            await _require_secret_ownership(secret, caller)


def _allowed_server_bins() -> set[str]:
    """The commands `treg run --server` may execute: catalog-known CLIs + an admin allow-list. Blocks a
    member naming `bash`/`python` to run arbitrary code as the server user (docs/CLI-RUN-PLAN.md Option A)."""
    from . import providers as prov
    bins = {(e.get("cli") or {}).get("bin") for e in prov.CATALOG}
    bins.discard(None)
    extra = get_settings().run_allowed_bins
    bins |= {b.strip() for b in extra.split(",") if b.strip()}
    return bins  # type: ignore[return-value]


@app.post("/tools")
async def create_tool(
    body: ToolIn, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    _require_can_register(caller)
    await _enforce_sandbox_cap(caller, Tool, demo_sandbox.MAX_TOOLS, "endpoints", db)
    if body.bindings is not None:
        bindings = body.bindings
    elif body.secret_id is not None:
        bindings = [_flat_binding(body)]
    else:
        bindings = []  # a public upstream needing no credential is allowed
    _require_public_base_url(body.base_url)  # no SSRF to internal/metadata hosts via the proxy
    await _validate_bindings(bindings, caller, db)
    await _validate_bundle_id(body.bundle_id, caller.org_id, db)
    _validate_cli_profile(body.cli)
    await _validate_cli_secrets(body.cli, caller, db)
    project = await _resolve_project(body.project, caller.org_id, db)
    tool = Tool(
        org_id=caller.org_id, name=body.name, owner=caller.email, base_url=body.base_url,
        host=_host_of(body.base_url), bindings=bindings, health_check=body.health_check,
        examples=body.examples or [], cli=body.cli, bundle_id=body.bundle_id,
        project_id=project.id if project else None,
    )
    db.add(tool)
    try:
        await db.commit()
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"tool name {body.name!r} already exists in this org")
    return _tool_view(tool)


@app.get("/tools")
async def list_tools(
    caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (await db.execute(select(Tool).where(Tool.org_id == caller.org_id))).scalars().all()
    # The per-member tool ACL hides what it gates: a restricted member's listing shows only their tools.
    return [_tool_view(t) for t in rows if _tool_usable(caller, t)]


@app.get("/tools/by-name/{name}")
async def get_tool_by_name(
    name: str, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    """Name-keyed lookup so shareable detail URLs (/app/tools/<name>) resolve without an id."""
    tool = (await db.execute(
        select(Tool).where(Tool.org_id == caller.org_id, Tool.name == name)
    )).scalars().first()
    if tool is None:
        raise HTTPException(status_code=404, detail="tool not found")
    _require_tool_use(caller, tool)  # a 403 names the fix (ask an admin) — clearer than a fake 404
    return _tool_view(tool)


@app.patch("/tools/{tool_id}")
async def update_tool(
    tool_id: int,
    body: ToolUpdate,
    caller: Caller = Depends(require_member),
    db: AsyncSession = Depends(get_session),
) -> dict:
    tool = await db.get(Tool, tool_id)
    if tool is None or tool.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="tool not found")
    if not _can_manage(caller, tool):
        raise HTTPException(status_code=403, detail="only the creator or an admin can edit this tool")
    _require_not_live_demo_tool(caller, tool)
    fields = body.model_dump(exclude_unset=True)
    if "base_url" in fields and fields["base_url"] is None:  # NOT-NULL column + feeds _host_of — 422, not 500
        raise HTTPException(status_code=422, detail="base_url cannot be null")
    if fields.get("base_url"):
        _require_public_base_url(fields["base_url"])  # no SSRF to internal/metadata hosts
    # Secrets ALREADY on the tool are grandfathered on edit — only a NEWLY-added binding/inject must be
    # owned by the caller. Otherwise re-saving a tool an admin wired with a shared key locks its owner out.
    grandfather = frozenset(
        {b.get("secret_id") for b in tool.bindings if b.get("secret_id") is not None}
        | {e.get("secret_id") for e in ((tool.cli or {}).get("inject") or []) if e.get("secret_id") is not None}
    )
    if "bindings" in fields:
        await _validate_bindings(fields["bindings"], caller, db, grandfather)
    if "cli" in fields:  # explicit null clears the profile (turns local runs off entirely)
        _validate_cli_profile(fields["cli"])
        await _validate_cli_secrets(fields["cli"], caller, db, grandfather)
    if "project" in fields:  # slug/id in, column out; explicit null = back to org-wide
        project = await _resolve_project(fields.pop("project"), caller.org_id, db)
        tool.project_id = project.id if project else None
    for k, v in fields.items():
        setattr(tool, k, v)
    if "base_url" in fields:
        tool.host = _host_of(tool.base_url)  # keep the resolution index in sync
    await db.commit()
    return _tool_view(tool)


@app.delete("/tools/{tool_id}")
async def delete_tool(
    tool_id: int, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    tool = await db.get(Tool, tool_id)
    if tool is None or tool.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="tool not found")
    if not _can_manage(caller, tool):
        raise HTTPException(status_code=403, detail="only the creator or an admin can delete this tool")
    _require_not_live_demo_tool(caller, tool)
    await db.delete(tool)
    await db.commit()
    return {"deleted": tool_id}


def _tool_view(t: Tool) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "owner": t.owner,
        "base_url": t.base_url,
        "host": t.host,
        "bindings": t.bindings,
        "health_check": t.health_check,
        "examples": t.examples or [],
        "cli": t.cli,
        # Server-computed so the dashboard never guesses: a run needs a cli profile, an allow-listed bin
        # (server config the client can't see), AND a server-injectable auth mechanism — a config_file /
        # device CLI authenticates from the member's own machine, so it's local-only (default "env" keeps
        # every pre-auth_mechanism tool server-runnable as before).
        "server_runnable": (bool(t.cli) and (t.cli.get("bin") or t.name) in _allowed_server_bins()
                            and (t.cli.get("auth_mechanism") or "env") in ("env", "argv")),
        "project_id": t.project_id,  # None = org-wide
        "bundle_id": t.bundle_id,
    }
