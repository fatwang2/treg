"""Secret, tool, skill, and bundle HTTP routes."""

import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import convert as _convert
from .. import crypto, health, injectors, localrun, sandbox as demo_sandbox
from .. import db as _db
from .. import providers as _providers
from .. import skills as _skills
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
sys.modules.setdefault("treg.routers.convert", _convert)
sys.modules.setdefault("treg.routers.skills", _skills)
sys.modules.setdefault("treg.routers.db", _db)


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


class BundleUpdate(BaseModel):
    recipe: str | None = None  # edit the SKILL.md text of a recipe/skill bundle
    # (Run metadata moved to Tool.cli — a tool with a cli profile is runnable.)


class SkillSecretIn(BaseModel):
    local_name: str  # name within the skill; bindings reference it by this
    value: str
    kind: str = "env"


class SkillToolIn(BaseModel):
    name: str
    base_url: str
    bindings: list[dict] = []  # each binding's "secret" is a local_name, resolved server-side
    health_check: dict | None = None  # optional {method, path, expect_status}
    examples: list[dict] = []  # optional [{method, path, note}]
    cli: dict | None = None  # optional local-run profile; inject entries may reference local_names


class SkillIn(BaseModel):
    name: str
    recipe: str = ""  # the SKILL.md text
    files: dict[str, str] = {}  # companion files {relpath: content} — the rest of the skill folder
    secrets: list[SkillSecretIn] = []
    tools: list[SkillToolIn] = []
    # (Execution config — both run tiers — lives in each tool's `cli` block: bin/server/enabled/inject.)


class SkillFileIn(BaseModel):
    path: str      # the file's path relative to the picked folder (webkitRelativePath)
    content: str


class SkillAnalyzeIn(BaseModel):
    files: list[SkillFileIn] = []


class SkillImportIn(BaseModel):
    files: list[SkillFileIn] = []
    select: list[str] = []           # skill names to register (empty = every ready one)
    env_values: dict[str, str] = {}  # user-filled values for env secrets missing from the upload


# A second router keeps local grant/report between CRUD and skills in the legacy route order.
app = APIRouter()
skill_router = app


@app.post("/skills")
async def register_skill(
    body: SkillIn, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    """Register a skill from a raw payload (recipe + secrets + tools). The dashboard's folder importer
    and the CLI build this same payload; the shared core is `_register_skill_bundle`."""
    return await _register_skill_bundle(body, caller, db)


_SECRET_DIR_RE = re.compile(r"(^|/)\.secrets?(/|$)")


def _sanitize_bundle_files(files: dict) -> dict:
    """Defense-in-depth before persisting companion files (the CLI/dashboard already exclude these):
    drop path-traversal / absolute paths, SKILL.md (that's `recipe`), and anything under a secret dir —
    a secret must NEVER live in the shipped file blob. `skill install` re-checks on the way out too."""
    clean: dict[str, str] = {}
    for raw, content in (files or {}).items():
        p = str(raw).replace("\\", "/")
        if not p or p.startswith("/") or ".." in p.split("/"):   # absolute or traversal → drop
            continue
        if p == "SKILL.md" or _SECRET_DIR_RE.search(p):
            continue
        if not isinstance(content, str):
            continue
        clean[p] = content
    return clean


async def _register_skill_bundle(body: SkillIn, caller: Caller, db: AsyncSession) -> dict:
    _require_can_register(caller)
    if demo_sandbox.is_sandbox(caller.org):  # a skill import would create unlimited tools/secrets, past the cap
        raise HTTPException(status_code=403, detail="skill import is disabled in the sandbox")
    names = [s.local_name for s in body.secrets]  # bindings reference secrets by local_name
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:  # a duplicate would silently orphan the first secret (only the last id is kept)
        raise HTTPException(status_code=422, detail=f"duplicate secret local_name(s): {dupes}")
    files = _sanitize_bundle_files(body.files)  # drop unsafe paths / secrets before persisting
    bundle = Bundle(org_id=caller.org_id, name=body.name, owner=caller.email, recipe=body.recipe, files=files)
    db.add(bundle)
    await db.flush()  # assign bundle.id without committing yet

    local_to_id: dict[str, int] = {}
    for s in body.secrets:
        secret = Secret(
            org_id=caller.org_id, name=s.local_name, owner=caller.email, kind=s.kind,
            value=crypto.encrypt(s.value), bundle_id=bundle.id,
        )
        db.add(secret)
        await db.flush()
        local_to_id[s.local_name] = secret.id

    for t in body.tools:
        _require_public_base_url(t.base_url)  # no SSRF to internal/metadata hosts via an imported skill
        resolved: list[dict] = []
        for raw in t.bindings:
            b = dict(raw)
            local = b.pop("secret", None)  # bindings reference secrets by local_name
            if local is not None:
                if local not in local_to_id:
                    raise HTTPException(status_code=422, detail=f"binding references unknown secret {local!r}")
                b["secret_id"] = local_to_id[local]
            resolved.append(b)
        # Same gate as POST /tools: reject unknown injectors / dangling secret_ids here, or the
        # skill door persists a poison tool (missing secret_id → KeyError → 500 on every call).
        await _validate_bindings(resolved, caller, db)
        cli = dict(t.cli) if t.cli else None
        if cli:  # inject entries reference secrets by local_name too — resolve like bindings
            cli["inject"] = [dict(e) for e in cli.get("inject") or []]
            for e in cli["inject"]:
                local = e.pop("secret", None)
                if local is not None:
                    if local not in local_to_id:
                        raise HTTPException(status_code=422, detail=f"cli.inject references unknown secret {local!r}")
                    e["secret_id"] = local_to_id[local]
            _validate_cli_profile(cli)
            await _validate_cli_secrets(cli, caller, db)  # a raw secret_id in the upload must be owned too
        db.add(Tool(
            org_id=caller.org_id, name=t.name, owner=caller.email, base_url=t.base_url,
            host=_host_of(t.base_url), bindings=resolved, health_check=t.health_check,
            examples=t.examples, cli=cli, bundle_id=bundle.id,
        ))

    try:
        await db.commit()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="a tool name in this skill already exists in this org")
    return await _bundle_view(bundle.id, db)


_SKILL_UPLOAD_MAX_FILES = 600


_SKILL_UPLOAD_MAX_BYTES = 2 * 1024 * 1024  # per file


_SKILL_UPLOAD_MAX_TOTAL_BYTES = 20 * 1024 * 1024  # whole upload — cap BEFORE materializing to disk


def _check_upload_size(files: list) -> None:
    """Reject an oversized folder upload early (before writing anything to disk), so a member can't
    exhaust the server with a huge `/skills/analyze|import` body. Per-file cap still applies later."""
    if len(files) > _SKILL_UPLOAD_MAX_FILES:
        raise HTTPException(status_code=413, detail=f"too many files (max {_SKILL_UPLOAD_MAX_FILES})")
    total = sum(len((getattr(f, "content", "") or "").encode("utf-8", "ignore")) for f in files)
    if total > _SKILL_UPLOAD_MAX_TOTAL_BYTES:
        raise HTTPException(status_code=413, detail="upload too large (max 20 MB total)")


def _materialize_skill_files(files: list) -> str:
    """Write uploaded skill files into a fresh temp dir so the SAME disk-based scanner the CLI uses
    (skills.scan_skills / _classify) can run on them unchanged. Paths are sanitized against traversal;
    the caller must rmtree the returned dir."""
    root = Path(tempfile.mkdtemp(prefix="treg-skill-")).resolve()
    for f in files[:_SKILL_UPLOAD_MAX_FILES]:
        rel = f.path.replace("\\", "/").lstrip("/")
        dest = (root / rel).resolve()
        if root not in dest.parents:      # a '..' path escaping the temp root — drop it
            continue
        if len(f.content.encode("utf-8", "ignore")) > _SKILL_UPLOAD_MAX_BYTES:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_text(f.content)
        except OSError:
            continue
    return str(root)


def _scan_uploaded_skills(root: str, catalog: list, env_names: set) -> list:
    """Find every skill dir (a dir with a SKILL.md) at any depth under root and classify each with the
    CLI's own `skills._classify` — so the dashboard verdict is identical to `treg upload skills`."""
    from . import skills as sk
    dets = []
    for dirpath, _dirs, filenames in os.walk(root):
        if any(m in filenames for m in ("SKILL.md", "skill.md")):
            dets.append(sk._classify(Path(dirpath), catalog, env_names))
    dets.sort(key=lambda d: d.name)
    return dets


@app.post("/skills/analyze")
async def analyze_skill_folder(
    body: SkillAnalyzeIn, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    """Classify an uploaded skill folder WITHOUT registering — the dashboard's verify step. Same
    classifier as `treg upload skills`: recipe-only vs contract vs generated, plus readiness gaps."""
    _require_can_register(caller)
    if demo_sandbox.is_sandbox(caller.org):
        raise HTTPException(status_code=403, detail="skill import is disabled in the sandbox")
    _check_upload_size(body.files)
    from . import providers as prov, convert, skills as sk_mod
    root = _materialize_skill_files(body.files)
    try:
        env_path = Path(root) / ".env"
        env_names = set(prov.var_names(str(env_path))) if env_path.is_file() else set()
        dets = _scan_uploaded_skills(root, prov.CATALOG, env_names)
        existing = {b.name for b in (await db.execute(
            select(Bundle).where(Bundle.org_id == caller.org_id))).scalars().all()}
        out = []
        for d in dets:
            secs = []
            for s in d.secrets:
                if s.get("file"):
                    secs.append({"name": s["name"], "source": "file", "ref": s["file"],
                                 "present": (Path(d.path) / s["file"]).is_file()})
                elif s.get("env"):
                    secs.append({"name": s["name"], "source": "env", "ref": s["env"],
                                 "present": s["env"] in env_names})
            out.append({"name": d.name, "kind": d.kind, "base_url": d.base_url,
                        "secrets": secs, "gaps": d.gaps, "ready": d.ready,
                        "already": d.name in existing,
                        "cli": sk_mod.cli_preview(d, prov.CATALOG),
                        "recipe_chars": len(convert._read_recipe(Path(d.path)))})
        return {"skills": out}
    finally:
        shutil.rmtree(root, ignore_errors=True)


@app.post("/skills/import")
async def import_skill_folder(
    body: SkillImportIn, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    """Register selected skills from an uploaded folder: scan → build the payload (secret VALUES from
    the uploaded files / provided env values) → register each as a bundle. Mirrors `treg upload skills`."""
    _require_can_register(caller)
    if demo_sandbox.is_sandbox(caller.org):
        raise HTTPException(status_code=403, detail="skill import is disabled in the sandbox")
    _check_upload_size(body.files)
    from . import skills as sk, providers as prov
    root = _materialize_skill_files(body.files)
    try:
        env_path = Path(root) / ".env"
        env_names = set(prov.var_names(str(env_path))) if env_path.is_file() else set()
        env_names |= set(body.env_values or {})  # a value the user typed in the dashboard counts as present
        dets = _scan_uploaded_skills(root, prov.CATALOG, env_names)
        want = set(body.select) if body.select else {d.name for d in dets if d.ready}
        chosen = [d for d in dets if d.name in want]
        values: dict[str, str] = {}
        need = sk.env_needs(chosen)
        if need and env_path.is_file():
            values.update(prov.env_values(str(env_path), need))
        values.update(body.env_values or {})
        # Idempotent + crash-proof (like the CLI): skip anything already registered, and never let one
        # skill 500 the whole batch. A name clash on the bundle/tool/secret would otherwise raise an
        # IntegrityError on flush (not on commit, so it escaped the register helper's guard).
        existing_bundles = {b.name for b in (await db.execute(
            select(Bundle).where(Bundle.org_id == caller.org_id))).scalars().all()}
        existing_tools = {t.name for t in (await db.execute(
            select(Tool).where(Tool.org_id == caller.org_id))).scalars().all()}
        existing_secrets = {s.name for s in (await db.execute(
            select(Secret).where(Secret.org_id == caller.org_id))).scalars().all()}
        from .db import session_maker
        results = []
        for d in chosen:
            if d.gaps:
                results.append({"name": d.name, "ok": False, "error": "; ".join(d.gaps)}); continue
            secret_names = {s["name"] for s in d.secrets}
            if d.name in existing_bundles or d.name in existing_tools or (secret_names & existing_secrets):
                results.append({"name": d.name, "ok": False, "skipped": True, "error": "already registered"}); continue
            try:
                payload = sk.build_payload(d, values)
                # Each skill registers in its OWN session so a failure (bad binding, IntegrityError…)
                # can't poison the shared session for the rest of the batch (greenlet_spawn errors).
                async with session_maker() as sk_db:
                    await _register_skill_bundle(SkillIn(**payload), caller, sk_db)
                existing_bundles.add(d.name); existing_tools.add(d.name); existing_secrets |= secret_names
                results.append({"name": d.name, "ok": True, "kind": d.kind})
            except HTTPException as exc:
                results.append({"name": d.name, "ok": False, "error": str(exc.detail)})
            except Exception:  # noqa: BLE001 -- report per-skill, never 500 the batch
                # A generic message — a raw exception string could echo a fragment of an uploaded secret.
                results.append({"name": d.name, "ok": False, "error": "registration failed"})
        return {"results": results}
    finally:
        shutil.rmtree(root, ignore_errors=True)


async def _bundle_allowed(caller: Caller, bundle: Bundle, db: AsyncSession) -> bool:
    """Skill visibility for a tool-restricted member: the access list may grant a bundle by its own
    name (recipe-only skills) or via any of its tools. Owner / NULL access see everything."""
    if caller.role == "owner" or caller.membership.tool_access is None:
        return True
    access = set(caller.membership.tool_access)
    if bundle.name in access:
        return True
    tools = (await db.execute(select(Tool.name).where(Tool.bundle_id == bundle.id))).all()
    return any(r[0] in access for r in tools)


@app.get("/bundles")
async def list_bundles(
    caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (await db.execute(select(Bundle).where(Bundle.org_id == caller.org_id))).scalars().all()
    return [{"id": b.id, "name": b.name, "owner": b.owner}
            for b in rows if await _bundle_allowed(caller, b, db)]


@app.get("/bundles/by-name/{name}")
async def get_bundle_by_name(
    name: str, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    """Name-keyed lookup so shareable detail URLs (/app/skills/<name>) resolve without an id."""
    bundle = (await db.execute(
        select(Bundle).where(Bundle.org_id == caller.org_id, Bundle.name == name)
    )).scalars().first()
    if bundle is None:
        raise HTTPException(status_code=404, detail="bundle not found")
    if not await _bundle_allowed(caller, bundle, db):
        raise HTTPException(status_code=403, detail=(
            f"you don't have access to the skill {name!r} in this team — an admin can grant it"))
    return await _bundle_view(bundle.id, db)


@app.get("/bundles/{bundle_id}")
async def get_bundle(
    bundle_id: int, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    bundle = await db.get(Bundle, bundle_id)
    if bundle is None or bundle.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="bundle not found")
    if not await _bundle_allowed(caller, bundle, db):  # `treg skill install` uses this route too
        raise HTTPException(status_code=403, detail=(
            f"you don't have access to the skill {bundle.name!r} in this team — an admin can grant it"))
    return await _bundle_view(bundle_id, db)


@app.patch("/bundles/{bundle_id}")
async def update_bundle(
    bundle_id: int, body: BundleUpdate,
    caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session),
) -> dict:
    """Edit a bundle's SKILL.md text. Only its creator or an admin may. (Execution config lives on
    the tool's cli profile, not here.)"""
    bundle = await db.get(Bundle, bundle_id)
    if bundle is None or bundle.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="bundle not found")
    if not _can_manage(caller, bundle):
        raise HTTPException(status_code=403, detail="only the creator or an admin can edit this recipe")
    fields = body.model_dump(exclude_unset=True)  # exclude_unset so a field left out is untouched
    if fields.get("recipe") is not None:
        bundle.recipe = fields["recipe"]
    await db.commit()
    return await _bundle_view(bundle_id, db)


@app.delete("/bundles/{bundle_id}")
async def delete_bundle(
    bundle_id: int, caller: Caller = Depends(require_member), db: AsyncSession = Depends(get_session)
) -> dict:
    bundle = await db.get(Bundle, bundle_id)
    if bundle is None or bundle.org_id != caller.org_id:
        raise HTTPException(status_code=404, detail="bundle not found")
    if not _can_manage(caller, bundle):
        raise HTTPException(status_code=403, detail="only the creator or an admin can delete this bundle")
    bundle_tools = (await db.execute(select(Tool).where(Tool.bundle_id == bundle_id))).scalars().all()
    bundle_tool_ids = {t.id for t in bundle_tools}
    bundle_secrets = (await db.execute(select(Secret).where(Secret.bundle_id == bundle_id))).scalars().all()
    # A bundle secret may be bound by a tool OUTSIDE the bundle (use-without-hold). Deleting it would
    # dangle that binding — the same invariant delete_secret guards with a 409, enforced here too.
    org_tools = (await db.execute(select(Tool).where(Tool.org_id == bundle.org_id))).scalars().all()
    outside = [t for t in org_tools if t.id not in bundle_tool_ids]
    # A bundle secret may be referenced by an outside tool's HTTP binding OR its local-run cli.inject —
    # guard BOTH (delete_secret does), else a local-run tool would dangle a missing secret_id.
    referenced = {b.get("secret_id") for t in outside for b in t.bindings}
    referenced |= {e.get("secret_id") for t in outside for e in ((t.cli or {}).get("inject") or [])}
    if any(s.id in referenced for s in bundle_secrets):
        raise HTTPException(status_code=409, detail="a bundle secret is referenced by a tool outside this bundle")
    for t in bundle_tools:
        await db.delete(t)
    for s in bundle_secrets:
        await db.delete(s)
    await db.delete(bundle)
    await db.commit()
    return {"deleted": bundle_id}


async def _bundle_view(bundle_id: int, db: AsyncSession) -> dict:
    bundle = await db.get(Bundle, bundle_id)
    tools = (await db.execute(select(Tool).where(Tool.bundle_id == bundle_id))).scalars().all()
    secrets = (await db.execute(select(Secret).where(Secret.bundle_id == bundle_id))).scalars().all()
    return {
        "id": bundle.id,
        "name": bundle.name,
        "owner": bundle.owner,
        "recipe": bundle.recipe,
        "files": bundle.files or {},   # companion files {relpath: content} — `skill install` writes these
        "tools": [_tool_view(t) for t in tools],
        "secrets": [_secret_view(s) for s in secrets],
    }
