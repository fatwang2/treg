"""Credential connection workflows and transaction boundaries."""

import base64
from dataclasses import dataclass
from datetime import timedelta
import json
import logging
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import catalog_store, crypto, health, oauth, oauth_providers
from ..config import get_settings
from ..db import session_maker
from ..models import PendingOAuth, Secret, Tool
from ..timeutil import as_naive as _as_naive
from ..timeutil import utcnow_naive as _utcnow_naive


def _host_of(url: str) -> str:
    return urlsplit(url).netloc.lower()


async def _free_connection_name(base: str, org_id: int, db: AsyncSession) -> str:
    """First connection for a provider keeps the bare service name; later ones get -2, -3.

    The bare name matters: every skill and doc says `treg call google-search-console`, and a tool
    name is unique per org, so the first account must own it or all of that breaks. Suffixing only
    the extras means adding a second account can never change how the first one is called.
    """
    taken = set((await db.execute(
        select(Tool.name).where(Tool.org_id == org_id)
    )).scalars().all()) | set((await db.execute(
        select(Secret.name).where(Secret.org_id == org_id)
    )).scalars().all())
    if base not in taken:
        return base
    return next(f"{base}-{n}" for n in range(2, 1000) if f"{base}-{n}" not in taken)


def _provider_bindings(provider, secret: Secret) -> list[dict]:
    """The binding list that injects `secret` the way this registry provider authenticates.

    A pasted-secret provider's value is a plain string, not an oauth blob — injecting it with
    secret_field="access_token" would try to read a JSON field that isn't there. A key may ride in
    a header (default) or a query param (Semrush's ?key=…). A provider needing a second credential
    that TREG holds (Google Ads' developer token) gets it as a platform binding — read from settings
    at call time, never copied into the org's secrets."""
    if provider.uses_pasted_secret:
        if provider.token_location == "query":
            bindings = [{
                "secret_id": secret.id, "injector": "env", "location": "query",
                "name": provider.token_param, "format": provider.token_format,
            }]
        else:
            bindings = [{
                "secret_id": secret.id, "injector": "env", "location": "header",
                "name": provider.token_header, "format": provider.token_format,
            }]
    else:
        bindings = [{
            "secret_id": secret.id, "injector": "oauth", "location": "header",
            "name": "Authorization", "format": "Bearer {secret}", "secret_field": "access_token",
        }]
    # A provider-required protocol header is a constant-format binding over the same encrypted
    # secret reference. `format` deliberately contains no {secret}: the existing injector stamps
    # the literal value after caller headers are copied, so a caller cannot accidentally select a
    # different API version. The relay remains provider-blind.
    source = {k: v for k, v in bindings[0].items()
              if k in ("secret_id", "platform_setting", "injector", "secret_field")}
    bindings.extend({**source, "location": "header", "name": name, "format": value}
                    for name, value in provider.required_headers)
    if provider.needs_extra_credential and provider.extra_credential_is_platform:
        bindings.append({
            "platform_setting": provider.extra_credential_setting, "injector": "env",
            "location": "header", "name": provider.extra_credential_header, "format": "{secret}",
        })
    return bindings


async def _autoprovision_provider_tool(
    provider, secret: Secret, pending: PendingOAuth, db: AsyncSession
) -> None:
    """Bind the freshly-connected credential to the provider's API as a callable tool.

    Named after the CONNECTION, not the provider — a tool name is unique per org, so two accounts
    on one provider need two tools. The first account's connection is named for the service, so it
    still gets the bare `google-search-console` every skill and doc refers to.

    Idempotent by (org, name): reconnecting rebinds the existing tool to the new credential rather
    than piling up duplicates."""
    tool_name = secret.name or provider.service
    existing = (
        await db.execute(
            select(Tool).where(Tool.org_id == secret.org_id, Tool.name == tool_name)
        )
    ).scalars().first()
    bindings = _provider_bindings(provider, secret)
    # A registry tool with a probe can self-validate on `health --run` instead of sitting at
    # "unchecked" until something happens to call it.
    health_check = (
        {"method": "GET", "path": provider.probe_path, "expect_status": 200}
        if provider.probe_path else None
    )
    examples = _provider_tool_examples(provider)
    if existing is not None:
        existing.bindings = bindings
        existing.base_url = provider.base_url
        existing.host = _host_of(provider.base_url)
        # Reconnecting is how an already-provisioned tool picks up a probe — or examples — added
        # to the registry since it was made.
        existing.health_check = health_check or existing.health_check
        if examples and not existing.examples:
            existing.examples = examples
    else:
        db.add(Tool(
            org_id=secret.org_id, name=tool_name, owner=pending.owner,
            base_url=provider.base_url, host=_host_of(provider.base_url),
            bindings=bindings, health_check=health_check,
            examples=examples,
        ))
    await _upsert_provider_extra_tools(provider, secret, tool_name, pending.owner, db, bindings)


async def _upsert_provider_extra_tools(
    provider, secret: Secret, tool_name: str, owner: str, db: AsyncSession,
    bindings: list[dict] | None = None,
) -> int:
    """Upsert a split-host provider's companion tools; return the number newly created.

    Connect and startup backfill deliberately share this exact write path. A new provider registry
    `extra_tools` entry therefore heals old connections on their next boot without a one-off migration.
    """
    bindings = bindings or _provider_bindings(provider, secret)
    created = 0
    for extra in getattr(provider, "extra_tools", ()) or ():
        extra_name = f"{tool_name}-{extra['suffix']}"
        extra_probe = (
            {"method": "GET", "path": extra["probe_path"], "expect_status": 200}
            if extra.get("probe_path") else None
        )
        prior = (await db.execute(
            select(Tool).where(Tool.org_id == secret.org_id, Tool.name == extra_name)
        )).scalars().first()
        if prior is not None:
            prior.bindings = bindings
            prior.base_url = extra["base_url"]
            prior.host = _host_of(extra["base_url"])
            prior.health_check = extra_probe or prior.health_check
            if extra.get("examples") and not prior.examples:
                prior.examples = extra["examples"]
        else:
            db.add(Tool(
                org_id=secret.org_id, name=extra_name, owner=owner,
                base_url=extra["base_url"], host=_host_of(extra["base_url"]),
                bindings=bindings, health_check=extra_probe,
                examples=extra.get("examples") or [],
            ))
            created += 1
    return created


async def _backfill_provider_extra_tools() -> int:
    """Heal provider connections created before their registry entry gained companion tools.

    A connection qualifies only when its provider-attributed Secret still has the expected main
    Tool and that Tool is bound to the same Secret. This avoids creating orphan companions for a
    partially-deleted connection while keeping the scan generic across all future `extra_tools`.
    """
    async with session_maker() as db:
        provider_secrets = (await db.execute(
            select(Secret).where(Secret.provider != "")
        )).scalars().all()
        candidates = [
            (secret, provider)
            for secret in provider_secrets
            if (provider := oauth_providers.get(secret.provider)) is not None
            and (getattr(provider, "extra_tools", ()) or ())
        ]
        if not candidates:
            return 0

        org_ids = {secret.org_id for secret, _ in candidates}
        tools = (await db.execute(select(Tool).where(Tool.org_id.in_(org_ids)))).scalars().all()
        by_org_name = {(tool.org_id, tool.name): tool for tool in tools}
        created = 0
        for secret, provider in candidates:
            tool_name = secret.name or provider.service
            main = by_org_name.get((secret.org_id, tool_name))
            if main is None or not any(
                binding.get("secret_id") == secret.id for binding in (main.bindings or [])
            ):
                continue
            created += await _upsert_provider_extra_tools(
                provider, secret, tool_name, main.owner or secret.owner, db)
        await db.commit()
        if created:
            logging.getLogger("treg").info("backfilled %d provider companion tool(s)", created)
        return created


CATALOG_STAMP_CAP = 12  # a tool's examples are read by a human/agent scanning, not a full API doc


def _provider_tool_examples(provider) -> list[dict]:
    """The provisioned tool's `examples`: the registry's hand-written ones first, then the endpoint
    catalog's verified core operations for the same provider.

    This is what makes a fresh connection immediately useful — the agent gets real paths with the
    inputs they need instead of guessing them from the provider's docs and burning paid calls."""
    out = [dict(e) for e in provider.examples]
    seen = {(e.get("method", "").upper(), (e.get("path") or "").lstrip("/")) for e in out}
    for ex in catalog_store.tool_examples(provider.service):
        if len(out) >= CATALOG_STAMP_CAP:
            break
        key = (ex["method"], ex["path"].lstrip("/"))
        if key in seen:
            continue
        seen.add(key)
        out.append(ex)
    return out


async def _record_connected_identity(provider, secret: Secret, blob: dict, client) -> None:
    """Ask the provider who just connected, and remember it.

    Providers with nothing to choose between (LinkedIn acts as the one member who consented) would
    otherwise show a connection with no indication of WHICH account it is. This also captures the
    id the API actually needs — LinkedIn's person URN — so the agent doesn't re-fetch it on every
    call. Best-effort: a failed lookup must never fail the connect."""
    try:
        resp = await client.get(
            f"{provider.base_url.rstrip('/')}{provider.identity_path}",
            headers={"Authorization": f"Bearer {blob.get('access_token')}"},
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        ident = _dig(data, provider.identity_id_path)
        if not ident:
            return
        secret.resource_ref = provider.identity_ref_format.format(id=ident)
        label = _dig(data, provider.identity_label_path) if provider.identity_label_path else None
        secret.resource_name = str(label) if label else str(ident)
    except Exception as exc:  # noqa: BLE001
        print(f"[oauth] identity lookup failed for {provider.service}: {exc}")


def _dig(obj, dotted: str):
    """Walk a dotted path through dicts and list indices; None if any hop is missing."""
    for part in dotted.split("."):
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
        if obj is None:
            return None
    return obj


class ConnectError(Exception):
    """A framework-neutral connection refusal translated by the HTTP router."""

    def __init__(self, kind: str, detail: str):
        self.kind = kind
        self.detail = detail
        super().__init__(kind)


@dataclass(frozen=True)
class OAuthCallbackOutcome:
    kind: str


async def start_oauth_connection(
    *, org_id: int, owner: str, name: str, provider_name: str | None,
    capability: str | None, connection_id: int | None, client_id: str,
    client_secret: str, auth_uri: str, token_uri: str, scopes: list[str],
    redirect_uri: str | None,
) -> dict:
    async with session_maker() as db:
        code_verifier, auth_params, auth_method = "", "", "client_secret_post"
        cid_param, scope_sep = "client_id", " "
        long_lived = False

        if provider_name:
            provider = oauth_providers.get(provider_name)
            if provider is None:
                known = ", ".join(sorted(oauth_providers.REGISTRY))
                raise ConnectError(
                    "unknown_provider",
                    f"unknown provider {provider_name!r} (known: {known})",
                )
            chosen_capability = capability or provider.default_capability
            try:
                scopes = provider.scopes_for(chosen_capability)
                client_id, client_secret = oauth_providers.credentials(provider)
            except ValueError as exc:
                raise ConnectError("invalid_provider", str(exc)) from None
            auth_uri, token_uri = provider.auth_uri, provider.token_uri
            name = name or provider.service
            auth_method = provider.token_endpoint_auth_method
            cid_param, scope_sep = provider.client_id_param, provider.scope_separator
            long_lived = provider.long_lived_exchange
            if provider.auth_params is not None:
                auth_params = json.dumps(provider.auth_params)
            if provider.pkce:
                code_verifier = crypto.new_token()
        elif not (client_id and client_secret):
            raise ConnectError(
                "invalid_provider",
                "supply `provider` for a registry connect, or client_id + client_secret to bring your own app",
            )
        if not name:
            raise ConnectError("invalid_provider", "name is required")

        # Reconnecting targets ONE connection. Scoped to the caller's org so a guessed id can't aim a
        # consent at another org's credential, and matched to the provider so a Slack consent can't be
        # made to overwrite a Google one.
        replaces_id = None
        if connection_id is not None:
            target = (await db.execute(select(Secret).where(
                Secret.id == connection_id, Secret.org_id == org_id
            ))).scalars().first()
            if target is None:
                raise ConnectError("unknown_connection", "unknown connection")
            if provider_name and target.provider != provider_name:
                raise ConnectError(
                    "invalid_provider",
                    f"connection {connection_id} is {target.provider or 'not a provider connection'}, not {provider_name}",
                )
            replaces_id = target.id
            name = target.name

        state = crypto.new_token()
        treg_callback = f"{get_settings().public_url.rstrip('/')}/oauth/callback"
        # The code must come back to treg's OWN callback — a body-supplied redirect_uri pointing elsewhere
        # turns this into a consent-phishing URL builder (a legit provider link that routes the code away).
        if redirect_uri and redirect_uri.rstrip("/") != treg_callback:
            raise ConnectError("invalid_provider", "redirect_uri must be treg's own /oauth/callback")
        redirect_uri = redirect_uri or treg_callback
        pending = PendingOAuth(
            org_id=org_id, state=state, name=name, owner=owner,
            client_id=client_id, client_secret=crypto.encrypt(client_secret),
            auth_uri=auth_uri, token_uri=token_uri, scopes=scope_sep.join(scopes),
            redirect_uri=redirect_uri, provider=provider_name or "",
            code_verifier=code_verifier, auth_params=auth_params,
            token_endpoint_auth_method=auth_method, client_id_param=cid_param,
            scope_separator=scope_sep, long_lived_exchange=long_lived,
            replaces_secret_id=replaces_id,
        )
        db.add(pending)
        await db.commit()
        return {"state": state, "consent_url": oauth.consent_url(pending), "redirect_uri": redirect_uri}


async def complete_oauth_connection(
    *, state: str, code: str, error: str, client_factory,
) -> OAuthCallbackOutcome:
    async with session_maker() as db:
        # Hit by the BROWSER on redirect — no token; protected by the unguessable `state`.
        pending = (
            await db.execute(select(PendingOAuth).where(PendingOAuth.state == state))
        ).scalar_one_or_none()
        if pending is None:
            return OAuthCallbackOutcome("invalid")
        if pending.status != "pending":
            # A browser re-load re-hits this URL with a now-spent code; re-exchanging would fail and
            # flip a successful connect's status to "error". Return the terminal result without redoing it.
            return OAuthCallbackOutcome("done" if pending.status == "done" else "already_failed")
        if _as_naive(pending.created_at) < _utcnow_naive() - timedelta(minutes=health.OAUTH_PENDING_TTL_MIN):
            pending.status, pending.detail = "error", "expired"  # an old state must not stay redeemable
            await db.commit()
            return OAuthCallbackOutcome("expired")
        if error or not code:
            pending.status, pending.detail = "error", (error or "no authorization code")[:200]
            await db.commit()
            return OAuthCallbackOutcome("authorization_failed")

        try:
            client = client_factory()
            blob = await oauth.exchange_code(pending, code, client)
            provider = oauth_providers.get(pending.provider) if pending.provider else None
            # A consent either REPLACES one named connection or ADDS another. `replaces_secret_id` says
            # which, decided back at /oauth/start where the user's intent was known. This used to
            # blanket-replace by provider, which fixed the real bug — widening read→write silently made
            # a second google-search-console row — at the cost of banning a second account entirely.
            secret = None
            if pending.replaces_secret_id is not None:
                secret = (await db.execute(select(Secret).where(
                    Secret.id == pending.replaces_secret_id, Secret.org_id == pending.org_id
                ))).scalars().first()
                # Deleted between consent and callback: fall through and add it back rather than 500.
            if secret is None:
                secret = Secret(
                    org_id=pending.org_id,
                    name=await _free_connection_name(pending.name, pending.org_id, db),
                    owner=pending.owner,
                    kind="oauth", value=crypto.encrypt(json.dumps(blob)),
                )
                db.add(secret)
            else:
                secret.value = crypto.encrypt(json.dumps(blob))
                secret.last_error = ""
            secret.provider = pending.provider or ""
            # granted_scopes stays canonically SPACE-joined whatever dialect went over the wire, so the
            # readers (satisfied_capabilities, the health payload) can keep using a plain .split().
            # TikTok comma-joins its consent scopes; without this normalisation a whole grant would
            # come back as one bogus scope string and every capability would read as unsatisfied.
            separator = pending.scope_separator or " "
            secret.granted_scopes = " ".join(s for s in pending.scopes.split(separator) if s)
            secret.expires_at = oauth.expiry_of(blob)
            await db.flush()
            # A connect that yields no callable tool is a dead end — the user consented and got
            # nothing. Auto-provision the provider's tool bound to this credential so the very next
            # thing they can do is make a real proxied call.
            if provider and provider.can_autoprovision:
                await _autoprovision_provider_tool(provider, secret, pending, db)
            if provider and provider.has_identity:
                await _record_connected_identity(provider, secret, blob, client)
            pending.status, pending.secret_id, pending.detail = "done", secret.id, "connected"
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            print(f"[oauth] token exchange failed for state {state}: {exc}")  # detail stays server-side
            pending.status, pending.detail = "error", "token exchange failed"
            await db.commit()
            return OAuthCallbackOutcome("exchange_failed")
        return OAuthCallbackOutcome("connected")


async def connect_with_pasted_secret(
    *, provider_name: str, raw_token: str, org_id: int, owner: str, client_factory,
) -> dict:
    provider = oauth_providers.get(provider_name)
    if provider is None or not provider.uses_pasted_secret:
        raise ConnectError("invalid_token_provider", "this provider is connected by consent, not a token")
    token = raw_token.strip()
    if not token:
        raise ConnectError("invalid_token", f"{provider.token_label or 'Token'} is required")
    # HTTP Basic providers (DataForSEO, Moz) take a pasted `login:password`; store the Base64 blob so
    # `Basic {secret}` renders the same at connect and on every proxy call. Both dashboards ALSO hand
    # out a ready-made Base64 credential, and users paste that at least as often as the raw pair —
    # encoding it again produced a double-encoded blob the provider 401'd. So: if the paste already IS
    # Base64 of a printable `login:password`, keep it. A raw pair can never be mistaken for one (":"
    # is not in the Base64 alphabet, so strict decoding refuses it), and a Base64 blob can never be
    # a working raw pair (it has no ":"), so the branch is unambiguous either way.
    if provider.token_encode == "base64":
        already = None
        try:
            decoded = base64.b64decode(token, validate=True).decode()
            if ":" in decoded and decoded.isprintable():
                already = token
        except Exception:  # noqa: BLE001 — not Base64, or not text: encode it below
            pass
        token = already or base64.b64encode(token.encode()).decode()

    # The credential rides in a header (default) or a query param (Semrush: ?key=…). The cheapest
    # check may also live on a different host than base_url, so honor an absolute probe_url override,
    # and a POST probe with a JSON body (Serpstat's JSON-RPC limits call).
    rendered = provider.token_format.format(secret=token)
    if provider.token_location == "query":
        headers, params = {}, {provider.token_param: rendered}
    else:
        headers, params = {provider.token_header: rendered}, {}
    headers.update(dict(provider.required_headers))
    probe_url = provider.probe_url or f"{provider.base_url.rstrip('/')}{provider.probe_path}"
    # httpx REPLACES a URL's own query string when `params=` is passed, so a probe_path like
    # `/autocomplete?field=title&text=data` (PDL, Akta, JustOneAPI, SpyFu) silently lost its required
    # params and the probe 400'd — rejecting a perfectly good key. Merge the path's query into params
    # ourselves (params, i.e. the credential for a query provider, wins on a key collision).
    split = urlsplit(probe_url)
    if split.query:
        params = {**dict(parse_qsl(split.query, keep_blank_values=True)), **params}
        probe_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    try:
        client = client_factory()
        resp = await client.request(
            provider.probe_method or "GET", probe_url,
            headers=headers, params=params, json=provider.probe_json,
        )
    except Exception as exc:  # noqa: BLE001
        raise ConnectError(
            "provider_unreachable", f"could not reach {provider.display_name}: {exc}"
        ) from None
    # Try to parse the body as JSON regardless of the content-type header: ScrapeCreators returns a
    # real JSON body labelled `text/plain`, and gating on `application/json` left its payload empty so
    # `token_verify_field` (creditCount) read as false and a valid key was rejected. The parse is
    # defensive — a genuinely non-JSON key check (Semrush's CSV/number balance) simply throws and
    # leaves payload empty, falling through to the `text_error` branch exactly as before.
    ctype = resp.headers.get("content-type", "")
    payload: dict = {}
    if resp.status_code < 500:
        try:
            parsed = resp.json()
            payload = parsed if isinstance(parsed, dict) else {}
        except Exception:  # noqa: BLE001
            payload = {}
    # Some providers answer HTTP 200 even for a BAD key and signal validity only in the body: a JSON
    # field (Slack: "ok"; Apollo: "is_logged_in") or an "ERROR ..." text line (Semrush). An HTTP
    # status alone would happily accept a dead key, so check all three signals.
    field_bad = bool(provider.token_verify_field) and not payload.get(provider.token_verify_field)
    field_reject = bool(provider.token_reject_field) and bool(payload.get(provider.token_reject_field))
    equals_bad = bool(provider.token_ok_field) and str(payload.get(provider.token_ok_field)) != provider.token_ok_value
    # Usually any >=400 is a bad key; a provider with no free probe (Coresignal) POSTs an empty body so
    # a VALID key answers 400 — there only 401/403 mean the key itself is bad.
    status_reject = (
        resp.status_code in provider.probe_reject_statuses
        if provider.probe_reject_statuses else resp.status_code >= 400
    )
    text_error = (
        resp.status_code < 400
        and not ctype.startswith("application/json")
        and resp.text.lstrip().upper().startswith("ERROR")
    )
    if status_reject or field_bad or field_reject or equals_bad or text_error:
        why = (
            payload.get("error")
            or (payload.get("ErrorMessage") if equals_bad else None)
            or (f"{provider.token_verify_field}=false" if field_bad else None)
            or (resp.text.strip()[:80] if text_error else f"HTTP {resp.status_code}")
        )
        raise ConnectError(
            "invalid_token", f"{provider.display_name} rejected that token ({why})"
        )

    async with session_maker() as db:
        secret = (await db.execute(
            select(Secret).where(Secret.org_id == org_id, Secret.provider == provider.service)
        )).scalars().first()
        if secret is None:
            secret = Secret(
                org_id=org_id, name=provider.service, owner=owner, kind="env",
                value=crypto.encrypt(token), provider=provider.service,
            )
            db.add(secret)
        else:
            secret.value = crypto.encrypt(token)
        if provider.token_scopes_header:
            granted = resp.headers.get(provider.token_scopes_header, "")
            if granted:
                secret.granted_scopes = " ".join(x.strip() for x in granted.split(",") if x.strip())
        secret.last_error = ""
        secret.health_status, secret.health_detail = "ok", "token verified at connect"
        secret.health_checked_at = _utcnow_naive()
        if provider.has_identity:
            ident = _dig(payload, provider.identity_id_path)
            if ident:
                secret.resource_ref = provider.identity_ref_format.format(id=ident)
                label = _dig(payload, provider.identity_label_path) if provider.identity_label_path else None
                secret.resource_name = str(label) if label else str(ident)
        await db.flush()

        pending = PendingOAuth(
            org_id=org_id, state="", name=provider.service, owner=owner,
            client_id="", client_secret="", auth_uri="", token_uri="", redirect_uri="",
        )
        await _autoprovision_provider_tool(provider, secret, pending, db)
        await db.commit()
        await db.refresh(secret)
        return oauth.connection_view(secret)


async def get_oauth_status(*, state: str, org_id: int) -> dict:
    async with session_maker() as db:
        pending = (
            await db.execute(
                select(PendingOAuth).where(PendingOAuth.state == state, PendingOAuth.org_id == org_id)
            )
        ).scalar_one_or_none()
        if pending is None:
            raise ConnectError("unknown_state", "unknown oauth state")
        return {
            "status": pending.status,
            "secret_id": pending.secret_id,
            "detail": pending.detail,
            "name": pending.name,
        }
