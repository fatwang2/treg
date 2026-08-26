---
title: Application composition and deployment roles
status: shipped
sources:
  - src/treg/bootstrap.py
  - src/treg/domain/identity/mcp_oauth.py
  - src/treg/domain/identity/session.py
  - src/treg/routers/admin.py
  - src/treg/routers/auth.py
  - src/treg/routers/orgs.py
  - src/treg/routers/web.py
  - scripts/dump_surface.py
related:
  - architecture/import-boundaries.md
  - interface/api.md
  - architecture/mcp-oauth.md
  - ops/deploy.md
---

# Application composition

`bootstrap.create_app(role)` is the FastAPI composition root. `api.py` hosts the ordered route table;
the auth module defines login, session, invite, user-token, OAuth-server, and grant-management blocks;
the org module defines signup, team-entry, invite-lifecycle, and member-management blocks; the Catalog, web, and admin
modules define their concern-specific `APIRouter` blocks that `api.py`
appends at their legacy registration points. It then calls the factory once at EOF so the deployed
and documented `treg.api:app` import path remains the default `all` role.

The factory owns concrete assembly: the three pure-ASGI middleware registrations, five exception handlers,
static mounts, optional MCP mount and lifespan, GET-to-HEAD widening, the OpenAPI wrapper that hides
implied HEAD operations, shared HTTP client creation, startup work, shutdown drains, and the Ads
conversion worker. Registration order is compatibility behavior. The four stage-0 snapshots stay
byte-identical for `role="all"` unless that composition intentionally changes.

The middleware stack is `_BodyDecodeMiddleware` -> `_SecurityHeadersMiddleware` ->
`_LegacyHostRedirectMiddleware` -> routes/mounts. All three are pure ASGI. The security wrapper adds
headers at `http.response.start` with case-insensitive setdefault semantics, and the redirect wrapper
either sends the same 301/302 response as before or calls its child directly. Keeping
`BaseHTTPMiddleware.call_next()` out of this stack matters for streaming and disconnects: an MCP
client may close while its stateless transport terminates without sending a response, which is a
normal end to an already-dead connection rather than a server 500.

Pure ASGI does not make a genuine missing-response defect silent. Uvicorn's
`RequestResponseCycle.run_asgi` checks an app that returns while the connection is still live, logs
`ASGI callable returned without starting response.`, and sends a 500. It skips that error only when
the protocol has already marked the client disconnected, when no response can be delivered. Response
completion also remains responsible for Starlette background tasks: the `/call` relay's
`StreamingResponse` runs `BackgroundTask(upstream_resp.aclose)` after its body, and an assertion test
pins that the shared httpx connection is released exactly once. Removing the two AnyIO memory-stream
hops changes streaming backpressure and scheduling but not interruption semantics, which the
callmatrix stream-failure case pins.

## Role manifests

Every created app exposes `app.state.role_manifest` with explicit `routes`, `background_tasks`, and
`startup_checks` lists. `tests/test_app_roles.py` pins all three lists for every role.

| Role | HTTP routes and mounts | Background tasks | Startup checks |
|---|---|---|---|
| `all` | The complete existing surface, including `/run`, static files, and `/mcp` | Ads conversion worker when enabled | DB init, provider-tool backfill, single-user bootstrap, HTTP client, MCP lifespan |
| `dataplane` | `/call/{rest:path}`, the `/mcp` mount, and its RFC 9728 resource-metadata route; no `/run`, static files, docs, or OpenAPI | None | DB init, provider-tool backfill, HTTP client, MCP lifespan |
| `control` | Everything except the calling surface (`/call/{rest:path}`, `/mcp`, and its resource metadata); includes `/run` and static files | Ads conversion worker when enabled | DB init, provider-tool backfill, single-user bootstrap, HTTP client |

MCP is calling traffic (the refactor plan's role table assigns `mcp.py` to the dataplane), so a future
dataplane deployment serves agents on both entry points. OAuth token issuance - consent pages and the
`/oauth/*` endpoints - stays on control; the MCP surface only validates tokens, which is a read.
`domain.identity.session` is therefore a both-role primitive: control signs browser and identity
tokens, while both roles share its signing-key validation through `domain.identity.mcp_oauth`.

`_CONTROL_ROUTE_KEYS` and `_DATAPLANE_ROUTE_KEYS` assign every `api.router` route to exactly one
owner. App creation fails on an unclassified, stale, duplicate, or multiply-owned key, so adding a
route cannot silently expand the dataplane. Role separation is preparatory in stage 1; only the
`all` role is deployed.

## Route cloning

Each factory call must produce an independent app whose dependency overrides belong to that app.
`_include_routes` therefore shallow-clones every `APIRoute`, points its dependency override provider
at the new FastAPI instance, and rebuilds its request handler. This also avoids the internal
`_IncludedRouter` wrapper added by the current FastAPI `include_router()` implementation, which would
otherwise change route inspection and the committed surface snapshot.

`scripts.dump_surface._lifespan` records the optional MCP lifespan condition against
`treg.bootstrap._mcp`, where optional MCP composition now lives. This is a documentation-only snapshot
correction; the mounted lifespan behavior is unchanged.
