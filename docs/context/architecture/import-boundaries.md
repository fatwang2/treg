---
title: Enforced import boundaries
status: shipped
sources:
  - pyproject.toml
  - .github/workflows/ci.yml
  - src/treg/application/__init__.py
  - src/treg/domain/__init__.py
  - src/treg/domain/governance/__init__.py
  - src/treg/domain/governance/teams.py
  - src/treg/domain/identity/__init__.py
  - tests/test_import_lightness.py
related:
  - architecture/composition.md
  - architecture/money.md
  - interface/cli.md
---

# Enforced import boundaries

Import Linter reads the contracts under `tool.importlinter` in `pyproject.toml`. The main CI `test`
job installs the hand-maintained lock with `uv sync --frozen`, then runs
`uv run --frozen lint-imports` before the test suite. Keeping the check in that job reuses the
development environment and avoids a second install for a fast static architecture check.
The separate `test-postgres` job runs its database-sensitive subset serially against Postgres 16;
it includes agent attribution, credential health, local-run reporting and ads-conversion coverage so
naive-UTC assumptions are exercised by asyncpg rather than hidden by SQLite's permissive adapter.

Stage 1 activated the first two contracts:

- The explicit lightweight CLI module list cannot directly import any server-extra package, including
  FastAPI, SQLModel, SQLAlchemy, Alembic, database drivers, MCP, Stripe, or cryptography. Imports guarded
  by `TYPE_CHECKING` are excluded globally because they cannot load at runtime. Indirect imports are
  allowed by this contract because optional proxy dependencies may appear in lazily executed internal
  modules; the named CLI modules themselves must remain free of direct server imports.
- `treg.ledger` cannot import `treg.audit`. Money correctness never flows through the best-effort audit
  path, whose writes may be shed under load.

Stage 2 adds a third contract: the complete `treg.routers` package cannot import `treg.api`, directly or
indirectly. `as_packages = true` makes the source cover every current and future router submodule.
`api.py` remains the compatibility exporter and ordered route-table host, so the allowed direction is
API to routers.

Stage 3 adds domain contracts as packages appear. The complete `treg.domain.identity` package cannot import
`treg.api`, `treg.routers`, or `treg.application`. Identity now owns session signing and validation,
MCP token and grant-family primitives, and caller/access resolution as a leaf. Sibling-domain
edges are added when the sibling appears; identity therefore also forbids governance. Governance may
import identity but cannot import the API, routers, or application layer. Future sibling contracts remain
absent until their packages exist, so no placeholder domain makes a future boundary look active.

Two direct edges are precise exceptions. `cli.ensure_proxy_dependency` imports `cryptography` only after
the user invokes the optional proxy feature and offers to install the proxy extra first.
`localrun.render_grant` imports SQLModel only when the server executes the grant path. Import Linter treats
function-local imports as ordinary direct edges, so both appear in `ignore_imports`; unmatched ignores are
errors, ensuring a removed or renamed edge cannot leave a stale exception behind.

An ignore covers an entire module edge and therefore cannot detect someone moving either lazy import to
module scope. `tests.test_import_lightness` closes that gap by starting an isolated Python subprocess,
importing every lightweight module, and asserting that no server dependency root appears in `sys.modules`.
Base dependencies such as httpx and questionary remain allowed.
