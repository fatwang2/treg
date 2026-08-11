#!/bin/sh
# treg CLI installer  -  curl -fsSL {BASE}/install.sh | sh
# Installs the `treg` command and points it at this server ({BASE}).
set -e

BASE="{BASE}"

# Optional token for a one-shot, fully-authed setup:
#   curl -fsSL {BASE}/install.sh | sh -s -- --token <key>      (or: TREG_TOKEN=<key> … | sh)
# With it, this installs the CLI + skill AND signs in + registers the MCP server into every supported
# agent, header-authed — no browser. The key bakes in the team, so nothing else is needed. Without a
# token, it installs the CLI + skill and prints the sign-in step (the original behavior, unchanged).
TOKEN="${TREG_TOKEN:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --token=*) TOKEN="${1#--token=}"; shift ;;
    *) shift ;;
  esac
done
# Install from PyPI (fast, public, no git clone). The base package is the light CLI; the FastAPI/DB
# server stack is the `tools-registry[server]` extra, which people who self-host install separately.
#
# `[proxy]` is included here on purpose. It adds only `cryptography`, which is what `treg <command>`
# needs to generate this machine's certificate authority — and it ships as a prebuilt wheel, so there
# is no compiler and no meaningful wait. Without it the headline feature (`treg claude`) stops on its
# first run asking to be installed, which is a bad first minute. `pip install tools-registry` stays
# light for anyone who wants only the plain CLI.
SRC="tools-registry[proxy]"

printf '\n\033[38;5;173m▚ tools-registry\033[0m - installing the treg CLI…\n\n'

if command -v uv >/dev/null 2>&1; then
  uv tool install --force "$SRC"
elif command -v pipx >/dev/null 2>&1; then
  pipx install --force "$SRC"
elif command -v pip3 >/dev/null 2>&1; then
  pip3 install --user --upgrade "$SRC"
else
  echo "Need Python 3.12+ and one of: uv (recommended), pipx, or pip3." >&2
  echo "Install uv:  https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

# point the CLI at this server (falls back silently on older CLIs)
treg config --base-url "$BASE" >/dev/null 2>&1 || true

# install the official treg skill into every detected agent so it knows how to use treg.
# `treg skill bootstrap` fans out across all supported agents (Claude Code, Cursor, Codex, Gemini,
# Copilot, OpenCode, Windsurf, …). Fall back to the Claude-only drop for older CLIs without it.
if treg skill bootstrap 2>/dev/null; then
  :
else
  SKILL_DIR="$HOME/.claude/skills/treg"
  if mkdir -p "$SKILL_DIR" 2>/dev/null && curl -fsSL "$BASE/skill.md" -o "$SKILL_DIR/SKILL.md" 2>/dev/null; then
    printf '\033[32m✓\033[0m Installed the \033[1mtreg\033[0m skill for Claude Code (%s)\n' "$SKILL_DIR"
  fi
fi

# One-shot authed setup when a token was passed: sign in (the key bakes in the team) and register the
# MCP server into every supported agent, header-authed. Both are best-effort — a failure here never
# fails the install, since the CLI + skill are already in place.
if [ -n "$TOKEN" ]; then
  if treg login --token "$TOKEN" >/dev/null 2>&1; then
    printf '\033[32m✓\033[0m Signed in.\n'
    treg mcp install 2>/dev/null || true
  else
    printf '\033[33m!\033[0m That token did not verify — run \033[1mtreg login\033[0m to sign in.\n'
  fi
  printf '\n\033[32m✓\033[0m treg is set up. Docs & tutorial:  %s/tutorial\n\n' "$BASE"
else
  printf '\n\033[32m✓\033[0m Installed \033[1mtreg\033[0m. Next:\n'
  printf '    \033[38;5;173mtreg login\033[0m      # sign in (GitHub or email) - first login registers you\n'
  printf '    \033[38;5;173mtreg mcp install\033[0m  # optional: add treg as an MCP server in your agents\n'
  printf '\nDocs & interactive tutorial:  %s/tutorial\n\n' "$BASE"
fi
