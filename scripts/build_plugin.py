#!/usr/bin/env python3
"""Generate the Codex/ChatGPT plugin's SKILL.md from the one source: `src/treg/web/skill.md`.

The plugin is a shop window — a listing in the directory ChatGPT and Codex share — and what it ships
is the SAME skill `treg skill bootstrap` already writes into `~/.codex/skills/`. Copying that file by
hand would be a second source of truth for the product's most-read page, and it would rot: the served
copy changes whenever the product does, and nothing would notice the plugin drifting behind it. So it
is generated, and `tests/test_plugin.py` fails if the checked-in copy is stale.

Two transformations, and each exists for a reason the served file does not have:

1. `{BASE}` is a placeholder the SERVER substitutes per request (`api.py` `/skill.md`). Nothing
   substitutes it inside an installed plugin, so a raw copy would ship the literal string `{BASE}`
   and every URL in it would be broken. It is baked to the public deployment here.

2. A short section is prepended mapping the skill onto the plugin's MCP tools. The served skill is
   written around the `treg` command line, because that is how every other install path reaches
   treg. A plugin user has no terminal and no CLI — they have the connector's tools. Without this
   the first run is an agent dutifully trying to run a shell command that does not exist, which is
   the listing's whole conversion funnel spent on an error message. The rest of the page still
   carries what matters: when treg is the right move, and how to choose between providers.

Usage:  python3 scripts/build_plugin.py [--check]
        --check exits 1 if the generated file differs from what is checked in (used by the test).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "treg" / "web" / "skill.md"
TARGET = ROOT / "plugin" / "skills" / "treg" / "SKILL.md"
PUBLIC_BASE = "https://treg.superdesign.dev"

BOOTSTRAP = """
## You already have treg — use the tools, not the terminal

This plugin ships a **connector**, so treg is available to you as tools right now. Nothing to
install:

| tool | use it for |
|---|---|
| `catalog_search` | find an endpoint by WHAT YOU WANT TO DO — "work email", "backlinks", "tiktok comments" |
| `catalog_get` | one endpoint's parameters and its exact price, **before** you spend |
| `call` | make the call; treg injects the credential and relays the answer |
| `balance` | the team's prepaid balance |
| `my_tools` | what this team registered and you can call without holding the key |

The rest of this page explains **when** treg is the right move and **how to choose** between
providers. It is written around the `treg` command line, which a human uses for the same jobs — read
`treg catalog search` as `catalog_search`, `treg call` as `call`, and so on.

**If the tools are not there**, the connector has no token yet: the human sets `TREG_TOKEN` (from
{BASE} → sign in → copy token) for this plugin. A new team starts with **$1.00 of free balance**,
so there is nothing to pay before the first call. Say that plainly and stop — do not ask them for a
provider's API key, which is the thing treg exists to avoid.

---
"""


def render() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    if "---" not in text:
        raise SystemExit(f"{SOURCE} has no frontmatter — refusing to guess where it ends")
    # Keep the frontmatter exactly as served (name + description drive discovery in BOTH surfaces),
    # and insert the bootstrap immediately after it, before the skill's own opening.
    _, fm, body = text.split("---", 2)
    out = f"---{fm}---\n{BOOTSTRAP}\n{body.lstrip(chr(10))}"
    return out.replace("{BASE}", PUBLIC_BASE)


def main() -> int:
    generated = render()
    check = "--check" in sys.argv
    current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else None

    if check:
        if current == generated:
            print(f"OK — {TARGET.relative_to(ROOT)} matches {SOURCE.relative_to(ROOT)}")
            return 0
        print(f"STALE — {TARGET.relative_to(ROOT)} does not match {SOURCE.relative_to(ROOT)}\n"
              f"  regenerate with: python3 scripts/build_plugin.py", file=sys.stderr)
        return 1

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(generated, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)}  ({len(generated.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
