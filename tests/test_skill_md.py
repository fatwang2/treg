"""The official treg skill: served {BASE}-templated at GET /skill.md, and installed
to ~/.claude/skills/treg/ by install.sh (so one curl gives a machine the CLI + the skill)."""

from __future__ import annotations

from pathlib import Path

from treg import api as api_mod


async def test_skill_md_served_and_templated(clients):
    r = await clients.get("/skill.md")
    assert r.status_code == 200
    body = r.text
    assert body.startswith("---") and "name: treg" in body  # loadable skill frontmatter
    assert "{BASE}" not in body                                        # fully templated
    assert "/call/https://api.intercom.io" in body                     # the passthrough teaching line
    assert "treg register" not in body                                 # the retired command must not resurface


def test_install_sh_installs_the_skill():
    sh = (Path(api_mod.__file__).parent / "web" / "install.sh").read_text()
    assert "$BASE/skill.md" in sh and ".claude/skills/treg" in sh


def test_install_sh_supports_the_one_shot_authed_setup():
    """`… | sh -s -- --token <key>` (or TREG_TOKEN=) → sign in + register MCP in one go; the key
    bakes in the team, so no org is passed. Without a token the flow is unchanged."""
    sh = (Path(api_mod.__file__).parent / "web" / "install.sh").read_text()
    assert "--token" in sh and "TREG_TOKEN" in sh
    assert "treg login --token" in sh
    assert "treg mcp install" in sh
