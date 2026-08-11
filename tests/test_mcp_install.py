"""`treg mcp install` — registering the treg MCP server into agents, header-authed, user-global.

The header path is deliberate: treg 200s a valid Authorization header, so a client never falls back
to OAuth discovery (verified against Claude Code). These tests lock the config each agent actually
writes and the user-global scope — a project-scoped MCP entry is a per-repo surprise, not a setup.
"""
from __future__ import annotations

import json

from treg import mcp_install


def test_json_agents_write_user_global_header_config(tmp_path, monkeypatch):
    """Cursor + opencode: a header-authed entry in the per-USER config file (not a project ./ file),
    merged so anything already there survives, and idempotent on re-run."""
    monkeypatch.setattr(mcp_install, "HOME", tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    # pre-existing unrelated servers must be preserved
    cur = tmp_path / ".cursor"; cur.mkdir()
    (cur / "mcp.json").write_text(json.dumps({"mcpServers": {"other": {"url": "http://x"}}}))
    (tmp_path / ".config" / "opencode").mkdir(parents=True)

    out = mcp_install.install_mcp(base_url="https://treg.superdesign.dev", token="TESTKEY",
                                  only=["cursor", "opencode"])
    got = {d: (s, detail) for d, s, detail in out["results"]}
    assert got["Cursor"][0] == "ok" and got["opencode"][0] == "ok", out

    cursor = json.loads((cur / "mcp.json").read_text())
    assert cursor["mcpServers"]["other"] == {"url": "http://x"}          # untouched
    treg = cursor["mcpServers"]["treg"]
    assert treg["url"] == "https://treg.superdesign.dev/mcp/"
    assert treg["headers"]["Authorization"] == "Bearer TESTKEY"

    oc = json.loads((tmp_path / ".config" / "opencode" / "opencode.json").read_text())
    assert oc["mcp"]["treg"]["type"] == "remote" and oc["mcp"]["treg"]["enabled"] is True
    assert oc["mcp"]["treg"]["headers"]["Authorization"] == "Bearer TESTKEY"

    # idempotent: a second run leaves exactly one entry, still correct
    mcp_install.install_mcp(base_url="https://treg.superdesign.dev", token="TESTKEY", only=["cursor"])
    again = json.loads((cur / "mcp.json").read_text())
    assert list(again["mcpServers"].keys()) == ["other", "treg"]


def test_uninstalled_agents_are_skipped_not_written(tmp_path, monkeypatch):
    """No marker dir → the agent isn't touched (no stray config created for something not installed)."""
    monkeypatch.setattr(mcp_install, "HOME", tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    out = mcp_install.install_mcp(base_url="https://treg.superdesign.dev", token="K",
                                  only=["cursor", "opencode"])
    assert out["results"] == []                       # nothing installed → nothing written
    assert not (tmp_path / ".cursor").exists()


def test_the_mcp_url_carries_the_trailing_slash():
    """The resource identifier is `/mcp/` — the transport is served there, and a client that resolves
    metadata uses that exact form."""
    out = mcp_install.install_mcp(base_url="https://treg.superdesign.dev/", token="K", only=[])
    assert out["mcp_url"] == "https://treg.superdesign.dev/mcp/"
