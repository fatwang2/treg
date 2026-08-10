# treg — Codex / ChatGPT plugin

A **distribution wrapper**, not a second product. It ships the same skill that
`treg skill bootstrap` already installs into `~/.codex/skills/`, packaged so people find treg by
searching the plugin directory that ChatGPT and Codex share.

    plugin/
    ├── .codex-plugin/plugin.json     the manifest + the listing copy
    ├── skills/treg/        GENERATED — do not edit by hand
    └── assets/                       icon + logo (▚ in clay #e0703f)

## The skill is generated

`src/treg/web/skill.md` is the one source. It is served at `/skill.md`, written into every agent by
`treg skill bootstrap`, and rendered into this plugin by:

```bash
python3 scripts/build_plugin.py            # regenerate
python3 scripts/build_plugin.py --check    # fail if stale (also a test)
```

Two things differ from the served copy, both because a plugin arrives where the server does not:

- **`{BASE}` is baked** to the public deployment. The server substitutes that placeholder per
  request; nothing substitutes it inside an installed plugin, so a raw copy would ship the literal.
- **A bootstrap section is prepended.** Every other install path implies the CLI already exists —
  `treg skill bootstrap` only runs because `treg` is installed. This is the one path where the skill
  can land on a machine with no treg at all, and without it a first run ends in `command not found`.

**Never edit `skills/treg/SKILL.md`.** Change `src/treg/web/skill.md` and regenerate;
`tests/test_plugin.py` fails if the two disagree.

## Testing it locally (verified with codex-cli 0.145.0)

**No desktop app required** — the Codex CLI installs and loads plugins itself.

The marketplace manifest is a **user-side** file and is deliberately not part of this plugin. It
lives at `~/.agents/plugins/marketplace.json`, and its `path` is resolved **relative to `$HOME`**,
not to the manifest and not as an absolute path:

```jsonc
{
  "name": "superdesign-local",
  "interface": { "displayName": "superdesign (local dev)" },
  "plugins": [
    {
      "name": "treg",
      "source": { "source": "local", "path": "./devs/superdesign/tools-registry-oss/plugin" },
      "policy": { "installation": "AVAILABLE", "authentication": "ON_INSTALL" },
      "category": "Developer Tools"
    }
  ]
}
```

Then:

```bash
codex plugin list                   # treg@superdesign-local — not installed
codex plugin add treg@superdesign-local     # the @marketplace suffix is REQUIRED
codex plugin list                   # installed, enabled, 0.7.0
```

Installed copies land in `~/.codex/plugins/cache/$MARKETPLACE/$PLUGIN/$VERSION/`. Confirm the skill
actually loaded — it should appear as `treg:tools-registry`:

```bash
codex exec --skip-git-repo-check "List the names of every skill you have available."
```

`codex plugin marketplace add ./plugin` does **not** work: that command expects a marketplace root,
and this directory is a plugin.

## The listing copy is the product

`category` and `capabilities` are not guesses — they are what OpenAI's own shipped plugins use
(`github` is `Developer Tools` + `["Interactive", "Write"]`; `gmail` is `Communication`;
`openai-templates` is `Productivity`). The published docs show neither list, so read a real installed
manifest under `~/.codex/plugins/cache/` before inventing a value.

Before submitting through OpenAI's plugin portal, check the manifest `version` matches
`pyproject.toml` (a test enforces this), and that the copy still describes what treg does: it
**compares** providers and the agent chooses. treg does not route automatically and does not fail
over — the landing page had to be corrected for that claim once already, and a directory listing is
harder to correct than a web page. A test guards this too.
