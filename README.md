# tightlip

**English** · [Tiếng Việt](README.vi.md)

A Claude Code plugin that keeps secrets out of the model's context. Named after *tight-lipped*: Claude keeps working on your project, but never sees your keys, tokens or passwords. This repo is both a marketplace (`vntrungld`) and the plugin itself (`tightlip`).

| Hook | What it does |
|---|---|
| `SessionStart` | Names new sessions after the folder, e.g. `my-backend 10-04 16:15`, so Claude Code doesn't send your first prompt to a small model to generate a title. That request runs before any hook can block it. |
| `UserPromptSubmit` | Blocks prompts that contain a secret. Right after the final gate trips, the next prompt is also blocked once, as a reminder. |
| `PreToolUse` | Denies commands and file reads that are certain to expose secrets: `env`, `echo $DB_PASSWORD`, `gh auth token`, `kubectl get secret -o yaml`, `~/.ssh/id_*`, `~/.aws/credentials`… Also denies any Write/Edit/Bash/MCP call that contains a `[REDACTED:...]` placeholder, so placeholders never overwrite real values. |
| `PostToolUse` | Redacts secrets in every tool's output via `updatedToolOutput`, keeping the JSON shape intact. |
| `PostToolBatch` | Final gate before each model request. If any result still holds a secret (usually output of a failed command, which hooks can't rewrite), it stops the turn and tells you where the secret is. |

The plugin only runs hooks and adds nothing to the model's context, so it costs no tokens. Requires Claude Code ≥ 2.1.121 and Python ≥ 3.8 (standard library only).

## Install

**1. In Claude Code:**

```
/plugin marketplace add vntrungld/tightlip
/plugin install tightlip
```

Or from a shell:

```bash
claude plugin marketplace add vntrungld/tightlip
claude plugin install tightlip
```

If another marketplace also has a plugin named `tightlip`, use the full id `tightlip@vntrungld`.

When developing the plugin you can install straight from a clone: `claude plugin marketplace add ./tightlip`. Hooks then run directly from the repo folder (Claude Code still keeps a copy in `~/.claude/plugins/cache/`), so edits to `tightlip.py` take effect on the next hook call, with no version bump or update. Changes to `hooks.json` need a new session.

**2. Options (optional):** run `/plugin configure tightlip@vntrungld`, or use `/config`.

| Option | Default | Effect |
|---|---|---|
| `name_sessions` | on | Name sessions after the folder (see limitation 2) |
| `quiet` | off | Don't show a status line each time something is redacted |
| `block_dotenv` | off | Deny reading `.env` files instead of redacting them (`.env.example` is still allowed) |
| `allow_regex` | empty | Values that fully match this regex are never redacted, e.g. test fixtures |

**3. Releasing (maintainers):** bump `version` in `plugins/tightlip/.claude-plugin/plugin.json` and push. Users don't get a new release unless the version changes. They update with `claude plugin update tightlip@vntrungld`, or by enabling auto-update under `/plugin` → Marketplaces.

### For a whole team

Add this to the project's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "vntrungld": { "source": { "source": "github", "repo": "vntrungld/tightlip" } }
  },
  "enabledPlugins": { "tightlip@vntrungld": true }
}
```

When someone trusts the project folder, the marketplace is registered automatically, but each person still runs `/plugin install` once. To enforce it across an organization, an admin sets both keys in managed settings (`/etc/claude-code/managed-settings.json` on Linux).

### What the plugin can't do for you

Plugins aren't allowed to add `permissions`. Files you attach yourself with `@` don't go through hooks, so to cover that case add this to `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.ssh/id_*)",
      "Read(~/.aws/credentials)",
      "Read(~/.kube/config)",
      "Read(~/.docker/config.json)",
      "Read(~/.claude/.credentials.json)"
    ]
  }
}
```

## Install without the plugin system

```bash
python3 standalone/install.py --dry-run   # preview settings.json after the merge
python3 standalone/install.py
```

The script copies the hook to `~/.claude/hooks/` and merges its config (including the deny rules above) into `~/.claude/settings.json`, keeping your existing hooks and writing a backup first. In this mode options are environment variables: `TIGHTLIP_QUIET=1`, `TIGHTLIP_BLOCK_DOTENV=1`, `TIGHTLIP_NAME_SESSIONS=0`, `TIGHTLIP_ALLOW_REGEX=...`, `TIGHTLIP_DISABLE=1`. Use one install method, not both.

## Testing

```bash
python3 -m unittest discover -v tests                                       # 39 tests
echo 'DB_PASSWORD=abc123xyz' | python3 plugins/tightlip/scripts/tightlip.py --filter
```

Tested through the marketplace on Claude Code 2.1.289:
- `claude plugin details` lists all 5 hooks.
- In a real session, `cat .env` shows the model only placeholders.
- With `cat .env && exit 3`, the turn stops before the output reaches the model.
- No session-title request is sent.

## What it detects

- **Tokens with a known format (about 50 rules):** AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI/Anthropic/DeepSeek, DigitalOcean, Shopify, Atlassian, Sentry, PostHog `phx_`, npm, Docker Hub, Telegram, Grafana, Vault, Doppler, JWT, PEM private keys, Laravel `APP_KEY`…
- **By context:**
  - dotenv/shell `KEY=value`, including lines prefixed by `grep -n`, `grep -rn` or `cat -n`.
  - YAML, JSON and PHP arrays with sensitive keys.
  - `user:pass@` in URLs, `Authorization`/`X-API-Key` headers, `?token=` query strings, `--password=` flags.
  - k8s `env` blocks, `php artisan config:show` output.
  - Secrets hard-coded in source: `const apiKey: string = "…"` (TS, Rust, Swift, Kotlin, C#, Go, Java, PHP, Ruby, Python), `define('API_KEY', …)`, `#define API_KEY "…"`, Elixir `@api_key "…"`. In code the value must look random, so ordinary constants are left alone.
- **Long random values** in `UPPER_CASE=...`.

Run over laravel/framework, express, the Python standard library and npm packages (about 6,500 files), it only redacted test values that look like real secrets. Validation rules, `env('APP_KEY')`, translation files, lock-file hashes and constants in source code are left alone.

## Limitations

1. **Output of failed commands.** Hooks can't rewrite it, only stop the turn before it's sent. The content stays in the conversation, and if you just keep chatting the model will see it, so use `/rewind` (Esc Esc) to go back before that turn. The block message says where the secret is (command, or file and line such as `config/.env.prod:12`) so you can review it, but never the value itself.
2. **Session titles.** With `name_sessions` on, sessions are named after the folder and time instead of a model-written summary. With it off, each session's first prompt is sent before hooks can block it.
3. **`@` attachments and your own `!` commands bypass hooks.** The output of `! cat .env` goes straight into the conversation unredacted. For `@` files, see the deny rules above.
4. **Regexes have limits.** These get through: values printed without their variable name (e.g. `cut -d= -f2 .env`), base64-encoded secrets, tokens with unusual formats. Add your own formats to `FORMAT_RULES` in `scripts/tightlip.py`.
5. **Hooks only change what the model sees.** Commands still run for real, and OpenTelemetry (if enabled) still records the original output.
6. **The model could edit the plugin files via Bash.** For a hard guarantee, an admin force-enables the plugin in managed settings and turns on `allowManagedHooksOnly`.
7. **Claude Code only.** Codex doesn't let hooks replace tool output yet (openai/codex#38135).
