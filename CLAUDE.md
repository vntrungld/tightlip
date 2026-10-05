# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

tightlip is a Claude Code plugin (hooks only) that keeps secrets out of the model's context. The repo is both a plugin marketplace (`.claude-plugin/marketplace.json`) and the plugin itself (`plugins/tightlip/`); the marketplace is named `vntrungld`, the plugin `tightlip`, so its id is `tightlip@vntrungld`. Pure Python ≥ 3.8, standard library only — no dependencies, no build step. Requires Claude Code ≥ 2.1.121.

## Commands

```bash
python3 -m unittest discover -v tests                                  # full suite
python3 -m unittest tests.test_tightlip.PreToolUse.test_denied_commands  # single test
echo 'DB_PASSWORD=abc123xyz' | python3 plugins/tightlip/scripts/tightlip.py --filter  # redact stdin
python3 standalone/install.py --dry-run                                # preview standalone install merge
```

If tightlip is installed in the current Claude Code session, it will redact secret-looking values in your own tool output (test fixtures, `--filter` results). Placeholders like `[REDACTED:rule:id]` in output are the hook working, not a bug — and Write/Edit inputs containing a placeholder are denied.

## Architecture

Everything lives in one script, `plugins/tightlip/scripts/tightlip.py`, invoked for five hook events and dispatched on `hook_event_name` via `HANDLERS`:

- `SessionStart` → sets a folder-based `sessionTitle` so Claude Code doesn't send the first prompt to a title-generating model (which runs before `UserPromptSubmit` can block).
- `UserPromptSubmit` → blocks prompts containing secrets; also blocks once after a `PostToolBatch` gate trip (via a marker file under `$XDG_STATE_HOME/tightlip/blocked-<session>`).
- `PreToolUse` → `check_command()` parses shell commands (`split_segments` + `strip_wrappers`) to deny env dumps, `echo $SECRET`, credential-printing CLIs (`secret_cli`), `kubectl get secret -o …`, and reads of credential paths (`CRED_PATH_RES`). Write/Edit/MCP inputs containing a placeholder are denied so placeholders never overwrite real secrets. A command's stdout being piped/redirected ("consumed") changes the verdict.
- `PostToolUse` → `Redactor.walk()` rewrites every string in `tool_response` and returns it as `updatedToolOutput`. The JSON shape must be preserved exactly — Claude Code ignores replacements that don't match the tool's output schema.
- `PostToolBatch` → final gate: re-scans what the model is about to receive (failed-command output can't be rewritten) and returns `decision: block` if anything is left.

The `Redactor` applies three rule layers in order: `FORMAT_RULES` (known token prefixes), `CONTEXT_RULES` (URL creds, auth headers, CLI flags…), then `KV_RULES` (key/value forms: dotenv, ini, k8s name/value, artisan dots, YAML/JSON colon, PHP arrow). KV matches are judged by key sensitivity (`is_sensitive_key`) plus a value check: `strict_value_is_secret` for UPPER_CASE dotenv-style keys, `loose_value_is_secret` for code/config keys, `high_entropy_literal` for non-sensitive UPPER keys. Much of the code exists to avoid false positives on source code, validation rules, translations, hashes and references (`${…}`, `env(...)`). Placeholders are `[REDACTED:<rule>:<hmac8>]` keyed by a per-machine key in `$XDG_CONFIG_HOME/tightlip/key`; they preserve newline count so Read line numbers stay correct.

Options come from `option()`/`flag()`, which read `TIGHTLIP_<NAME>` (standalone) or `CLAUDE_PLUGIN_OPTION_<NAME>` (plugin `userConfig` in `plugin.json`).

Two install paths share the same script: the plugin (`plugins/tightlip/hooks/hooks.json`, uses `${CLAUDE_PLUGIN_ROOT}`) and standalone (`standalone/install.py` copies the script to `~/.claude/hooks/` and merges `standalone/settings.example.json`). Changes to hook events/matchers must be made in both `hooks.json` and `settings.example.json`.

## Conventions

- **Tests must never contain a literal token.** Fake credentials are generated at runtime with `rnd()`, and known prefixes are split with `p("gh", "p_")` so neither secret scanners nor GitHub push protection flag the file. New false-positive regressions go in `NOT_SECRETS`; new formats go in `SAMPLES`.
- Tests point `XDG_CONFIG_HOME`/`XDG_STATE_HOME` at temp dirs; keep it that way so the real HMAC key and markers aren't touched.
- Messages shown to the user (`systemMessage`, block `reason`s, installer output, `README.vi.md`) are in Vietnamese, `README.md` is the English version of the README (keep both in sync); messages read by the model (`permissionDecisionReason`, `additionalContext`) are in English.
- Releasing: bump `version` in `plugins/tightlip/.claude-plugin/plugin.json` (users don't get updates otherwise) and keep `VERSION` in `tightlip.py` in sync.
- Hook handlers must never crash the session: `main()` swallows exceptions, exits 0, and warns that output wasn't scanned.
