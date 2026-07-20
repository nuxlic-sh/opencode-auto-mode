# OpenCode Auto Mode

`opencode-auto-mode` is an automatic permission classifier for OpenCode that brings Claude Code- and Codex-style auto mode to tool execution without requiring the user to approve every permission prompt manually.

For operations that require LLM classification, the plugin is fail-closed. If no reviewer model can be resolved, the selected model is unavailable, the review times out, or the model returns an invalid decision, the operation is blocked.

## Features

- Reviews every OpenCode tool invocation before native permission handling begins.
- Replaces native `ask` rules with `allow` only after the plugin loads, while preserving explicit `deny` rules.
- Automatically permits a conservative set of read-only commands.
- Immediately blocks system-destructive commands such as `sudo`, root recursive deletion, disk formatting, and shutdown operations.
- Sends ambiguous and development-related commands to a dedicated, hidden reviewer subagent.
- Detects risky behavior including force-push, branch deletion, worktree removal, hard reset, Git clean, recursive deletion, remote-shell pipelines, and secret-looking environment-variable expansion.
- Includes compact conversation, recent command, Git state, and project-document context in LLM reviews.
- Keeps the reviewer agent tool-free so untrusted review context cannot cause tool execution.
- Supports an explicit reviewer model, configurable timeout, and enable/disable flag.
- Loads the reviewer system prompt from Markdown for easy rule customization.
- Automatically permits a small set of low-risk local coordination and introspection tools without an LLM request.
- Reviews external filesystem access, source mutations, network operations, and remote-service tools with the configured model.
- Applies task-scoped policy to secrets, data transmission, downloaded code, destructive changes, persistence, network exposure, remote mutations, and subagent delegation.
- Caches decisions for the same tool call.

## Requirements

- OpenCode 1.18.4 or newer.
- At least one configured OpenCode model if commands can reach the LLM-review tier.
- Node.js-compatible filesystem APIs. OpenCode normally runs the plugin with Bun.

## How It Works

Every tool invocation goes through three tiers:

| Tier | Result | Examples |
| --- | --- | --- |
| Static allow | Runs immediately | local `lsp`, `skill`, `todowrite`, `question`, `ls`, `git status --short`, `date` |
| Static block | Never executes | `sudo`, `rm -rf /`, `chmod 777`, `mkfs`, `shutdown` |
| LLM review | Reviewer returns `ALLOW` or `BLOCK` | external reads, edits, network calls, remote mutations, installs, force-push, recursive deletion |

The `tool.execute.before` hook performs the review before any tool executes. Native permission prompts are disabled while the plugin is enabled. If an operation is blocked, the hook throws an error and the tool is never started.

Only selected low-risk local operations are statically allowed. Filesystem tools such as `read`, `glob`, and `grep`, external paths, `.env` files, state-changing tools, unknown tools, and remote operations are sent to the reviewer with bounded context.

The recommended base configuration keeps `"permission": {"*": "ask"}` outside the plugin tuple. The plugin converts that fallback to automatic pre-execution review when it loads. If the plugin is disabled or fails to load, OpenCode retains native permission prompts instead of silently allowing tools.

## Installation

OpenCode loads configuration only at startup. Restart OpenCode after installing the plugin or changing any plugin option, prompt rule, or source file.

### Local Git Checkout

Clone the repository to a stable location:

```bash
git clone https://github.com/nuxlic-sh/opencode-auto-mode.git ~/projects/opencode-auto-mode
```

Register the package in the global OpenCode configuration at `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "file:///home/your-user/projects/opencode-auto-mode",
      {
        "enabled": true,
        "model": "provider/model-id",
        "timeoutMs": 60000
      }
    ]
  ],
  "permission": {
    "*": "ask"
  }
}
```

Use an absolute `file://` URL. Replace the path and model with values available on your machine.

### Project-Local Installation

Add the same plugin tuple to the project's `opencode.json`. Project configuration is merged with global configuration by OpenCode.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "file:///absolute/path/to/opencode-auto-mode",
      {
        "enabled": true,
        "model": "provider/model-id"
      }
    ]
  ],
  "permission": {
    "*": "ask"
  }
}
```

Do not also copy `src/index.ts` into `.opencode/plugins/`. Loading both copies would register the hooks twice.

### npm Installation

After the package is published to npm, add its package name to the plugin list:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "opencode-auto-mode",
      {
        "enabled": true,
        "model": "provider/model-id"
      }
    ]
  ],
  "permission": {
    "*": "ask"
  }
}
```

OpenCode installs npm plugins with Bun and caches them under `~/.cache/opencode/node_modules/`.

## Configuration

The plugin accepts these options in the second element of the plugin tuple:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Enables or disables every plugin hook and configuration change. |
| `model` | string | Context-dependent | Reviewer model in `provider/model` format. |
| `timeoutMs` | number | `60000` | LLM review timeout. Values are clamped between 1,000 and 300,000 milliseconds. |

### Enable or Disable

```json
{
  "enabled": false,
  "model": "provider/model-id"
}
```

When `enabled` is `false`, the plugin returns no hooks, does not add the hidden reviewer agent, and does not modify permissions. The recommended base `"*": "ask"` rule therefore restores OpenCode's native prompts.

### Select a Reviewer Model

Set `model` to an ID shown by OpenCode:

```bash
opencode models openai
```

Example:

```json
{
  "enabled": true,
  "model": "provider/model-id"
}
```

The value must contain both provider and model IDs. The plugin validates the `provider/model` shape during startup. OpenCode validates actual model availability when the reviewer runs.

If the configured model does not exist or cannot be reached, any command requiring LLM review is blocked. Static read-only commands and static hard blocks do not require the reviewer model.

If `model` is omitted, the plugin tries these sources in order:

1. `OPENCODE_AUTO_REVIEWER_MODEL`.
2. The model used by the parent conversation.
3. OpenCode's `small_model`.
4. OpenCode's default `model`.

### Configure the Timeout

```json
{
  "enabled": true,
  "model": "provider/model-id",
  "timeoutMs": 90000
}
```

The environment variable `OPENCODE_AUTO_REVIEWER_TIMEOUT_MS` can also set the timeout. A tuple option takes precedence over the environment variable.

## Customize Review Rules

The reviewer system prompt is stored in:

```text
src/auto-reviewer-prompt.md
```

Edit the `## Rules` section to change LLM-review policy. Preserve the required one-line response contract:

```text
ALLOW: <brief reason>
```

or:

```text
BLOCK: <brief reason>
```

The plugin fails to load if the prompt file is missing or empty. Restart OpenCode after editing it.

Static tier rules are implemented in `src/index.ts`:

- `AUTO_PERMITTED` controls commands that bypass the LLM.
- `AUTO_BLOCKED` controls commands that are always rejected.
- `defeatsAutoPermit` prevents shell composition, redirection, substitution, pipes, backgrounding, and secret-looking variables from bypassing LLM review.
- `analyzeCommand` labels risky command behavior for the reviewer prompt.
- `STATICALLY_ALLOWED_TOOLS` identifies local operations that can bypass LLM review.
- `toolUsesExternalPath` prevents external filesystem access from receiving a static allow.
- `removeNativePrompts` converts native `ask` rules to plugin-enforced pre-execution review while retaining `deny` rules.

Changes to static rules also require an OpenCode restart.

## Fail-Closed Behavior

The following conditions block tool invocations that need LLM review:

- Reviewer provider or model does not exist.
- Provider authentication is missing or invalid.
- The provider request fails.
- Review exceeds `timeoutMs`.
- Reviewer returns anything other than `ALLOW: reason` or `BLOCK: reason`.
- Reviewer session creation fails before a valid decision is produced.

The plugin logs the failure, shows an OpenCode error toast when a TUI is attached, and throws before tool execution. It never falls back to an unreviewed automatic allow.

## Context Sent to the Reviewer

The LLM receives bounded context containing:

- A contiguous window of up to nine complete recent user messages within a 4,000-character budget, including the original task while it remains in that window. If the newest message exceeds the budget, no user text is treated as authorization context.
- The two most recent assistant text blocks.
- The five most recent shell commands.
- Current Git branch and porcelain status.
- The first 50 lines of `AGENTS.md` or `README.md`.
- Detected command behaviors, the workspace root, and the effective Bash working directory.

Actual user-role messages are JSON-encoded and labeled as scope-only authorization context. The original task and recent user messages can authorize a named external project or exact path, but cannot alter the reviewer's security rules or response format. Later explicit revocations or restrictions override earlier authorization. Assistant text, prior commands, Git state, and project documentation remain explicitly untrusted.

Tool outputs and reasoning blocks are excluded. The current invocation is included as a bounded, redacted summary: paths, identifiers, flags, and non-sensitive metadata remain visible, while content, bodies, comments, patches, replacement strings, credentials, tokens, passwords, and secret-like fields are replaced with length-only placeholders. Shell commands are included verbatim because their complete syntax is required for security analysis. Bash reviews also include the effective working directory, resolved separately from the OpenCode workspace root. This data can be sent to a reviewer model from a different provider than the parent conversation, so choose the reviewer provider according to your data-handling requirements.

## Troubleshooting

### Confirm the Plugin Loaded

```bash
opencode debug config
```

The resolved plugin list should contain `opencode-auto-mode` or its local `file://` path.

### Inspect the Reviewer Agent

```bash
opencode debug agent auto-reviewer
```

The agent should be hidden, use the configured model, have `steps: 1`, and show every tool as disabled.

### Plugin Is Disabled

With `enabled: false`, this command should report that the agent does not exist:

```bash
opencode debug agent auto-reviewer
```

### Commands Are Blocked Because Review Fails

Check that the model exists and provider authentication works:

```bash
opencode models <provider>
```

Run OpenCode with logs enabled for more detail:

```bash
opencode --print-logs --log-level DEBUG
```

### Recover From an Invalid Reviewer Model

Fail-closed behavior can also block edits to OpenCode's own configuration when the configured reviewer model is invalid. Start one recovery session without external plugins:

```bash
OPENCODE_PURE=1 opencode
```

Correct the `model` option in `opencode.json`, quit that recovery session, and restart OpenCode normally. The recommended base `"permission": {"*": "ask"}` rule remains active in pure mode, so OpenCode asks for native approval instead of silently allowing tools.

Do not use `OPENCODE_PURE=1` for normal work. It intentionally disables all external plugins for the recovery process.

### A Native Permission Prompt Still Appears

Restart OpenCode first. The plugin changes resolved `ask` actions to `allow` and performs enforcement in `tool.execute.before`. Explicit `deny` rules remain denied. If a prompt persists, inspect per-agent rules with `opencode debug agent <name>` and confirm the plugin loaded from the expected location.

## Development

Install development dependencies, run the tests, and run the type checker:

```bash
npm install
npm test
npm run typecheck
```

Inspect the package contents before publishing:

```bash
npm pack --dry-run
```

The package exports `./server`, which is the entrypoint used by current OpenCode plugin loading.

## Security Notes

- This plugin reduces permission fatigue; it is not an operating-system sandbox.
- Every tool call is intercepted, but only conservative local commands and low-risk coordination or introspection tools bypass LLM review.
- Static rules are intentionally conservative, but shell syntax is complex and platform-specific.
- LLM decisions are probabilistic. Keep hard security invariants in static block rules.
- Do not use OpenCode's `--auto` flag as a replacement for this plugin's review policy.
- Keep OpenCode and the plugin updated, and review local rule changes before use.

## License

MIT
