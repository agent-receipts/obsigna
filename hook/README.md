# obsigna-hook

Short-lived hook binary for [Agent Receipts](https://github.com/agent-receipts/obsigna). Invoked by agent runtimes on `PostToolUse` events — reads a JSON frame from stdin, maps it to an audit event, and forwards it to `obsigna-daemon` over a Unix-domain socket. It exits 0 silently when the frame is unreadable or the runtime isn't recognised; once the runtime is identified, a failure to record the receipt exits 1 with a stderr message (surfacing a broken audit pipeline rather than dropping receipts). It never pauses or modifies the tool call.

> **Renamed from `agent-receipts-hook`** (ADR-0036). The old `agent-receipts-hook` binary still ships as a thin deprecation shim that forwards to `obsigna-hook`, so existing runtime hook configs keep working — point new configs at `obsigna-hook`. Homebrew now ships the hook in the umbrella `obsigna` formula (ADR-0034), which installs both `obsigna-hook` and the `agent-receipts-hook` shim.

## Install

```bash
brew install agent-receipts/tap/obsigna
# or
go install github.com/agent-receipts/ar/hook/cmd/obsigna-hook@latest
```

Requires `obsigna-daemon` to be running to capture events.

## Claude Code setup

In your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "obsigna-hook"
          }
        ]
      }
    ]
  }
}
```

## Supported runtimes

| Runtime | Detection | Format flag |
|---------|-----------|-------------|
| Claude Code | `CLAUDE_SESSION_ID` env var | `--format claude-code` |

Auto-detection runs when `--format` is unset. Use `--format` to force a specific format.

## License

Apache-2.0 — see [LICENSE](../LICENSE).
