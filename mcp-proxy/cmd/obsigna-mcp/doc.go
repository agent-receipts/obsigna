// Command obsigna-mcp sits between an MCP client and an MCP server,
// transparently intercepting every tool call to classify it, evaluate YAML
// policy rules (pass/flag/pause/block), run optional approval workflows, and
// forward completed events to the agent-receipts daemon for signing and
// persistence.
//
// It is the long-running stdio proxy launched via `obsigna mcp run`, which
// execs straight into this image (ADR-0030, ADR-0033). The legacy `mcp-proxy`
// binary is a thin deprecation shim that forwards here (see ../mcp-proxy).
//
// Usage:
//
//	obsigna-mcp [flags] <command> [args...]
//	obsigna-mcp serve   [flags] <command> [args...]
//	obsigna-mcp doctor  [-rules <file>] [-approver <url>] [-json]
//	obsigna-mcp init    [-name <name>] [-http-port <port>] [-no-approval]
//
// The default subcommand is serve, which wraps the given MCP server command
// and proxies its stdin/stdout, applying policy and emitting receipts.
//
// See https://agentreceipts.ai/mcp-proxy/ for full documentation.
package main
