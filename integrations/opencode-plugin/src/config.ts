/**
 * Configuration for the OpenCode plugin. Every field is optional; the plugin
 * resolves a usable config from (in precedence order) an explicit config
 * object, environment variables, then built-in defaults.
 *
 * Environment variables (read by {@link resolveConfig}):
 *   - `AGENT_RECEIPTS_CHANNEL`  → {@link AgentReceiptsPluginConfig.channel}
 *   - `AGENT_RECEIPTS_STRICT`   → {@link AgentReceiptsPluginConfig.strict}
 *     (truthy: "1", "true", "yes", case-insensitive)
 *   - `AGENT_RECEIPTS_ALLOW`    → {@link AgentReceiptsPluginConfig.allow}
 *     (comma-separated tool names)
 *   - `AGENT_RECEIPTS_DENY`     → {@link AgentReceiptsPluginConfig.deny}
 *     (comma-separated tool names)
 *
 * The daemon socket path is NOT read here: when `socketPath` is unset the
 * underlying `DaemonEmitter` resolves it from `AGENTRECEIPTS_SOCKET` and the
 * per-OS default, keeping a single source of truth across SDKs.
 */
export interface AgentReceiptsPluginConfig {
	/** Receipt channel label. Defaults to `"opencode"`. */
	channel?: string;
	/**
	 * Override the daemon Unix-socket path. When unset, the `DaemonEmitter`
	 * resolves it from `AGENTRECEIPTS_SOCKET` then the per-OS default.
	 */
	socketPath?: string;
	/**
	 * Failure posture (ADR-0025). Default (`false`) is catch-and-warn: a tool
	 * call is NEVER aborted because the daemon is unreachable; the drop is
	 * logged loudly via {@link debugLog}. When `true`, an emit failure is
	 * re-thrown from the `tool.execute.after` hook so OpenCode surfaces a
	 * broken audit pipeline rather than silently dropping receipts.
	 */
	strict?: boolean;
	/**
	 * Tool allow-list. When set (non-empty), ONLY these tool names produce
	 * receipts. When unset, all tools are eligible (subject to {@link deny}).
	 */
	allow?: string[];
	/** Tool deny-list. These tool names never produce receipts. Wins over {@link allow}. */
	deny?: string[];
	/**
	 * Per-tool action-type overrides, merged over the built-in
	 * `DEFAULT_ACTION_MAP`. Keys are OpenCode tool names, values are taxonomy
	 * action types (e.g. `{ webfetch: "system.browser.navigate" }`).
	 */
	actionMap?: Record<string, string>;
	/**
	 * Sink for loud drop diagnostics and emit failures. Defaults to a
	 * `console.warn` writer prefixed with `[agent-receipts]`.
	 */
	debugLog?: (message: string, attrs: Record<string, string>) => void;
}

/** Fully-resolved config the recorder operates on. */
export interface ResolvedConfig {
	channel: string;
	socketPath?: string;
	strict: boolean;
	/** `null` means "no allow-list — all tools eligible". */
	allow: ReadonlySet<string> | null;
	deny: ReadonlySet<string>;
	actionMap: Readonly<Record<string, string>>;
	debugLog: (message: string, attrs: Record<string, string>) => void;
}

const TRUTHY = new Set(["1", "true", "yes", "on"]);

function parseList(value: string | undefined): string[] {
	if (!value) {
		return [];
	}
	return value
		.split(",")
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}

function defaultDebugLog(message: string, attrs: Record<string, string>): void {
	console.warn(`[agent-receipts] ${message}`, attrs);
}

/**
 * Resolve a {@link ResolvedConfig} from an explicit config object layered over
 * environment variables and defaults. `env` is injectable for testing; real
 * callers omit it and `process.env` is used.
 */
export function resolveConfig(
	config: AgentReceiptsPluginConfig = {},
	env: NodeJS.ProcessEnv = process.env,
): ResolvedConfig {
	const channel = config.channel ?? env.AGENT_RECEIPTS_CHANNEL ?? "opencode";

	const strict =
		config.strict ??
		(env.AGENT_RECEIPTS_STRICT
			? TRUTHY.has(env.AGENT_RECEIPTS_STRICT.toLowerCase())
			: false);

	const allowList = config.allow ?? parseList(env.AGENT_RECEIPTS_ALLOW);
	const denyList = config.deny ?? parseList(env.AGENT_RECEIPTS_DENY);

	return {
		channel,
		socketPath: config.socketPath,
		strict,
		allow: allowList.length > 0 ? new Set(allowList) : null,
		deny: new Set(denyList),
		actionMap: config.actionMap ?? {},
		debugLog: config.debugLog ?? defaultDebugLog,
	};
}

/** Returns true when a tool name should produce a receipt under `config`. */
export function shouldEmit(config: ResolvedConfig, tool: string): boolean {
	if (config.deny.has(tool)) {
		return false;
	}
	if (config.allow !== null && !config.allow.has(tool)) {
		return false;
	}
	return true;
}
