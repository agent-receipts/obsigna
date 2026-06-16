/**
 * OpenCode plugin entry point. Wires the OpenCode `tool.execute` hooks and
 * session lifecycle events to the framework-agnostic {@link ReceiptRecorder}.
 *
 * This adapter is intentionally thin — all mapping and emission logic lives in
 * `recorder.ts` so it can be tested without an OpenCode runtime. The plugin
 * runs inside OpenCode and is an emitter only; it never signs or holds a key
 * (see `recorder.ts` for the full trust-boundary note).
 */

import type { Plugin } from "@opencode-ai/plugin";
import { type AgentReceiptsPluginConfig, resolveConfig } from "./config.js";
import { ReceiptRecorder } from "./recorder.js";

/**
 * Build an OpenCode {@link Plugin} that emits an Agent Receipt for every native
 * tool call. `userConfig` is layered over environment variables and defaults
 * (see {@link resolveConfig}). Use this when you want to configure the plugin
 * programmatically; most installs use the pre-built {@link AgentReceiptsPlugin}.
 */
export function createAgentReceiptsPlugin(
	userConfig: AgentReceiptsPluginConfig = {},
): Plugin {
	return async () => {
		const config = resolveConfig(userConfig);
		const recorder = new ReceiptRecorder(config);

		return {
			// Capture intent/params before the tool runs; the receipt is emitted
			// in the after-hook so it can include the outcome.
			"tool.execute.before": async (input, output) => {
				recorder.recordIntent({
					tool: input.tool,
					sessionID: input.sessionID,
					callID: input.callID,
					args: output.args,
				});
			},
			// One receipt per completed native tool call.
			"tool.execute.after": async (input, output) => {
				await recorder.recordResult({
					tool: input.tool,
					sessionID: input.sessionID,
					callID: input.callID,
					args: input.args,
					title: output.title,
					output: output.output,
					metadata: output.metadata,
				});
			},
			// Release the per-session emitter when a session is deleted. We do
			// NOT close on `session.idle`: OpenCode fires that after every turn,
			// not at session end, so closing there would churn sockets and could
			// tear down a connection mid-emit. Emitters otherwise live until
			// plugin teardown (`dispose`).
			event: async ({ event }) => {
				if (event.type === "session.deleted") {
					recorder.closeSession(event.properties.info.id);
				}
			},
			// Plugin teardown: close every emitter.
			dispose: async () => {
				recorder.close();
			},
		};
	};
}

/**
 * Pre-built plugin configured from environment variables and defaults. This is
 * the export OpenCode loads from `.opencode/plugin/`.
 */
export const AgentReceiptsPlugin: Plugin = createAgentReceiptsPlugin();
