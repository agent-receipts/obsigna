import type { ActionTypeEntry } from "./types.js";

const FILESYSTEM_ACTIONS: readonly ActionTypeEntry[] = [
	{
		type: "filesystem.file.create",
		description: "Create a file",
		risk_level: "low",
	},
	{
		type: "filesystem.file.read",
		description: "Read a file",
		risk_level: "low",
	},
	{
		type: "filesystem.file.modify",
		description: "Modify a file",
		risk_level: "medium",
	},
	{
		type: "filesystem.file.delete",
		description: "Delete a file",
		risk_level: "high",
	},
	{
		type: "filesystem.file.move",
		description: "Move or rename a file",
		risk_level: "medium",
	},
	{
		type: "filesystem.directory.create",
		description: "Create a directory",
		risk_level: "low",
	},
	{
		type: "filesystem.directory.delete",
		description: "Delete a directory",
		risk_level: "high",
	},
	{
		type: "filesystem.directory.list",
		description: "List directory contents",
		risk_level: "low",
	},
];

const SYSTEM_ACTIONS: readonly ActionTypeEntry[] = [
	{
		type: "system.application.launch",
		description: "Launch an application",
		risk_level: "low",
	},
	{
		type: "system.application.control",
		description: "Control an application via UI automation",
		risk_level: "medium",
	},
	{
		type: "system.settings.modify",
		description: "Modify system or app settings",
		risk_level: "high",
	},
	{
		type: "system.command.execute",
		description: "Execute a shell command",
		risk_level: "high",
	},
	{
		type: "system.code.execute",
		description: "Execute code in a sandbox code interpreter",
		risk_level: "high",
	},
	{
		type: "system.pty.open",
		description: "Open an interactive PTY session",
		risk_level: "critical",
	},
	{
		type: "system.pty.close",
		description: "Close a PTY session",
		risk_level: "high",
	},
	{
		type: "system.browser.navigate",
		description: "Navigate to a URL",
		risk_level: "low",
	},
	{
		type: "system.browser.form_submit",
		description: "Submit a web form",
		risk_level: "medium",
	},
	{
		type: "system.browser.authenticate",
		description: "Log into a service",
		risk_level: "high",
	},
];

const DATA_ACTIONS: readonly ActionTypeEntry[] = [
	{
		type: "data.api.read",
		description: "Read data from an external API",
		risk_level: "low",
	},
	{
		type: "data.api.write",
		description: "Write data to an external API",
		risk_level: "medium",
	},
	{
		type: "data.api.delete",
		description: "Delete data via an external API",
		risk_level: "high",
	},
];

const NETWORK_ACTIONS: readonly ActionTypeEntry[] = [
	{
		type: "network.egress.observed",
		description:
			"Observed outbound network connection crossing a sandbox boundary",
		risk_level: "medium",
	},
];

const UNKNOWN_ACTION: ActionTypeEntry = {
	type: "unknown",
	description: "Tool call that does not map to any known action type",
	risk_level: "medium",
};

const ALL_ACTIONS: readonly ActionTypeEntry[] = [
	...FILESYSTEM_ACTIONS,
	...SYSTEM_ACTIONS,
	...DATA_ACTIONS,
	...NETWORK_ACTIONS,
	UNKNOWN_ACTION,
];

const ACTION_MAP = new Map<string, ActionTypeEntry>(
	ALL_ACTIONS.map((entry) => [entry.type, entry]),
);

export function getActionType(type: string): ActionTypeEntry | undefined {
	return ACTION_MAP.get(type);
}

export function resolveActionType(type: string): ActionTypeEntry {
	return ACTION_MAP.get(type) ?? UNKNOWN_ACTION;
}

export {
	ALL_ACTIONS,
	DATA_ACTIONS,
	FILESYSTEM_ACTIONS,
	NETWORK_ACTIONS,
	SYSTEM_ACTIONS,
	UNKNOWN_ACTION,
};
