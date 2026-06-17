// Loads the IN-TREE @obsigna/opencode-plugin (installed into this workspace's
// node_modules from the freshly built tarball by ../start.sh) the documented
// way: a file under .opencode/plugin/ that exports a configured plugin instance.
//
// strict: true makes the demo fail LOUDLY if a receipt cannot be emitted —
// "verified end-to-end" means the path either works or the session errors, never
// a silent pass. deny skips read-only tool noise so every receipt is a mutation.
import { createObsignaPlugin } from "@obsigna/opencode-plugin";

export const ObsignaPlugin = createObsignaPlugin({
	strict: true,
	deny: ["read", "glob", "grep", "list", "webfetch"],
});
