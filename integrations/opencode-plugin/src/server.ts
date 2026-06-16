import { ObsignaPlugin } from "./plugin.js";

/**
 * OpenCode server-plugin entry point.
 *
 * opencode resolves a `kind: "server"` plugin through this package's
 * `exports["./server"]` and reads the module's **default** export, expecting a
 * V1 plugin descriptor: an object whose `server` field is the plugin function
 * (see opencode's `readV1Plugin` / `resolvePackageEntrypoint`).
 *
 * This entry deliberately default-exports *only* `{ server }`. The library
 * barrel (`./index.ts`) also exports values that are not plugin functions
 * (`DEFAULT_ACTION_MAP`, `ReceiptRecorder`, config helpers, the factory); if
 * opencode fell back to its legacy loader — which iterates `Object.values(mod)`
 * and calls each as a plugin — those would throw "Plugin export is not a
 * function". Providing a valid V1 default export keeps opencode on the V1 path
 * and never reaches that fallback.
 */
export default { server: ObsignaPlugin };
