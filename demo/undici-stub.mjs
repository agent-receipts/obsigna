// Stub replacing undici for the opencode plugin bundle.
// The plugin uses DaemonEmitter (Unix socket via node:net) — never HttpEmitter.
// Stubbing undici prevents its webidl internals from failing at load time.
export class Client {}
export class Pool {}
export class Agent {}
export class Dispatcher {}
export class BalancedPool {}
export class ProxyAgent {}
export class EnvHttpProxyAgent {}
export class RetryAgent {}
export class RetryHandler {}
export class MockPool {}
export class MockAgent {}
export const fetch = undefined;
export const getGlobalDispatcher = () => null;
export const setGlobalDispatcher = () => {};
