// MCP tool-call interception gateway — design ported from AGT's Python
// agent_os/mcp_gateway.py (microsoft/agent-governance-toolkit,
// commit 359a2332f57d9000924baba269ed24e4e15ad8b0). No AGT source was
// copied and this module has zero runtime dependencies on AGT or anything
// else — only the *shape* of the interception pipeline was carried over:
//
//   - two gates, not one: request-side (interceptToolCall) and
//     response-side (interceptToolResponse)
//   - a staged evaluation pipeline where every decision carries the stage
//     that produced it, not just a bare allow/deny
//   - fail-closed at each pluggable call site (policy runtime, approval
//     callback, response scanner) instead of one blanket try/catch
//   - a policy "transform" (rewritten args) is refused, not silently
//     collapsed into allow/deny, because this gate's return type has
//     nowhere to put a rewrite
//   - redaction happens at the point of persisting an audit entry, not at
//     the point of deciding — policy evaluation sees raw params
//   - audit sink and rate-limit store are injected interfaces, so the
//     gateway doesn't care whether they're in-memory, a file, or Redis
//   - per-agent state, keyed by agent id, not one global counter

export type Stage =
  | "deny_list"
  | "builtin_pattern"
  | "runtime"
  | "approval_pending"
  | "approval_denied"
  | "approval_error"
  | "rate_limit"
  | "allowed"
  | "error";

export interface GatewayDecision {
  allowed: boolean;
  reason: string;
  stage: Stage;
}

export interface ThreatMatch {
  category: string;
  description: string;
}

export interface ResponseDecision {
  allowed: boolean;
  reason: string;
  content: string | null;
  threats: ThreatMatch[];
  action: "allowed" | "logged" | "sanitized" | "blocked" | "error";
}

export interface AuditEntry {
  timestamp: number;
  agentId: string;
  toolName: string;
  direction: "request" | "response";
  parameters?: Record<string, unknown>;
  allowed: boolean;
  reason: string;
  stage?: Stage;
  threats?: string[];
}

export interface AuditSink {
  record(entry: AuditEntry): void;
}

export interface RateLimitStore {
  getCount(agentId: string): number;
  increment(agentId: string): void;
  reset(agentId: string): void;
}

export interface PolicyResult {
  allowed: boolean;
  reason?: string;
  /** Present when the runtime wants to rewrite the call's arguments rather
   *  than a flat allow/deny. This gate cannot apply a rewrite, so it
   *  refuses instead of guessing — see evaluate() below. */
  transform?: Record<string, unknown>;
}

export interface PolicyRuntime {
  evaluatePreToolCall(input: {
    agentId: string;
    toolName: string;
    args: Record<string, unknown>;
    callId: string;
  }): PolicyResult | Promise<PolicyResult>;
}

export interface ScanResult {
  safe: boolean;
  threats: ThreatMatch[];
}

export interface ResponseScanner {
  scan(content: string, toolName: string): ScanResult | Promise<ScanResult>;
  /** Optional — only needed if responsePolicy is "sanitize". */
  sanitize?(
    content: string,
    toolName: string,
  ): { sanitized: string; removed: ThreatMatch[] };
}

export type ApprovalCallback = (
  agentId: string,
  toolName: string,
  params: Record<string, unknown>,
) => "approved" | "denied" | Promise<"approved" | "denied">;

export type ResponsePolicy = "block" | "sanitize" | "log";

const HARD_BLOCK_CATEGORIES = new Set(["pii_leak", "data_exfiltration"]);

// Cheap, local, no-dependency checks — deliberately evaluated before the
// (possibly expensive/networked) policy runtime call.
const BUILTIN_DANGEROUS_PATTERNS: RegExp[] = [
  /\b\d{3}-\d{2}-\d{4}\b/, // SSN
  /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, // credit card
  /;\s*(rm|del|format|mkfs)\b/i, // destructive commands
  /\$\([^)]*\)/, // command substitution
  /`[^`]+`/, // backtick execution
];

export class InMemoryRateLimitStore implements RateLimitStore {
  private counts = new Map<string, number>();
  getCount(agentId: string): number {
    return this.counts.get(agentId) ?? 0;
  }
  increment(agentId: string): void {
    this.counts.set(agentId, this.getCount(agentId) + 1);
  }
  reset(agentId: string): void {
    this.counts.set(agentId, 0);
  }
}

export class InMemoryAuditSink implements AuditSink {
  readonly entries: AuditEntry[] = [];
  record(entry: AuditEntry): void {
    this.entries.push(entry);
  }
}

interface AgentContext {
  callCount: number;
}

export interface McpGatewayOptions {
  runtime: PolicyRuntime;
  deniedTools?: string[];
  sensitiveTools?: string[];
  approvalCallback?: ApprovalCallback;
  enableBuiltinSanitization?: boolean;
  rateLimit?: number;
  rateLimitStore?: RateLimitStore;
  auditSink?: AuditSink;
  /** Pass null to disable response scanning entirely. */
  responseScanner?: ResponseScanner | null;
  responsePolicy?: ResponsePolicy;
  /** Applied only to what's written to the audit sink — policy evaluation
   *  always sees the raw params. Default is identity; pass a real redactor
   *  for anything that touches real data. */
  redact?: (params: Record<string, unknown>) => Record<string, unknown>;
  clock?: () => number;
}

export class McpGateway {
  private readonly runtime: PolicyRuntime;
  private readonly deniedTools: Set<string>;
  private readonly sensitiveTools: Set<string>;
  private readonly approvalCallback?: ApprovalCallback;
  private readonly enableBuiltinSanitization: boolean;
  private readonly rateLimit: number;
  private readonly rateLimitStore: RateLimitStore;
  private readonly auditSink: AuditSink;
  private readonly responseScanner: ResponseScanner | null;
  private readonly responsePolicy: ResponsePolicy;
  private readonly redact: (
    params: Record<string, unknown>,
  ) => Record<string, unknown>;
  private readonly clock: () => number;
  private readonly contexts = new Map<string, AgentContext>();

  constructor(opts: McpGatewayOptions) {
    this.runtime = opts.runtime;
    this.deniedTools = new Set(opts.deniedTools ?? []);
    this.sensitiveTools = new Set(opts.sensitiveTools ?? []);
    this.approvalCallback = opts.approvalCallback;
    this.enableBuiltinSanitization = opts.enableBuiltinSanitization ?? true;
    this.rateLimit = opts.rateLimit ?? 100;
    this.rateLimitStore = opts.rateLimitStore ?? new InMemoryRateLimitStore();
    this.auditSink = opts.auditSink ?? new InMemoryAuditSink();
    this.responseScanner =
      opts.responseScanner === undefined ? null : opts.responseScanner;
    this.responsePolicy = opts.responsePolicy ?? "block";
    this.redact = opts.redact ?? ((params) => params);
    this.clock = opts.clock ?? (() => Date.now());
  }

  // ── Request-side interception ──────────────────────────────────────

  async interceptToolCall(
    agentId: string,
    toolName: string,
    params: Record<string, unknown>,
  ): Promise<GatewayDecision> {
    let decision: GatewayDecision;
    try {
      decision = await this.evaluate(agentId, toolName, params);
    } catch {
      // Fail closed: deny on any unexpected error in the pipeline itself,
      // not just the sites we anticipated below.
      decision = {
        allowed: false,
        reason: "Internal gateway error — access denied (fail closed)",
        stage: "error",
      };
    }

    this.auditSink.record({
      timestamp: this.clock(),
      agentId,
      toolName,
      direction: "request",
      parameters: this.redact(params),
      allowed: decision.allowed,
      reason: decision.reason,
      stage: decision.stage,
    });

    return decision;
  }

  private async evaluate(
    agentId: string,
    toolName: string,
    params: Record<string, unknown>,
  ): Promise<GatewayDecision> {
    if (this.deniedTools.has(toolName)) {
      return {
        allowed: false,
        reason: `Tool '${toolName}' is on the deny list`,
        stage: "deny_list",
      };
    }

    if (this.enableBuiltinSanitization) {
      const paramText = safeStringify(params);
      for (const pattern of BUILTIN_DANGEROUS_PATTERNS) {
        if (pattern.test(paramText)) {
          return {
            allowed: false,
            reason: `Parameters matched dangerous pattern: ${pattern.source}`,
            stage: "builtin_pattern",
          };
        }
      }
    }

    const context = this.contextFor(agentId);
    let result: PolicyResult;
    try {
      result = await this.runtime.evaluatePreToolCall({
        agentId,
        toolName,
        args: params,
        callId: `mcp-${context.callCount + 1}`,
      });
    } catch {
      // Fail closed: the pluggable policy runtime is the most likely thing
      // to throw (network call, native binding, etc.) — catch it here
      // specifically, not just at the outer interceptToolCall boundary.
      return {
        allowed: false,
        reason: "Policy runtime error — access denied (fail closed)",
        stage: "error",
      };
    }

    if (result.transform) {
      // The runtime wants to rewrite the call's arguments. GatewayDecision
      // only has room for allow/deny, so forwarding the *original* args
      // while the policy believes they were rewritten would be silently
      // wrong. Refuse instead of guessing, until this gate's interface can
      // actually carry a rewrite.
      return {
        allowed: false,
        reason:
          "Runtime returned a transform this gateway cannot apply to tool " +
          `arguments (reason=${result.reason ?? "unspecified"})`,
        stage: "runtime",
      };
    }
    if (!result.allowed) {
      return {
        allowed: false,
        reason: result.reason ?? "Runtime denied tool call",
        stage: "runtime",
      };
    }

    if (this.sensitiveTools.has(toolName)) {
      if (!this.approvalCallback) {
        return {
          allowed: false,
          reason: "Awaiting human approval",
          stage: "approval_pending",
        };
      }
      let status: "approved" | "denied";
      try {
        status = await this.approvalCallback(agentId, toolName, params);
      } catch {
        return {
          allowed: false,
          reason: "Approval callback error — access denied (fail closed)",
          stage: "approval_error",
        };
      }
      if (status !== "approved") {
        return {
          allowed: false,
          reason: "Human approval denied",
          stage: "approval_denied",
        };
      }
    }

    if (this.rateLimitStore.getCount(agentId) >= this.rateLimit) {
      return {
        allowed: false,
        reason: `Agent '${agentId}' exceeded call budget (${this.rateLimit})`,
        stage: "rate_limit",
      };
    }
    this.rateLimitStore.increment(agentId);
    context.callCount += 1;
    return { allowed: true, reason: "Allowed by runtime", stage: "allowed" };
  }

  // ── Response-side interception ─────────────────────────────────────

  async interceptToolResponse(
    agentId: string,
    toolName: string,
    responseContent: unknown,
  ): Promise<ResponseDecision> {
    const text =
      typeof responseContent === "string"
        ? responseContent
        : safeStringify(responseContent);

    if (!this.responseScanner) {
      const decision: ResponseDecision = {
        allowed: true,
        reason: "No response scanner configured",
        content: text,
        threats: [],
        action: "allowed",
      };
      this.recordResponseAudit(agentId, toolName, decision);
      return decision;
    }

    let scan: ScanResult;
    try {
      scan = await this.responseScanner.scan(text, toolName);
    } catch {
      // Fail closed: a scanner that throws is treated the same as a
      // scanner that found something — we cannot conclude the response is
      // safe just because the check itself broke.
      const decision: ResponseDecision = {
        allowed: false,
        reason: "Response scanner error — blocked (fail closed)",
        content: null,
        threats: [],
        action: "error",
      };
      this.recordResponseAudit(agentId, toolName, decision);
      return decision;
    }

    if (scan.safe) {
      const decision: ResponseDecision = {
        allowed: true,
        reason: "Response clean",
        content: text,
        threats: [],
        action: "allowed",
      };
      this.recordResponseAudit(agentId, toolName, decision);
      return decision;
    }

    const decision = await this.applyResponsePolicy(text, toolName, scan);
    this.recordResponseAudit(agentId, toolName, decision);
    return decision;
  }

  private async applyResponsePolicy(
    text: string,
    toolName: string,
    scan: ScanResult,
  ): Promise<ResponseDecision> {
    if (this.responsePolicy === "log") {
      return {
        allowed: true,
        reason: `Response has ${scan.threats.length} threat(s) — logged`,
        content: text,
        threats: scan.threats,
        action: "logged",
      };
    }

    if (this.responsePolicy === "sanitize") {
      const hardBlocked = scan.threats.filter((t) =>
        HARD_BLOCK_CATEGORIES.has(t.category),
      );
      if (hardBlocked.length > 0) {
        // Some categories (PII, exfiltration) can't be safely stripped
        // from free-text prose — those are still a hard block even in
        // "sanitize" mode.
        const categories = uniqueSorted(hardBlocked.map((t) => t.category));
        return {
          allowed: false,
          reason: `Response blocked — ${categories.join(", ")} cannot be sanitized`,
          content: null,
          threats: scan.threats,
          action: "blocked",
        };
      }
      if (!this.responseScanner?.sanitize) {
        return {
          allowed: false,
          reason: "Response blocked — no sanitizer available (fail closed)",
          content: null,
          threats: scan.threats,
          action: "blocked",
        };
      }
      const { sanitized, removed } = this.responseScanner.sanitize(
        text,
        toolName,
      );
      // Trust but verify: don't take the sanitizer's word that it worked —
      // re-scan its own output. A sanitizer reporting success is not the
      // same as the threat actually being gone.
      const sanitizeReportedError = removed.some((t) => t.category === "error");
      let residualThreat = false;
      try {
        const rescan = await this.responseScanner.scan(sanitized, toolName);
        residualThreat = !rescan.safe;
      } catch {
        residualThreat = true; // can't verify → treat as still unsafe
      }
      if (sanitizeReportedError || residualThreat) {
        return {
          allowed: false,
          reason: "Response blocked — sanitization incomplete (fail closed)",
          content: null,
          threats: scan.threats,
          action: "blocked",
        };
      }
      return {
        allowed: true,
        reason: `Response sanitized — ${scan.threats.length} threat(s) stripped`,
        content: sanitized,
        threats: scan.threats,
        action: "sanitized",
      };
    }

    // "block" (default)
    const categories = uniqueSorted(scan.threats.map((t) => t.category));
    return {
      allowed: false,
      reason: `Response blocked — ${categories.join(", ")} detected`,
      content: null,
      threats: scan.threats,
      action: "blocked",
    };
  }

  private recordResponseAudit(
    agentId: string,
    toolName: string,
    decision: ResponseDecision,
  ): void {
    // Never persist response content — only threat categories. Logging
    // the leak while blocking it defeats the point.
    this.auditSink.record({
      timestamp: this.clock(),
      agentId,
      toolName,
      direction: "response",
      allowed: decision.allowed,
      reason: decision.reason,
      threats: decision.threats.map((t) => t.category),
    });
  }

  // ── Per-agent state ─────────────────────────────────────────────────

  private contextFor(agentId: string): AgentContext {
    let ctx = this.contexts.get(agentId);
    if (!ctx) {
      ctx = { callCount: 0 };
      this.contexts.set(agentId, ctx);
    }
    return ctx;
  }

  getAgentCallCount(agentId: string): number {
    return this.rateLimitStore.getCount(agentId);
  }

  resetAgentBudget(agentId: string): void {
    this.rateLimitStore.reset(agentId);
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort();
}
