import crypto from "node:crypto";

import type { AgentToolResult } from "@mariozechner/pi-agent-core";

import {
  type ExecApprovalsFile,
  addAllowlistEntry,
  evaluateShellAllowlist,
  maxAsk,
  minSecurity,
  recordAllowlistUse,
  requiresExecApproval,
  resolveExecApprovals,
  resolveExecApprovalsFromFile,
} from "../infra/exec-approvals.js";
import { buildNodeShellCommand } from "../infra/node-shell.js";
import { callGatewayTool } from "./tools/gateway.js";
import { listNodes, resolveNodeIdFromList } from "./tools/nodes-utils.js";
import type { ExecProcessHandle } from "./exec-process.js";
import { runExecProcess } from "./exec-process.js";
import { markBackgrounded, tail } from "./bash-process-registry.js";
import type { ExecToolDefaults, ExecToolDetails } from "./exec-types.js";

type ApprovalPromptOpts = {
  defaultApprovalTimeoutMs: number;
  defaultApprovalRequestTimeoutMs: number;
  approvalRunningNoticeMs: number;
  defaultNotifyTailChars: number;
  defaultTimeoutSec: number;
};

type ExecEventEmitter = (text: string, opts: { sessionKey?: string; contextKey?: string }) => void;

type ApplyPathPrepend = (
  env: Record<string, string>,
  prepend: string[],
  options?: { requireExisting?: boolean },
) => void;

function createApprovalSlug(id: string) {
  return id.slice(0, 8);
}

function normalizeNotifyOutput(value: string) {
  return value.replace(/\s+/g, " ").trim();
}

function getWarningText(warnings: string[]) {
  return warnings.length ? `${warnings.join("\n")}\n\n` : "";
}

export async function maybeHandleNodeExecHost(params: {
  command: string;
  requestedNode?: string;
  paramsEnv?: Record<string, string>;
  timeoutSec?: number;
  workdir: string;
  env: Record<string, string>;
  security: "deny" | "allowlist" | "full";
  ask: "off" | "on-miss" | "always";
  defaults?: ExecToolDefaults;
  agentId?: string;
  safePathPrepend: string[];
  defaultTimeoutSec: number;
  notifySessionKey?: string;
  warnings: string[];
  opts: ApprovalPromptOpts;
  emitExecSystemEvent: ExecEventEmitter;
  applyPathPrepend: ApplyPathPrepend;
}): Promise<AgentToolResult<ExecToolDetails>> {
  const approvals = resolveExecApprovals(params.agentId, {
    security: params.security,
    ask: params.ask,
  });
  const hostSecurity = minSecurity(params.security, approvals.agent.security);
  const hostAsk = maxAsk(params.ask, approvals.agent.ask);
  const askFallback = approvals.agent.askFallback;
  if (hostSecurity === "deny") {
    throw new Error("exec denied: host=node security=deny");
  }

  const boundNode = params.defaults?.node?.trim();
  const requestedNode = params.requestedNode?.trim();
  if (boundNode && requestedNode && boundNode !== requestedNode) {
    throw new Error(`exec node not allowed (bound to ${boundNode})`);
  }
  const nodeQuery = boundNode || requestedNode;
  const nodes = await listNodes({});
  if (nodes.length === 0) {
    throw new Error(
      "exec host=node requires a paired node (none available). This requires a companion app or node host.",
    );
  }
  let nodeId: string;
  try {
    nodeId = resolveNodeIdFromList(nodes, nodeQuery, !nodeQuery);
  } catch (err) {
    if (!nodeQuery && String(err).includes("node required")) {
      throw new Error(
        "exec host=node requires a node id when multiple nodes are available (set tools.exec.node or exec.node).",
        { cause: err },
      );
    }
    throw err;
  }
  const nodeInfo = nodes.find((entry) => entry.nodeId === nodeId);
  const supportsSystemRun = Array.isArray(nodeInfo?.commands)
    ? nodeInfo?.commands?.includes("system.run")
    : false;
  if (!supportsSystemRun) {
    throw new Error(
      "exec host=node requires a node that supports system.run (companion app or node host).",
    );
  }

  const argv = buildNodeShellCommand(params.command, nodeInfo?.platform);
  const nodeEnv = params.paramsEnv ? { ...params.paramsEnv } : undefined;
  if (nodeEnv) {
    params.applyPathPrepend(nodeEnv, params.safePathPrepend, { requireExisting: true });
  }

  const baseAllowlistEval = evaluateShellAllowlist({
    command: params.command,
    allowlist: [],
    safeBins: new Set(),
    cwd: params.workdir,
    env: params.env,
  });
  let analysisOk = baseAllowlistEval.analysisOk;
  let allowlistSatisfied = false;
  if (hostAsk === "on-miss" && hostSecurity === "allowlist" && analysisOk) {
    try {
      const approvalsSnapshot = await callGatewayTool<{ file: string }>(
        "exec.approvals.node.get",
        { timeoutMs: 10_000 },
        { nodeId },
      );
      const approvalsFile =
        approvalsSnapshot && typeof approvalsSnapshot === "object"
          ? approvalsSnapshot.file
          : undefined;
      if (approvalsFile && typeof approvalsFile === "object") {
        const resolved = resolveExecApprovalsFromFile({
          file: approvalsFile as ExecApprovalsFile,
          agentId: params.agentId,
          overrides: { security: "allowlist" },
        });
        const allowlistEval = evaluateShellAllowlist({
          command: params.command,
          allowlist: resolved.allowlist,
          safeBins: new Set(),
          cwd: params.workdir,
          env: params.env,
        });
        allowlistSatisfied = allowlistEval.allowlistSatisfied;
        analysisOk = allowlistEval.analysisOk;
      }
    } catch {
      // Fall back to requiring approval if node approvals cannot be fetched.
    }
  }

  const requiresAsk = requiresExecApproval({
    ask: hostAsk,
    security: hostSecurity,
    analysisOk,
    allowlistSatisfied,
  });
  const invokeTimeoutMs = Math.max(
    10_000,
    (typeof params.timeoutSec === "number" ? params.timeoutSec : params.defaultTimeoutSec) * 1000 +
      5_000,
  );
  const buildInvokeParams = (
    approvedByAsk: boolean,
    approvalDecision: "allow-once" | "allow-always" | null,
    runId?: string,
  ) =>
    ({
      nodeId,
      command: "system.run",
      params: {
        command: argv,
        rawCommand: params.command,
        cwd: params.workdir,
        env: nodeEnv,
        timeoutMs: typeof params.timeoutSec === "number" ? params.timeoutSec * 1000 : undefined,
        agentId: params.agentId,
        sessionKey: params.defaults?.sessionKey,
        approved: approvedByAsk,
        approvalDecision: approvalDecision ?? undefined,
        runId: runId ?? undefined,
      },
      idempotencyKey: crypto.randomUUID(),
    }) satisfies Record<string, unknown>;

  if (requiresAsk) {
    const approvalId = crypto.randomUUID();
    const approvalSlug = createApprovalSlug(approvalId);
    const expiresAtMs = Date.now() + params.opts.defaultApprovalTimeoutMs;
    const contextKey = `exec:${approvalId}`;
    const noticeSeconds = Math.max(1, Math.round(params.opts.approvalRunningNoticeMs / 1000));
    const warningText = getWarningText(params.warnings);

    void (async () => {
      let decision: string | null = null;
      try {
        const decisionResult = await callGatewayTool<{ decision: string }>(
          "exec.approval.request",
          { timeoutMs: params.opts.defaultApprovalRequestTimeoutMs },
          {
            id: approvalId,
            command: params.command,
            cwd: params.workdir,
            host: "node",
            security: hostSecurity,
            ask: hostAsk,
            agentId: params.agentId,
            resolvedPath: undefined,
            sessionKey: params.defaults?.sessionKey,
            timeoutMs: params.opts.defaultApprovalTimeoutMs,
          },
        );
        const decisionValue =
          decisionResult && typeof decisionResult === "object"
            ? (decisionResult as { decision?: unknown }).decision
            : undefined;
        decision = typeof decisionValue === "string" ? decisionValue : null;
      } catch {
        params.emitExecSystemEvent(
          `Exec denied (node=${nodeId} id=${approvalId}, approval-request-failed): ${params.command}`,
          { sessionKey: params.notifySessionKey, contextKey },
        );
        return;
      }

      let approvedByAsk = false;
      let approvalDecision: "allow-once" | "allow-always" | null = null;
      let deniedReason: string | null = null;

      if (decision === "deny") {
        deniedReason = "user-denied";
      } else if (!decision) {
        if (askFallback === "full") {
          approvedByAsk = true;
          approvalDecision = "allow-once";
        } else if (askFallback !== "allowlist") {
          deniedReason = "approval-timeout";
        }
      } else if (decision === "allow-once") {
        approvedByAsk = true;
        approvalDecision = "allow-once";
      } else if (decision === "allow-always") {
        approvedByAsk = true;
        approvalDecision = "allow-always";
      }

      if (deniedReason) {
        params.emitExecSystemEvent(
          `Exec denied (node=${nodeId} id=${approvalId}, ${deniedReason}): ${params.command}`,
          { sessionKey: params.notifySessionKey, contextKey },
        );
        return;
      }

      let runningTimer: NodeJS.Timeout | null = null;
      if (params.opts.approvalRunningNoticeMs > 0) {
        runningTimer = setTimeout(() => {
          params.emitExecSystemEvent(
            `Exec running (node=${nodeId} id=${approvalId}, >${noticeSeconds}s): ${params.command}`,
            { sessionKey: params.notifySessionKey, contextKey },
          );
        }, params.opts.approvalRunningNoticeMs);
      }

      try {
        await callGatewayTool(
          "node.invoke",
          { timeoutMs: invokeTimeoutMs },
          buildInvokeParams(approvedByAsk, approvalDecision, approvalId),
        );
      } catch {
        params.emitExecSystemEvent(
          `Exec denied (node=${nodeId} id=${approvalId}, invoke-failed): ${params.command}`,
          { sessionKey: params.notifySessionKey, contextKey },
        );
      } finally {
        if (runningTimer) {
          clearTimeout(runningTimer);
        }
      }
    })();

    return {
      content: [
        {
          type: "text",
          text: `${warningText}Approval required (id ${approvalSlug}). Approve to run; updates will arrive after completion.`,
        },
      ],
      details: {
        status: "approval-pending",
        approvalId,
        approvalSlug,
        expiresAtMs,
        host: "node",
        command: params.command,
        cwd: params.workdir,
        nodeId,
      },
    };
  }

  const startedAt = Date.now();
  const raw = await callGatewayTool(
    "node.invoke",
    { timeoutMs: invokeTimeoutMs },
    buildInvokeParams(false, null),
  );
  const payload =
    raw && typeof raw === "object" ? (raw as { payload?: unknown }).payload : undefined;
  const payloadObj =
    payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const stdout = typeof payloadObj.stdout === "string" ? payloadObj.stdout : "";
  const stderr = typeof payloadObj.stderr === "string" ? payloadObj.stderr : "";
  const errorText = typeof payloadObj.error === "string" ? payloadObj.error : "";
  const success = typeof payloadObj.success === "boolean" ? payloadObj.success : false;
  const exitCode = typeof payloadObj.exitCode === "number" ? payloadObj.exitCode : null;
  return {
    content: [{ type: "text", text: stdout || stderr || errorText || "" }],
    details: {
      status: success ? "completed" : "failed",
      exitCode,
      durationMs: Date.now() - startedAt,
      aggregated: [stdout, stderr, errorText].filter(Boolean).join("\n"),
      cwd: params.workdir,
    },
  };
}

export async function enforceGatewayExecApprovals(params: {
  command: string;
  paramsPty?: boolean;
  timeoutSec?: number;
  workdir: string;
  env: Record<string, string>;
  security: "deny" | "allowlist" | "full";
  ask: "off" | "on-miss" | "always";
  defaults?: ExecToolDefaults;
  agentId?: string;
  safeBins: Set<string>;
  notifySessionKey?: string;
  warnings: string[];
  maxOutput: number;
  pendingMaxOutput: number;
  sandboxActive: boolean;
  opts: ApprovalPromptOpts;
  emitExecSystemEvent: ExecEventEmitter;
}): Promise<void | AgentToolResult<ExecToolDetails>> {
  const approvals = resolveExecApprovals(params.agentId, {
    security: params.security,
    ask: params.ask,
  });
  const hostSecurity = minSecurity(params.security, approvals.agent.security);
  const hostAsk = maxAsk(params.ask, approvals.agent.ask);
  const askFallback = approvals.agent.askFallback;
  if (hostSecurity === "deny") {
    throw new Error("exec denied: host=gateway security=deny");
  }

  const allowlistEval = evaluateShellAllowlist({
    command: params.command,
    allowlist: approvals.allowlist,
    safeBins: params.safeBins,
    cwd: params.workdir,
    env: params.env,
  });
  const allowlistMatches = allowlistEval.allowlistMatches;
  const analysisOk = allowlistEval.analysisOk;
  const allowlistSatisfied =
    hostSecurity === "allowlist" && analysisOk ? allowlistEval.allowlistSatisfied : false;
  const requiresAsk = requiresExecApproval({
    ask: hostAsk,
    security: hostSecurity,
    analysisOk,
    allowlistSatisfied,
  });

  if (requiresAsk) {
    const approvalId = crypto.randomUUID();
    const approvalSlug = createApprovalSlug(approvalId);
    const expiresAtMs = Date.now() + params.opts.defaultApprovalTimeoutMs;
    const contextKey = `exec:${approvalId}`;
    const resolvedPath = allowlistEval.segments[0]?.resolution?.resolvedPath;
    const noticeSeconds = Math.max(1, Math.round(params.opts.approvalRunningNoticeMs / 1000));
    const effectiveTimeout =
      typeof params.timeoutSec === "number" ? params.timeoutSec : params.opts.defaultTimeoutSec;
    const warningText = getWarningText(params.warnings);

    void (async () => {
      let decision: string | null = null;
      try {
        const decisionResult = await callGatewayTool<{ decision: string }>(
          "exec.approval.request",
          { timeoutMs: params.opts.defaultApprovalRequestTimeoutMs },
          {
            id: approvalId,
            command: params.command,
            cwd: params.workdir,
            host: "gateway",
            security: hostSecurity,
            ask: hostAsk,
            agentId: params.agentId,
            resolvedPath,
            sessionKey: params.defaults?.sessionKey,
            timeoutMs: params.opts.defaultApprovalTimeoutMs,
          },
        );
        const decisionValue =
          decisionResult && typeof decisionResult === "object"
            ? (decisionResult as { decision?: unknown }).decision
            : undefined;
        decision = typeof decisionValue === "string" ? decisionValue : null;
      } catch {
        params.emitExecSystemEvent(
          `Exec denied (gateway id=${approvalId}, approval-request-failed): ${params.command}`,
          { sessionKey: params.notifySessionKey, contextKey },
        );
        return;
      }

      let approvedByAsk = false;
      let deniedReason: string | null = null;

      if (decision === "deny") {
        deniedReason = "user-denied";
      } else if (!decision) {
        if (askFallback === "full") {
          approvedByAsk = true;
        } else if (askFallback === "allowlist") {
          if (!analysisOk || !allowlistSatisfied) {
            deniedReason = "approval-timeout (allowlist-miss)";
          } else {
            approvedByAsk = true;
          }
        } else {
          deniedReason = "approval-timeout";
        }
      } else if (decision === "allow-once") {
        approvedByAsk = true;
      } else if (decision === "allow-always") {
        approvedByAsk = true;
        if (hostSecurity === "allowlist") {
          for (const segment of allowlistEval.segments) {
            const pattern = segment.resolution?.resolvedPath ?? "";
            if (pattern) {
              addAllowlistEntry(approvals.file, params.agentId, pattern);
            }
          }
        }
      }

      if (hostSecurity === "allowlist" && (!analysisOk || !allowlistSatisfied) && !approvedByAsk) {
        deniedReason = deniedReason ?? "allowlist-miss";
      }

      if (deniedReason) {
        params.emitExecSystemEvent(
          `Exec denied (gateway id=${approvalId}, ${deniedReason}): ${params.command}`,
          { sessionKey: params.notifySessionKey, contextKey },
        );
        return;
      }

      if (allowlistMatches.length > 0) {
        const seen = new Set<string>();
        for (const match of allowlistMatches) {
          if (seen.has(match.pattern)) {
            continue;
          }
          seen.add(match.pattern);
          recordAllowlistUse(
            approvals.file,
            params.agentId,
            match,
            params.command,
            resolvedPath ?? undefined,
          );
        }
      }

      let run: ExecProcessHandle | null = null;
      try {
        run = await runExecProcess({
          command: params.command,
          workdir: params.workdir,
          env: params.env,
          sandbox: undefined,
          containerWorkdir: null,
          usePty: params.paramsPty === true && !params.sandboxActive,
          warnings: params.warnings,
          maxOutput: params.maxOutput,
          pendingMaxOutput: params.pendingMaxOutput,
          notifyOnExit: false,
          scopeKey: params.defaults?.scopeKey,
          sessionKey: params.notifySessionKey,
          timeoutSec: effectiveTimeout,
        });
      } catch {
        params.emitExecSystemEvent(
          `Exec denied (gateway id=${approvalId}, spawn-failed): ${params.command}`,
          { sessionKey: params.notifySessionKey, contextKey },
        );
        return;
      }

      markBackgrounded(run.session);

      let runningTimer: NodeJS.Timeout | null = null;
      if (params.opts.approvalRunningNoticeMs > 0) {
        runningTimer = setTimeout(() => {
          params.emitExecSystemEvent(
            `Exec running (gateway id=${approvalId}, session=${run?.session.id}, >${noticeSeconds}s): ${params.command}`,
            { sessionKey: params.notifySessionKey, contextKey },
          );
        }, params.opts.approvalRunningNoticeMs);
      }

      const outcome = await run.promise;
      if (runningTimer) {
        clearTimeout(runningTimer);
      }
      const output = normalizeNotifyOutput(
        tail(outcome.aggregated || "", params.opts.defaultNotifyTailChars),
      );
      const exitLabel = outcome.timedOut ? "timeout" : `code ${outcome.exitCode ?? "?"}`;
      const summary = output
        ? `Exec finished (gateway id=${approvalId}, session=${run.session.id}, ${exitLabel})\n${output}`
        : `Exec finished (gateway id=${approvalId}, session=${run.session.id}, ${exitLabel})`;
      params.emitExecSystemEvent(summary, { sessionKey: params.notifySessionKey, contextKey });
    })();

    return {
      content: [
        {
          type: "text",
          text: `${warningText}Approval required (id ${approvalSlug}). Approve to run; updates will arrive after completion.`,
        },
      ],
      details: {
        status: "approval-pending",
        approvalId,
        approvalSlug,
        expiresAtMs,
        host: "gateway",
        command: params.command,
        cwd: params.workdir,
      },
    };
  }

  if (hostSecurity === "allowlist" && (!analysisOk || !allowlistSatisfied)) {
    throw new Error("exec denied: allowlist miss");
  }

  if (allowlistMatches.length > 0) {
    const seen = new Set<string>();
    for (const match of allowlistMatches) {
      if (seen.has(match.pattern)) {
        continue;
      }
      seen.add(match.pattern);
      recordAllowlistUse(
        approvals.file,
        params.agentId,
        match,
        params.command,
        allowlistEval.segments[0]?.resolution?.resolvedPath,
      );
    }
  }

  return;
}
