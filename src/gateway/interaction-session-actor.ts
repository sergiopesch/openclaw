// Gateway-owned interaction session identity and realtime runtime leasing.
import { randomUUID } from "node:crypto";

export type InteractionRuntimeKind = "managed-room" | "realtime-voice" | "transcription";

export type InteractionRuntimeLease = Readonly<{
  interactionSessionId: string;
  sessionKey: string;
  epoch: number;
  leaseId: string;
  runtimeId: string;
  runtimeKind: InteractionRuntimeKind;
}>;

type InteractionSessionProjectionState = "active" | "closed" | "replaced";

type InteractionSessionProjectionWithState<TState extends InteractionSessionProjectionState> =
  Readonly<{
    interactionSessionId: string;
    sessionKey: string;
    epoch: number;
    runtimeId: string;
    runtimeKind: InteractionRuntimeKind;
    state: TState;
  }>;

export type InteractionSessionBindingProjection =
  InteractionSessionProjectionWithState<InteractionSessionProjectionState>;

export type InteractionSessionActiveProjection = InteractionSessionProjectionWithState<"active">;

export type InteractionRuntimeLeaseRevokeReason = "runtime_replaced" | "session_closed";

type InteractionRuntimeLeaseRevoke = (params: {
  lease: InteractionRuntimeLease;
  reason: InteractionRuntimeLeaseRevokeReason;
}) => void;

type InteractionSessionProjectionObserver = (
  projection: InteractionSessionBindingProjection,
) => void;

type ActiveRuntime = {
  lease: InteractionRuntimeLease;
  activeProjectionPublished: boolean;
  onRevoked?: InteractionRuntimeLeaseRevoke;
  onProjection?: InteractionSessionProjectionObserver;
};

export type InteractionSessionSnapshot =
  | {
      phase: "idle";
      interactionSessionId: string;
      sessionKey: string;
      epoch: number;
    }
  | {
      phase: "active";
      interactionSessionId: string;
      sessionKey: string;
      epoch: number;
      runtime: InteractionRuntimeLease;
    }
  | {
      phase: "closed";
      interactionSessionId: string;
      sessionKey: string;
      epoch: number;
    };

export type InteractionRuntimeLeaseFailureReason = "session_closed" | "stale_epoch" | "stale_lease";

export type InteractionRuntimeLeaseValidation =
  | { ok: true }
  | { ok: false; reason: InteractionRuntimeLeaseFailureReason };

export type InteractionRuntimeOperationResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: InteractionRuntimeLeaseFailureReason };

export type InteractionSessionActor = {
  readonly snapshot: InteractionSessionSnapshot;
  leaseRuntime(params: {
    runtimeId: string;
    runtimeKind: InteractionRuntimeKind;
    onRevoked?: InteractionRuntimeLeaseRevoke;
    onProjection?: InteractionSessionProjectionObserver;
  }):
    | { ok: true; lease: InteractionRuntimeLease }
    | { ok: false; reason: "session_closed" | "stale_epoch" };
  validateRuntimeLease(lease: InteractionRuntimeLease): InteractionRuntimeLeaseValidation;
  runWithRuntimeLease<T>(
    lease: InteractionRuntimeLease,
    operation: () => T,
  ): InteractionRuntimeOperationResult<T>;
  releaseRuntime(lease: InteractionRuntimeLease): InteractionRuntimeLeaseValidation;
  close(): void;
};

export type GatewayInteractionRuntimeBinding = {
  readonly lease: InteractionRuntimeLease;
  readonly projection: InteractionSessionBindingProjection;
  readonly isActive: boolean;
  run<T>(operation: () => T): InteractionRuntimeOperationResult<T>;
  release(): InteractionRuntimeLeaseValidation;
};

export type GatewayInteractionRuntimeStartup = {
  readonly isCurrent: boolean;
  activate(): GatewayInteractionRuntimeBinding | undefined;
  cancel(): boolean;
};

function notifyRuntimeRevoked(
  runtime: ActiveRuntime | undefined,
  reason: InteractionRuntimeLeaseRevokeReason,
): void {
  if (!runtime?.onRevoked) {
    return;
  }
  try {
    runtime.onRevoked({ lease: runtime.lease, reason });
  } catch {
    // The new lease is already authoritative; adapter cleanup cannot roll it back.
  }
}

function projectRuntime<TState extends InteractionSessionProjectionState>(
  lease: InteractionRuntimeLease,
  state: TState,
): InteractionSessionProjectionWithState<TState> {
  return {
    interactionSessionId: lease.interactionSessionId,
    sessionKey: lease.sessionKey,
    epoch: lease.epoch,
    runtimeId: lease.runtimeId,
    runtimeKind: lease.runtimeKind,
    state,
  };
}

function notifyInteractionProjection(
  runtime: ActiveRuntime | undefined,
  state: InteractionSessionBindingProjection["state"],
): void {
  if (!runtime?.onProjection) {
    return;
  }
  try {
    runtime.onProjection(projectRuntime(runtime.lease, state));
  } catch {
    // Projection observers cannot roll back the actor transition they report.
  }
}

/** Creates one canonical Gateway interaction actor for an OpenClaw session key. */
export function createInteractionSessionActor(params: {
  sessionKey: string;
  interactionSessionId?: string;
}): InteractionSessionActor {
  const interactionSessionId = params.interactionSessionId ?? randomUUID();
  let epoch = 0;
  let activeRuntime: ActiveRuntime | undefined;
  let closed = false;

  const snapshot = (): InteractionSessionSnapshot => {
    if (closed) {
      return { phase: "closed", interactionSessionId, sessionKey: params.sessionKey, epoch };
    }
    if (!activeRuntime) {
      return { phase: "idle", interactionSessionId, sessionKey: params.sessionKey, epoch };
    }
    return {
      phase: "active",
      interactionSessionId,
      sessionKey: params.sessionKey,
      epoch,
      runtime: activeRuntime.lease,
    };
  };

  const validateRuntimeLease = (
    lease: InteractionRuntimeLease,
  ): InteractionRuntimeLeaseValidation => {
    if (closed) {
      return { ok: false, reason: "session_closed" };
    }
    if (
      lease.interactionSessionId !== interactionSessionId ||
      lease.sessionKey !== params.sessionKey ||
      (lease.epoch === epoch && lease.leaseId !== activeRuntime?.lease.leaseId)
    ) {
      return { ok: false, reason: "stale_lease" };
    }
    if (lease.epoch !== epoch) {
      return { ok: false, reason: "stale_epoch" };
    }
    return { ok: true };
  };

  return {
    get snapshot() {
      return snapshot();
    },
    leaseRuntime(runtimeParams) {
      if (closed) {
        return { ok: false, reason: "session_closed" };
      }
      const previousRuntime = activeRuntime;
      epoch += 1;
      const lease: InteractionRuntimeLease = {
        interactionSessionId,
        sessionKey: params.sessionKey,
        epoch,
        leaseId: randomUUID(),
        runtimeId: runtimeParams.runtimeId,
        runtimeKind: runtimeParams.runtimeKind,
      };
      activeRuntime = {
        lease,
        activeProjectionPublished: false,
        onRevoked: runtimeParams.onRevoked,
        onProjection: runtimeParams.onProjection,
      };
      const nextRuntime = activeRuntime;
      // Fence the old adapter before callbacks, then publish the new epoch.
      if (previousRuntime?.activeProjectionPublished) {
        notifyInteractionProjection(previousRuntime, "replaced");
      }
      notifyRuntimeRevoked(previousRuntime, "runtime_replaced");
      if (closed) {
        return { ok: false, reason: "session_closed" };
      }
      if (activeRuntime !== nextRuntime) {
        return { ok: false, reason: "stale_epoch" };
      }
      nextRuntime.activeProjectionPublished = true;
      notifyInteractionProjection(nextRuntime, "active");
      if (closed) {
        return { ok: false, reason: "session_closed" };
      }
      if (activeRuntime !== nextRuntime) {
        return { ok: false, reason: "stale_epoch" };
      }
      return { ok: true, lease };
    },
    validateRuntimeLease,
    runWithRuntimeLease(lease, operation) {
      const validation = validateRuntimeLease(lease);
      if (!validation.ok) {
        return validation;
      }
      return { ok: true, value: operation() };
    },
    releaseRuntime(lease) {
      const validation = validateRuntimeLease(lease);
      if (!validation.ok) {
        return validation;
      }
      const previousRuntime = activeRuntime;
      activeRuntime = undefined;
      if (previousRuntime?.activeProjectionPublished) {
        notifyInteractionProjection(previousRuntime, "closed");
      }
      return { ok: true };
    },
    close() {
      if (closed) {
        return;
      }
      const previousRuntime = activeRuntime;
      activeRuntime = undefined;
      closed = true;
      if (previousRuntime?.activeProjectionPublished) {
        notifyInteractionProjection(previousRuntime, "closed");
      }
      notifyRuntimeRevoked(previousRuntime, "session_closed");
    },
  };
}

type InteractionSessionEntry = {
  actor: InteractionSessionActor;
  startupSequence: number;
  pendingStartup?: {
    sequence: number;
    onSuperseded?: () => void;
  };
};

const interactionEntries = new Map<string, InteractionSessionEntry>();

function getOrCreateInteractionEntry(sessionKey: string): InteractionSessionEntry {
  const current = interactionEntries.get(sessionKey);
  if (current) {
    return current;
  }
  const entry: InteractionSessionEntry = {
    actor: createInteractionSessionActor({ sessionKey }),
    startupSequence: 0,
  };
  interactionEntries.set(sessionKey, entry);
  return entry;
}

function retireInteractionEntryIfIdle(sessionKey: string, entry: InteractionSessionEntry): void {
  if (entry.actor.snapshot.phase === "idle" && !entry.pendingStartup) {
    interactionEntries.delete(sessionKey);
  }
}

function notifyStartupSuperseded(startup: InteractionSessionEntry["pendingStartup"]): void {
  if (!startup?.onSuperseded) {
    return;
  }
  try {
    startup.onSuperseded();
  } catch {
    // The newer accepted startup remains authoritative even if stale adapter cleanup fails.
  }
}

function leaseGatewayInteractionRuntime(
  entry: InteractionSessionEntry,
  params: {
    sessionKey: string;
    runtimeId: string;
    runtimeKind: InteractionRuntimeKind;
    onRevoked?: InteractionRuntimeLeaseRevoke;
    onProjection?: InteractionSessionProjectionObserver;
  },
): GatewayInteractionRuntimeBinding | undefined {
  const actor = entry.actor;
  let terminalState: InteractionSessionBindingProjection["state"] | undefined;
  const leased = actor.leaseRuntime({
    ...params,
    onRevoked: (revoked) => {
      terminalState = revoked.reason === "runtime_replaced" ? "replaced" : "closed";
      params.onRevoked?.(revoked);
    },
  });
  if (!leased.ok) {
    if (leased.reason === "stale_epoch") {
      return undefined;
    }
    throw new Error("Cannot bind a runtime to a closed interaction session");
  }
  const lease = leased.lease;
  const projection = (): InteractionSessionBindingProjection => {
    if (terminalState) {
      return projectRuntime(lease, terminalState);
    }
    const validation = actor.validateRuntimeLease(lease);
    const state = validation.ok
      ? "active"
      : validation.reason === "session_closed"
        ? "closed"
        : "replaced";
    return projectRuntime(lease, state);
  };
  return {
    lease,
    get projection() {
      return projection();
    },
    get isActive() {
      return actor.validateRuntimeLease(lease).ok;
    },
    run(operation) {
      return actor.runWithRuntimeLease(lease, operation);
    },
    release() {
      const released = actor.releaseRuntime(lease);
      if (released.ok) {
        terminalState = "closed";
        retireInteractionEntryIfIdle(params.sessionKey, entry);
      }
      return released;
    },
  };
}

/** Reserves request order without replacing the incumbent until the adapter is ready. */
export function prepareGatewayInteractionRuntime(params: {
  sessionKey: string;
  runtimeId: string;
  runtimeKind: InteractionRuntimeKind;
  onRevoked?: InteractionRuntimeLeaseRevoke;
  onProjection?: InteractionSessionProjectionObserver;
  onStartupSuperseded?: () => void;
}): GatewayInteractionRuntimeStartup {
  const entry = getOrCreateInteractionEntry(params.sessionKey);
  const sequence = entry.startupSequence + 1;
  entry.startupSequence = sequence;
  const previousStartup = entry.pendingStartup;
  entry.pendingStartup = { sequence, onSuperseded: params.onStartupSuperseded };
  notifyStartupSuperseded(previousStartup);
  let terminal = false;

  const isCurrent = (): boolean =>
    !terminal &&
    interactionEntries.get(params.sessionKey) === entry &&
    entry.pendingStartup?.sequence === sequence;

  return {
    get isCurrent() {
      return isCurrent();
    },
    activate() {
      if (!isCurrent()) {
        return undefined;
      }
      terminal = true;
      entry.pendingStartup = undefined;
      return leaseGatewayInteractionRuntime(entry, params);
    },
    cancel() {
      if (!isCurrent()) {
        return false;
      }
      terminal = true;
      entry.pendingStartup = undefined;
      retireInteractionEntryIfIdle(params.sessionKey, entry);
      return true;
    },
  };
}

/** Binds a concrete realtime adapter to the canonical actor for its OpenClaw session. */
export function bindGatewayInteractionRuntime(params: {
  sessionKey: string;
  runtimeId: string;
  runtimeKind: InteractionRuntimeKind;
  onRevoked?: InteractionRuntimeLeaseRevoke;
  onProjection?: InteractionSessionProjectionObserver;
}): GatewayInteractionRuntimeBinding {
  const startup = prepareGatewayInteractionRuntime(params);
  const binding = startup.activate();
  if (!binding) {
    throw new Error("Cannot bind a superseded interaction runtime");
  }
  return binding;
}

/** Returns the active projection for one canonical session key. */
export function getGatewayInteractionSessionProjection(
  sessionKey: string,
): InteractionSessionActiveProjection | undefined {
  const snapshot = interactionEntries.get(sessionKey)?.actor.snapshot;
  return snapshot?.phase === "active" ? projectRuntime(snapshot.runtime, "active") : undefined;
}

/** Clears process-local interaction actors between Gateway tests. */
export function clearGatewayInteractionSessionsForTest(): void {
  const entries = [...interactionEntries.values()];
  interactionEntries.clear();
  for (const entry of entries) {
    notifyStartupSuperseded(entry.pendingStartup);
    entry.actor.close();
  }
}
