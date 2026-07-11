import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type InteractionRuntimeLease,
  type InteractionSessionActiveProjection,
  bindGatewayInteractionRuntime,
  clearGatewayInteractionSessionsForTest,
  createInteractionSessionActor,
  getGatewayInteractionSessionProjection,
  prepareGatewayInteractionRuntime,
} from "./interaction-session-actor.js";

describe("interaction session actor", () => {
  afterEach(() => {
    clearGatewayInteractionSessionsForTest();
  });

  it("leases a runtime with canonical session identity and epoch", () => {
    const actor = createInteractionSessionActor({
      sessionKey: "agent:main:main",
      interactionSessionId: "interaction-1",
    });

    const result = actor.leaseRuntime({
      runtimeId: "relay-1",
      runtimeKind: "realtime-voice",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.lease).toMatchObject({
      interactionSessionId: "interaction-1",
      sessionKey: "agent:main:main",
      epoch: 1,
      runtimeId: "relay-1",
      runtimeKind: "realtime-voice",
    });
    expect(actor.snapshot).toEqual({
      phase: "active",
      interactionSessionId: "interaction-1",
      sessionKey: "agent:main:main",
      epoch: 1,
      runtime: result.lease,
    });
  });

  it("advances the epoch before revoking a replaced runtime", () => {
    const actor = createInteractionSessionActor({
      sessionKey: "agent:main:main",
      interactionSessionId: "interaction-1",
    });
    const observedDuringRevoke: unknown[] = [];
    const firstLease = requireLease(
      actor.leaseRuntime({
        runtimeId: "relay-1",
        runtimeKind: "realtime-voice",
        onRevoked: ({ lease, reason }) => {
          observedDuringRevoke.push(reason, actor.validateRuntimeLease(lease), actor.snapshot);
        },
      }),
    );

    const secondLease = requireLease(
      actor.leaseRuntime({ runtimeId: "relay-2", runtimeKind: "realtime-voice" }),
    );

    expect(observedDuringRevoke).toEqual([
      "runtime_replaced",
      { ok: false, reason: "stale_epoch" },
      {
        phase: "active",
        interactionSessionId: "interaction-1",
        sessionKey: "agent:main:main",
        epoch: 2,
        runtime: secondLease,
      },
    ]);
    expect(actor.runWithRuntimeLease(firstLease, () => "old")).toEqual({
      ok: false,
      reason: "stale_epoch",
    });
    expect(actor.runWithRuntimeLease(secondLease, () => "current")).toEqual({
      ok: true,
      value: "current",
    });
  });

  it("does not let a stale release clear the replacement runtime", () => {
    const actor = createInteractionSessionActor({ sessionKey: "agent:main:main" });
    const firstLease = requireLease(
      actor.leaseRuntime({ runtimeId: "relay-1", runtimeKind: "realtime-voice" }),
    );
    const secondLease = requireLease(
      actor.leaseRuntime({ runtimeId: "relay-2", runtimeKind: "realtime-voice" }),
    );

    expect(actor.releaseRuntime(firstLease)).toEqual({ ok: false, reason: "stale_epoch" });
    expect(actor.snapshot).toMatchObject({ phase: "active", runtime: secondLease });
    expect(actor.releaseRuntime(secondLease)).toEqual({ ok: true });
    expect(actor.snapshot).toMatchObject({ phase: "idle", epoch: 2 });
  });

  it("rejects forged and closed-session leases", () => {
    const actor = createInteractionSessionActor({ sessionKey: "agent:main:main" });
    const onRevoked = vi.fn();
    const lease = requireLease(
      actor.leaseRuntime({
        runtimeId: "relay-1",
        runtimeKind: "realtime-voice",
        onRevoked,
      }),
    );

    expect(actor.validateRuntimeLease({ ...lease, leaseId: "other" })).toEqual({
      ok: false,
      reason: "stale_lease",
    });
    actor.close();
    expect(onRevoked).toHaveBeenCalledWith({ lease, reason: "session_closed" });
    expect(actor.validateRuntimeLease(lease)).toEqual({
      ok: false,
      reason: "session_closed",
    });
    expect(actor.leaseRuntime({ runtimeId: "relay-2", runtimeKind: "realtime-voice" })).toEqual({
      ok: false,
      reason: "session_closed",
    });
  });

  it("shares one actor per session key and retires it after the current lease releases", () => {
    const firstRevoked = vi.fn();
    const projections: unknown[] = [];
    const first = bindGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-1",
      runtimeKind: "realtime-voice",
      onRevoked: firstRevoked,
      onProjection: (projection) => projections.push(projection),
    });
    const second = bindGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-2",
      runtimeKind: "realtime-voice",
      onProjection: (projection) => projections.push(projection),
    });

    expect(first.lease.interactionSessionId).toBe(second.lease.interactionSessionId);
    expect(second.lease.epoch).toBe(first.lease.epoch + 1);
    expect(first.projection).toEqual({
      interactionSessionId: first.lease.interactionSessionId,
      sessionKey: "agent:main:main",
      epoch: first.lease.epoch,
      runtimeId: "relay-1",
      runtimeKind: "realtime-voice",
      state: "replaced",
    });
    expect(second.projection).toEqual({
      interactionSessionId: second.lease.interactionSessionId,
      sessionKey: "agent:main:main",
      epoch: second.lease.epoch,
      runtimeId: "relay-2",
      runtimeKind: "realtime-voice",
      state: "active",
    });
    expect(projections).toEqual([
      { ...first.projection, state: "active" },
      first.projection,
      second.projection,
    ]);
    expect(getGatewayInteractionSessionProjection("agent:main:main")).toEqual(second.projection);
    expect(firstRevoked).toHaveBeenCalledWith({
      lease: first.lease,
      reason: "runtime_replaced",
    });
    expect(first.isActive).toBe(false);
    expect(second.isActive).toBe(true);
    expect(first.release()).toEqual({ ok: false, reason: "stale_epoch" });
    expect(projections).toHaveLength(3);
    expect(second.release()).toEqual({ ok: true });
    expect(second.projection.state).toBe("closed");
    expect(projections.at(-1)).toEqual(second.projection);
    expect(getGatewayInteractionSessionProjection("agent:main:main")).toBeUndefined();

    const third = bindGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-3",
      runtimeKind: "realtime-voice",
    });
    expect(third.lease.interactionSessionId).not.toBe(second.lease.interactionSessionId);
    expect(third.lease.epoch).toBe(1);
  });

  it("commits only the newest accepted startup regardless of readiness order", () => {
    const incumbent = bindGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-incumbent",
      runtimeKind: "realtime-voice",
    });
    const firstSuperseded = vi.fn();
    const first = prepareGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-slow",
      runtimeKind: "realtime-voice",
      onStartupSuperseded: firstSuperseded,
    });
    const second = prepareGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "transcription-newest",
      runtimeKind: "transcription",
    });

    expect(firstSuperseded).toHaveBeenCalledOnce();
    expect(first.activate()).toBeUndefined();
    expect(getGatewayInteractionSessionProjection("agent:main:main")?.runtimeId).toBe(
      "relay-incumbent",
    );

    const newest = second.activate();
    expect(newest?.isActive).toBe(true);
    expect(incumbent.isActive).toBe(false);
    expect(newest?.lease.runtimeId).toBe("transcription-newest");
    expect(newest?.lease.epoch).toBe(incumbent.lease.epoch + 1);
  });

  it("an immediate runtime invalidates an older pending startup", () => {
    const pendingSuperseded = vi.fn();
    const pending = prepareGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-pending",
      runtimeKind: "realtime-voice",
      onStartupSuperseded: pendingSuperseded,
    });

    const managed = bindGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "room-newest",
      runtimeKind: "managed-room",
    });

    expect(pendingSuperseded).toHaveBeenCalledOnce();
    expect(pending.activate()).toBeUndefined();
    expect(managed.isActive).toBe(true);
    expect(getGatewayInteractionSessionProjection("agent:main:main")?.runtimeId).toBe(
      "room-newest",
    );
  });

  it("does not publish or return a candidate superseded by a revoke callback", () => {
    const actor = createInteractionSessionActor({
      sessionKey: "agent:main:main",
      interactionSessionId: "interaction-1",
    });
    const projections: string[] = [];
    const candidateRevoked = vi.fn();
    let nestedLease: InteractionRuntimeLease | undefined;
    actor.leaseRuntime({
      runtimeId: "relay-incumbent",
      runtimeKind: "realtime-voice",
      onProjection: (projection) => projections.push(`${projection.runtimeId}:${projection.state}`),
      onRevoked: () => {
        const nested = actor.leaseRuntime({
          runtimeId: "room-reentrant",
          runtimeKind: "managed-room",
          onProjection: (projection) =>
            projections.push(`${projection.runtimeId}:${projection.state}`),
        });
        nestedLease = requireLease(nested);
      },
    });

    const candidate = actor.leaseRuntime({
      runtimeId: "transcription-candidate",
      runtimeKind: "transcription",
      onProjection: (projection) => projections.push(`${projection.runtimeId}:${projection.state}`),
      onRevoked: candidateRevoked,
    });

    expect(candidate).toEqual({ ok: false, reason: "stale_epoch" });
    expect(candidateRevoked).toHaveBeenCalledOnce();
    expect(projections).toEqual([
      "relay-incumbent:active",
      "relay-incumbent:replaced",
      "room-reentrant:active",
    ]);
    expect(actor.snapshot).toMatchObject({ phase: "active", runtime: nestedLease });
  });

  it("types the gateway lookup as an active-only projection", () => {
    bindGatewayInteractionRuntime({
      sessionKey: "agent:main:main",
      runtimeId: "relay-1",
      runtimeKind: "realtime-voice",
    });

    const projection: InteractionSessionActiveProjection | undefined =
      getGatewayInteractionSessionProjection("agent:main:main");

    expect(projection?.state).toBe("active");
  });
});

function requireLease(
  result: ReturnType<ReturnType<typeof createInteractionSessionActor>["leaseRuntime"]>,
) {
  if (!result.ok) {
    throw new Error(`Expected runtime lease, got ${result.reason}`);
  }
  return result.lease;
}
