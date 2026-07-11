/**
 * Tests talk transcription relay behavior between realtime events and clients.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RealtimeTranscriptionProviderPlugin } from "../plugins/types.js";
import type { RealtimeTranscriptionSessionCreateRequest } from "../realtime-transcription/provider-types.js";
import { getGatewayInteractionSessionProjection } from "./interaction-session-actor.js";
import { getUnifiedTalkSession } from "./talk-session-registry.js";
import {
  cancelTalkTranscriptionRelayTurn,
  clearTalkTranscriptionRelaySessionsForTest,
  createTalkTranscriptionRelaySession,
  sendTalkTranscriptionRelayAudio,
  stopTalkTranscriptionRelaySession,
} from "./talk-transcription-relay.js";
import { expectRecordFields, isRecord, requireRecord } from "./test-helpers.assertions.js";

type BroadcastEvent = { event: string; payload: unknown; connIds: string[] };

function createSttSessionMock(connect: () => Promise<void> = async () => {}) {
  return {
    connect: vi.fn(connect),
    sendAudio: vi.fn(),
    close: vi.fn(),
    isConnected: vi.fn(() => true),
  };
}

function createTranscriptionProvider(
  sttSession: ReturnType<typeof createSttSessionMock>,
  onRequest?: (req: RealtimeTranscriptionSessionCreateRequest) => void,
): RealtimeTranscriptionProviderPlugin {
  return {
    id: "stt-test",
    label: "STT Test",
    isConfigured: () => true,
    createSession: vi.fn((req) => {
      onRequest?.(req);
      return sttSession;
    }),
  };
}

function createBroadcastContext() {
  const events: BroadcastEvent[] = [];
  const projections: Array<Record<string, unknown>> = [];
  const context = {
    getRuntimeConfig: () => ({}),
    broadcastToConnIds: (event: string, payload: unknown, connIds: ReadonlySet<string>) => {
      events.push({ event, payload, connIds: [...connIds] });
    },
    broadcast: (_event: string, payload: unknown) => {
      projections.push(payload as Record<string, unknown>);
    },
  } as never;
  return { context, events, projections };
}

async function createStartedRelaySession(
  sttSession: ReturnType<typeof createSttSessionMock>,
  providerConfig: Record<string, unknown>,
  onRequest?: (req: RealtimeTranscriptionSessionCreateRequest) => void,
) {
  const provider = createTranscriptionProvider(sttSession, onRequest);
  const { context, events } = createBroadcastContext();
  const session = createTalkTranscriptionRelaySession({
    context,
    connId: "conn-1",
    provider,
    providerConfig,
    sessionKey: "agent:main:main",
  });
  await Promise.resolve();
  return { provider, events, session };
}

function findPayloadByType(events: BroadcastEvent[], type: string): Record<string, unknown> {
  const event = events.find((candidate) => {
    const payload = candidate.payload;
    return isRecord(payload) && payload.type === type;
  });
  if (!event) {
    throw new Error(`expected relay event type ${type}`);
  }
  expect(event.event).toBe("talk.event");
  return requireRecord(event.payload, `${type} payload`);
}

function findPayloadByTalkEventType(
  events: BroadcastEvent[],
  type: string,
): Record<string, unknown> {
  const event = events.find((candidate) => {
    const payload = candidate.payload;
    return isRecord(payload) && isRecord(payload.talkEvent) && payload.talkEvent.type === type;
  });
  if (!event) {
    throw new Error(`expected talk event type ${type}`);
  }
  return requireRecord(event.payload, `${type} payload`);
}

function expectTalkEventFields(
  payload: Record<string, unknown>,
  expected: Record<string, unknown>,
): Record<string, unknown> {
  return expectRecordFields(payload.talkEvent, "talk event", expected);
}

describe("talk transcription gateway relay", () => {
  afterEach(() => {
    vi.useRealTimers();
    clearTalkTranscriptionRelaySessionsForTest();
  });

  it("bridges browser audio into a transcription-only Talk event stream", async () => {
    let sttRequest: RealtimeTranscriptionSessionCreateRequest | undefined;
    const sttSession = createSttSessionMock();
    const { events, session } = await createStartedRelaySession(
      sttSession,
      { model: "stt-model" },
      (req) => {
        sttRequest = req;
      },
    );
    sttRequest?.onSpeechStart?.();
    sttRequest?.onPartial?.("hel");
    sttRequest?.onTranscript?.("hello world");

    expectRecordFields(session, "session", {
      provider: "stt-test",
      mode: "transcription",
      transport: "gateway-relay",
    });
    expectRecordFields(session.audio, "session audio", {
      inputEncoding: "g711_ulaw",
      inputSampleRateHz: 8000,
    });
    expectRecordFields(sttRequest, "stt request", {
      providerConfig: { model: "stt-model" },
    });

    sendTalkTranscriptionRelayAudio({
      transcriptionSessionId: session.transcriptionSessionId,
      connId: "conn-1",
      audioBase64: Buffer.from("audio-in").toString("base64"),
    });
    stopTalkTranscriptionRelaySession({
      transcriptionSessionId: session.transcriptionSessionId,
      connId: "conn-1",
    });

    expect(sttSession.sendAudio).toHaveBeenCalledWith(Buffer.from("audio-in"));
    expect(sttSession.close).toHaveBeenCalledOnce();
    const readyPayload = findPayloadByType(events, "ready");
    expect(events.find((event) => event.payload === readyPayload)?.connIds).toEqual(["conn-1"]);
    expectRecordFields(readyPayload, "ready payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "ready",
    });
    expectTalkEventFields(readyPayload, {
      sessionId: session.transcriptionSessionId,
      type: "session.ready",
      mode: "transcription",
      transport: "gateway-relay",
      brain: "none",
      provider: "stt-test",
    });

    const speechStartPayload = findPayloadByType(events, "speechStart");
    expectRecordFields(speechStartPayload, "speechStart payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "speechStart",
    });
    expectTalkEventFields(speechStartPayload, { type: "turn.started", turnId: "turn-1" });

    const partialPayload = findPayloadByType(events, "partial");
    expectRecordFields(partialPayload, "partial payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "partial",
      text: "hel",
    });
    expectTalkEventFields(partialPayload, {
      type: "transcript.delta",
      turnId: "turn-1",
      payload: { text: "hel" },
    });

    const transcriptPayload = findPayloadByType(events, "transcript");
    expectRecordFields(transcriptPayload, "transcript payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "transcript",
      text: "hello world",
      final: true,
    });
    expectTalkEventFields(transcriptPayload, {
      type: "transcript.done",
      turnId: "turn-1",
      final: true,
      payload: { text: "hello world" },
    });

    const audioPayload = findPayloadByType(events, "inputAudio");
    expectRecordFields(audioPayload, "input audio payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "inputAudio",
      byteLength: 8,
    });
    expectTalkEventFields(audioPayload, { type: "input.audio.delta" });

    const closePayload = findPayloadByType(events, "close");
    expectRecordFields(closePayload, "close payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "close",
      reason: "completed",
    });
    expectTalkEventFields(closePayload, {
      type: "session.closed",
      final: true,
    });
  });

  it("rejects provider configs that do not match relay audio input", () => {
    const provider = createTranscriptionProvider(createSttSessionMock());
    const { context } = createBroadcastContext();

    expect(() =>
      createTalkTranscriptionRelaySession({
        context,
        connId: "conn-1",
        provider,
        providerConfig: { encoding: "linear16", sampleRate: 16000 },
        sessionKey: "agent:main:main",
      }),
    ).toThrow("Gateway transcription relay requires g711_ulaw/8000 audio");
    expect(provider.createSession).not.toHaveBeenCalled();
  });

  it("rejects session creation when transcription expiry would exceed Date range", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(8_640_000_000_000_000));
    const provider = createTranscriptionProvider(createSttSessionMock());
    const { context } = createBroadcastContext();

    expect(() =>
      createTalkTranscriptionRelaySession({
        context,
        connId: "conn-1",
        provider,
        providerConfig: {},
        sessionKey: "agent:main:main",
      }),
    ).toThrow("Transcription relay session expiry is outside the supported Date range");
    expect(provider.createSession).not.toHaveBeenCalled();
  });

  it("cancels an active transcription turn and closes the provider session", async () => {
    let sttRequest: RealtimeTranscriptionSessionCreateRequest | undefined;
    const sttSession = createSttSessionMock(async () => {
      sttRequest?.onSpeechStart?.();
    });
    const { events, session } = await createStartedRelaySession(sttSession, {}, (req) => {
      sttRequest = req;
    });

    cancelTalkTranscriptionRelayTurn({
      transcriptionSessionId: session.transcriptionSessionId,
      connId: "conn-1",
      reason: "barge-in",
    });

    expect(sttSession.close).toHaveBeenCalledOnce();
    const cancelledPayload = findPayloadByTalkEventType(events, "turn.cancelled");
    expectRecordFields(cancelledPayload, "cancelled payload", {
      transcriptionSessionId: session.transcriptionSessionId,
    });
    expectTalkEventFields(cancelledPayload, {
      type: "turn.cancelled",
      turnId: "turn-1",
      payload: { reason: "barge-in" },
      final: true,
    });

    const closePayload = findPayloadByType(events, "close");
    expectRecordFields(closePayload, "close payload", {
      transcriptionSessionId: session.transcriptionSessionId,
      type: "close",
      reason: "completed",
    });
  });

  it("replaces the prior runtime and ignores its later provider callbacks", async () => {
    const requests: RealtimeTranscriptionSessionCreateRequest[] = [];
    const sttSessions = [createSttSessionMock(), createSttSessionMock()];
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn((request) => {
        requests.push(request);
        const sttSession = sttSessions[requests.length - 1];
        if (!sttSession) {
          throw new Error("Unexpected transcription session creation");
        }
        return sttSession;
      }),
    };
    const { context, events, projections } = createBroadcastContext();
    const first = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();
    const second = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-2",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();

    expect(sttSessions[0]?.close).toHaveBeenCalledOnce();
    expect(() => getUnifiedTalkSession(first.transcriptionSessionId)).toThrow(
      "Unknown Talk session",
    );
    const replaced = events.find((event) => {
      const payload = event.payload;
      return (
        isRecord(payload) &&
        payload.type === "close" &&
        payload.transcriptionSessionId === first.transcriptionSessionId
      );
    });
    expectRecordFields(replaced?.payload, "replaced payload", {
      reason: "completed",
    });
    expectRecordFields(
      requireRecord(replaced?.payload, "replaced payload").talkEvent,
      "talk event",
      {
        type: "session.replaced",
        final: true,
      },
    );

    const eventCountAfterReplacement = events.length;
    requests[0]?.onSpeechStart?.();
    requests[0]?.onPartial?.("stale partial");
    requests[0]?.onTranscript?.("stale transcript");
    requests[0]?.onError?.(new Error("stale error"));
    expect(events).toHaveLength(eventCountAfterReplacement);
    expect(sttSessions[1]?.close).not.toHaveBeenCalled();

    requests[1]?.onPartial?.("current partial");
    const partial = findPayloadByType(events, "partial");
    expectRecordFields(partial, "current partial payload", {
      transcriptionSessionId: second.transcriptionSessionId,
      text: "current partial",
    });
    stopTalkTranscriptionRelaySession({
      transcriptionSessionId: second.transcriptionSessionId,
      connId: "conn-2",
    });
    expect(projections.map((projection) => [projection.runtimeId, projection.state])).toEqual([
      [first.transcriptionSessionId, "active"],
      [first.transcriptionSessionId, "replaced"],
      [second.transcriptionSessionId, "active"],
      [second.transcriptionSessionId, "closed"],
    ]);
  });

  it("does not let an older pending transcription reclaim a newer startup", async () => {
    const requests: RealtimeTranscriptionSessionCreateRequest[] = [];
    let resolveOlder: (() => void) | undefined;
    let resolveNewest: (() => void) | undefined;
    const sttSessions = [
      createSttSessionMock(),
      createSttSessionMock(
        () =>
          new Promise<void>((resolve) => {
            resolveOlder = resolve;
          }),
      ),
      createSttSessionMock(
        () =>
          new Promise<void>((resolve) => {
            resolveNewest = resolve;
          }),
      ),
    ];
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn((request) => {
        requests.push(request);
        const session = sttSessions[requests.length - 1];
        if (!session) {
          throw new Error("Unexpected transcription session creation");
        }
        return session;
      }),
    };
    const { context, projections } = createBroadcastContext();
    const incumbent = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();
    const olderPending = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-2",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    const newest = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-3",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });

    expect(sttSessions[1]?.close).toHaveBeenCalledOnce();
    expect(sttSessions[0]?.close).not.toHaveBeenCalled();
    expect(() => getUnifiedTalkSession(olderPending.transcriptionSessionId)).toThrow(
      "Unknown Talk session",
    );
    resolveOlder?.();
    await Promise.resolve();
    expect(sttSessions[0]?.close).not.toHaveBeenCalled();

    resolveNewest?.();
    await Promise.resolve();
    expect(sttSessions[0]?.close).toHaveBeenCalledOnce();
    expect(projections.map((projection) => [projection.runtimeId, projection.state])).toEqual([
      [incumbent.transcriptionSessionId, "active"],
      [incumbent.transcriptionSessionId, "replaced"],
      [newest.transcriptionSessionId, "active"],
    ]);
  });

  it("cleans up a provider error reported synchronously during construction", () => {
    const sttSession = createSttSessionMock();
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn((request) => {
        request.onError?.(new Error("synchronous setup failure"));
        return sttSession;
      }),
    };
    const { context, events } = createBroadcastContext();

    const session = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });

    expect(sttSession.connect).not.toHaveBeenCalled();
    expect(sttSession.close).toHaveBeenCalledOnce();
    expect(() => getUnifiedTalkSession(session.transcriptionSessionId)).toThrow(
      "Unknown Talk session",
    );
    expect(findPayloadByType(events, "error")).toMatchObject({
      message: "synchronous setup failure",
    });
  });

  it("cleans up a provider connect call that throws synchronously", () => {
    const sttSession = {
      connect: vi.fn(() => {
        throw new Error("synchronous connect failure");
      }),
      sendAudio: vi.fn(),
      close: vi.fn(),
      isConnected: vi.fn(() => false),
    };
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn(() => sttSession),
    };
    const { context, events } = createBroadcastContext();

    const session = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });

    expect(sttSession.close).toHaveBeenCalledOnce();
    expect(() => getUnifiedTalkSession(session.transcriptionSessionId)).toThrow(
      "Unknown Talk session",
    );
    expect(getGatewayInteractionSessionProjection("agent:main:main")).toBeUndefined();
    expect(findPayloadByType(events, "error")).toMatchObject({
      message: "synchronous connect failure",
    });
  });

  it("expires through the timer when provider close throws without duplicating terminal events", async () => {
    vi.useFakeTimers();
    const sttSession = {
      connect: vi.fn(async () => undefined),
      sendAudio: vi.fn(),
      close: vi.fn(() => {
        throw new Error("provider close failed");
      }),
      isConnected: vi.fn(() => true),
    };
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn(() => sttSession),
    };
    const { context, events, projections } = createBroadcastContext();
    const session = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();

    expect(() => vi.advanceTimersByTime(30 * 60 * 1000)).not.toThrow();

    expect(() => getUnifiedTalkSession(session.transcriptionSessionId)).toThrow(
      "Unknown Talk session",
    );
    expect(getGatewayInteractionSessionProjection("agent:main:main")).toBeUndefined();
    expect(projections.map((projection) => projection.state)).toEqual(["active", "closed"]);
    expect(
      events.filter((event) => isRecord(event.payload) && event.payload.type === "close"),
    ).toHaveLength(1);

    vi.advanceTimersByTime(30 * 60 * 1000);
    expect(projections.map((projection) => projection.state)).toEqual(["active", "closed"]);
  });

  it("swallows provider close failures after an asynchronous connect failure", async () => {
    const sttSession = {
      connect: vi.fn(async () => {
        throw new Error("async connect failed");
      }),
      sendAudio: vi.fn(),
      close: vi.fn(() => {
        throw new Error("provider close failed");
      }),
      isConnected: vi.fn(() => false),
    };
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn(() => sttSession),
    };
    const { context, events } = createBroadcastContext();
    const session = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });

    await Promise.resolve();
    await Promise.resolve();

    expect(sttSession.close).toHaveBeenCalledOnce();
    expect(() => getUnifiedTalkSession(session.transcriptionSessionId)).toThrow(
      "Unknown Talk session",
    );
    expect(getGatewayInteractionSessionProjection("agent:main:main")).toBeUndefined();
    expect(
      events.filter((event) => isRecord(event.payload) && event.payload.type === "close"),
    ).toHaveLength(1);
  });

  it("keeps the current runtime when a replacement provider session cannot be constructed", async () => {
    let firstRequest: RealtimeTranscriptionSessionCreateRequest | undefined;
    const sttSession = createSttSessionMock();
    let createCount = 0;
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn((request) => {
        createCount += 1;
        if (createCount > 1) {
          throw new Error("transcription setup failed");
        }
        firstRequest = request;
        return sttSession;
      }),
    };
    const { context, events } = createBroadcastContext();
    const first = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();

    expect(() =>
      createTalkTranscriptionRelaySession({
        context,
        connId: "conn-2",
        provider,
        providerConfig: {},
        sessionKey: "agent:main:main",
      }),
    ).toThrow("transcription setup failed");
    expect(sttSession.close).not.toHaveBeenCalled();

    firstRequest?.onPartial?.("still current");
    const partial = findPayloadByType(events, "partial");
    expectRecordFields(partial, "current partial payload", {
      transcriptionSessionId: first.transcriptionSessionId,
      text: "still current",
    });
  });

  it("keeps the current runtime when a replacement provider session fails to connect", async () => {
    const requests: RealtimeTranscriptionSessionCreateRequest[] = [];
    const sttSessions = [
      createSttSessionMock(),
      createSttSessionMock(async () => {
        throw new Error("replacement connect failed");
      }),
    ];
    const provider: RealtimeTranscriptionProviderPlugin = {
      id: "stt-test",
      label: "STT Test",
      isConfigured: () => true,
      createSession: vi.fn((request) => {
        requests.push(request);
        const sttSession = sttSessions[requests.length - 1];
        if (!sttSession) {
          throw new Error("Unexpected transcription session creation");
        }
        return sttSession;
      }),
    };
    const { context, events } = createBroadcastContext();
    const first = createTalkTranscriptionRelaySession({
      context,
      connId: "conn-1",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();

    createTalkTranscriptionRelaySession({
      context,
      connId: "conn-2",
      provider,
      providerConfig: {},
      sessionKey: "agent:main:main",
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(sttSessions[0]?.close).not.toHaveBeenCalled();
    expect(sttSessions[1]?.close).toHaveBeenCalledOnce();
    requests[0]?.onPartial?.("incumbent remains active");
    const partial = findPayloadByType(events, "partial");
    expectRecordFields(partial, "current partial payload", {
      transcriptionSessionId: first.transcriptionSessionId,
      text: "incumbent remains active",
    });
  });
});
