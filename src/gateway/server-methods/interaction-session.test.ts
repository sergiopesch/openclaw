import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RespondFn } from "./types.js";

const getGatewayInteractionSessionProjection = vi.hoisted(() => vi.fn());

vi.mock("../interaction-session-actor.js", () => ({
  getGatewayInteractionSessionProjection,
}));

import { interactionSessionHandlers } from "./interaction-session.js";

const runtimeConfig = {
  session: { mainKey: "primary" },
  agents: { list: [{ id: "ops", default: true }] },
};

async function runHandler(params: Record<string, unknown>) {
  const respond = vi.fn<RespondFn>();
  await interactionSessionHandlers["interaction.session.get"]({
    req: { type: "req", id: "req-interaction-session", method: "interaction.session.get" },
    params,
    respond,
    context: { getRuntimeConfig: () => runtimeConfig } as never,
    client: null,
    isWebchatConnect: () => false,
  });
  return respond;
}

describe("interaction.session.get", () => {
  beforeEach(() => {
    getGatewayInteractionSessionProjection.mockReset();
  });

  it("canonicalizes the requested key with runtime config before actor lookup", async () => {
    const projection = {
      interactionSessionId: "interaction-1",
      sessionKey: "agent:ops:primary",
      epoch: 1,
      runtimeId: "relay-1",
      runtimeKind: "managed-room",
      state: "active",
    } as const;
    getGatewayInteractionSessionProjection.mockReturnValue(projection);

    const respond = await runHandler({ sessionKey: "main" });

    expect(getGatewayInteractionSessionProjection).toHaveBeenCalledWith("agent:ops:primary");
    expect(respond).toHaveBeenCalledWith(true, {
      sessionKey: "agent:ops:primary",
      projection,
    });
  });

  it("trims the requested key before canonical lookup", async () => {
    const respond = await runHandler({ sessionKey: "  main  " });

    expect(getGatewayInteractionSessionProjection).toHaveBeenCalledWith("agent:ops:primary");
    expect(respond).toHaveBeenCalledWith(true, { sessionKey: "agent:ops:primary" });
  });

  it("returns the canonical key when no interaction runtime is active", async () => {
    const respond = await runHandler({ sessionKey: "agent:ops:other" });

    expect(getGatewayInteractionSessionProjection).toHaveBeenCalledWith("agent:ops:other");
    expect(respond).toHaveBeenCalledWith(true, { sessionKey: "agent:ops:other" });
  });

  it("rejects invalid params before actor lookup", async () => {
    const respond = await runHandler({ sessionKey: "", leaseId: "private-lease" });

    expect(getGatewayInteractionSessionProjection).not.toHaveBeenCalled();
    expect(respond).toHaveBeenCalledWith(
      false,
      undefined,
      expect.objectContaining({ code: "INVALID_REQUEST" }),
    );
  });

  it("rejects whitespace-only session keys before actor lookup", async () => {
    const respond = await runHandler({ sessionKey: " \t\n " });

    expect(getGatewayInteractionSessionProjection).not.toHaveBeenCalled();
    expect(respond).toHaveBeenCalledWith(
      false,
      undefined,
      expect.objectContaining({ code: "INVALID_REQUEST" }),
    );
  });
});
