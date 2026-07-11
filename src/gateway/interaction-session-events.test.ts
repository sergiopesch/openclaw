import { describe, expect, it, vi } from "vitest";
import {
  INTERACTION_SESSION_CHANGED_EVENT,
  broadcastInteractionSessionProjection,
} from "./interaction-session-events.js";

describe("interaction session events", () => {
  it("broadcasts the projection as the global event payload", () => {
    const broadcast = vi.fn();
    const projection = {
      interactionSessionId: "interaction-1",
      sessionKey: "agent:main:main",
      epoch: 2,
      runtimeId: "relay-2",
      runtimeKind: "realtime-voice",
      state: "active",
    } as const;

    broadcastInteractionSessionProjection({ broadcast }, projection);

    expect(broadcast).toHaveBeenCalledWith(INTERACTION_SESSION_CHANGED_EVENT, projection);
  });
});
