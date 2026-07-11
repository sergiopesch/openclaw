import { describe, expect, it } from "vitest";
import {
  validateInteractionSessionGetParams,
  validateInteractionSessionGetResult,
  validateInteractionSessionProjection,
} from "../index.js";

const baseProjection = {
  interactionSessionId: "interaction-1",
  sessionKey: "agent:main:main",
  epoch: 2,
  runtimeId: "relay-2",
  runtimeKind: "realtime-voice",
} as const;

describe("interaction session protocol schemas", () => {
  it("accepts every flat projection state and an absent projection", () => {
    for (const state of ["active", "replaced", "closed"] as const) {
      expect(validateInteractionSessionProjection({ ...baseProjection, state })).toBe(true);
    }
    expect(
      validateInteractionSessionGetResult({
        sessionKey: "agent:main:main",
        projection: { ...baseProjection, state: "active" },
      }),
    ).toBe(true);
    expect(
      validateInteractionSessionGetResult({
        sessionKey: "agent:main:main",
        projection: { ...baseProjection, state: "closed" },
      }),
    ).toBe(false);
    expect(validateInteractionSessionGetResult({ sessionKey: "agent:main:main" })).toBe(true);
    expect(validateInteractionSessionGetResult({})).toBe(false);
  });

  it("rejects unknown projection fields and invalid lookup params", () => {
    expect(
      validateInteractionSessionProjection({
        ...baseProjection,
        state: "active",
        leaseId: "private-lease",
      }),
    ).toBe(false);
    expect(validateInteractionSessionProjection({ ...baseProjection, state: "idle" })).toBe(false);
    expect(validateInteractionSessionGetParams({ sessionKey: "agent:main:main" })).toBe(true);
    expect(validateInteractionSessionGetParams({ sessionKey: "" })).toBe(false);
    expect(validateInteractionSessionGetParams({ sessionKey: " \t\n " })).toBe(false);
    expect(
      validateInteractionSessionGetParams({
        sessionKey: "agent:main:main",
        leaseId: "private-lease",
      }),
    ).toBe(false);
  });
});
