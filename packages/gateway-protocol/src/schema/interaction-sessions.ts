// Gateway Protocol schemas for canonical realtime interaction-session projections.
import { Type } from "typebox";
import { NonEmptyString } from "./primitives.js";

/** Closed runtime kinds owned by the Gateway interaction-session actor. */
export const InteractionRuntimeKindSchema = Type.Union([
  Type.Literal("managed-room"),
  Type.Literal("realtime-voice"),
  Type.Literal("transcription"),
]);

const InteractionSessionProjectionFields = {
  interactionSessionId: NonEmptyString,
  sessionKey: NonEmptyString,
  epoch: Type.Integer({ minimum: 1 }),
  runtimeId: NonEmptyString,
  runtimeKind: InteractionRuntimeKindSchema,
};

export const InteractionSessionActiveProjectionSchema = Type.Object(
  { ...InteractionSessionProjectionFields, state: Type.Literal("active") },
  { additionalProperties: false },
);

export const InteractionSessionReplacedProjectionSchema = Type.Object(
  { ...InteractionSessionProjectionFields, state: Type.Literal("replaced") },
  { additionalProperties: false },
);

export const InteractionSessionClosedProjectionSchema = Type.Object(
  { ...InteractionSessionProjectionFields, state: Type.Literal("closed") },
  { additionalProperties: false },
);

/** Public actor projection emitted on every interaction runtime transition. */
export const InteractionSessionProjectionSchema = Type.Union([
  InteractionSessionActiveProjectionSchema,
  InteractionSessionReplacedProjectionSchema,
  InteractionSessionClosedProjectionSchema,
]);

/** Lookup request for the interaction runtime bound to one OpenClaw session. */
export const InteractionSessionGetParamsSchema = Type.Object(
  { sessionKey: Type.String({ minLength: 1, pattern: "\\S" }) },
  { additionalProperties: false },
);

/** Lookup result; projection is absent when no interaction runtime is active. */
export const InteractionSessionGetResultSchema = Type.Object(
  {
    sessionKey: NonEmptyString,
    projection: Type.Optional(InteractionSessionActiveProjectionSchema),
  },
  { additionalProperties: false },
);
