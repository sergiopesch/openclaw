// Interaction-session RPCs expose the active Gateway actor projection by canonical session key.
import {
  ErrorCodes,
  errorShape,
  type InteractionSessionGetResult,
  validateInteractionSessionGetParams,
} from "../../../packages/gateway-protocol/src/index.js";
import { getGatewayInteractionSessionProjection } from "../interaction-session-actor.js";
import { resolveSessionStoreKey } from "../session-store-key.js";
import type { GatewayRequestHandlers } from "./types.js";
import { assertValidParams } from "./validation.js";

export const interactionSessionHandlers: GatewayRequestHandlers = {
  "interaction.session.get": ({ params, respond, context }) => {
    if (
      !assertValidParams(
        params,
        validateInteractionSessionGetParams,
        "interaction.session.get",
        respond,
      )
    ) {
      return;
    }
    const requestedSessionKey = params.sessionKey.trim();
    if (!requestedSessionKey) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "interaction.session.get requires a session key"),
      );
      return;
    }
    const sessionKey = resolveSessionStoreKey({
      cfg: context.getRuntimeConfig(),
      sessionKey: requestedSessionKey,
    });
    const projection = getGatewayInteractionSessionProjection(sessionKey);
    const result: InteractionSessionGetResult = projection
      ? { sessionKey, projection }
      : { sessionKey };
    respond(true, result);
  },
};
