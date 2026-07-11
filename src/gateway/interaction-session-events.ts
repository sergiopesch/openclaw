// Broadcasts canonical interaction-session projections to read-scoped clients.
import type { InteractionSessionBindingProjection } from "./interaction-session-actor.js";
import type { GatewayRequestContext } from "./server-methods/shared-types.js";

export const INTERACTION_SESSION_CHANGED_EVENT = "interaction.session.changed";

/** Publishes one ordered actor transition through the Gateway event sequencer. */
export function broadcastInteractionSessionProjection(
  context: Pick<GatewayRequestContext, "broadcast">,
  projection: InteractionSessionBindingProjection,
): void {
  context.broadcast(INTERACTION_SESSION_CHANGED_EVENT, projection);
}
