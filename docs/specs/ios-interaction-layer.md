---
title: iOS Interaction Layer
summary: "Working architecture for session-bound, provider-neutral realtime interaction on iOS."
read_when:
  - Extending realtime interaction on iOS
  - Changing Chat, Talk, or interaction-session ownership
  - Adding interaction modalities or realtime providers
  - Testing interaction behavior across Gateway and iOS
---

# iOS Interaction Layer

## Status

Working specification. The first architectural foundation is implemented locally and covered by focused Gateway, protocol, shared Swift, and iOS tests. The broader unified interaction product remains incomplete.

Last architecture review: 2026-07-11.

## Objective

Give a user one continuous OpenClaw session that can accept text, realtime voice, approvals, interruptions, artifacts, and future modalities without turning Chat and Talk into separate products or coupling the agent runtime to one realtime provider.

The interaction system sits between the user interface and the agent-facing Gateway surface:

```text
User interface
  -> interaction session
      -> realtime runtime adapters
          -> Gateway
              -> agent
                  -> harness
                      -> model provider
```

Realtime does not sit between the agent and its harness. Harness selection and provider execution remain agent-runtime concerns.

## Product Model

The durable user concept is a session, not a Chat mode or Talk mode.

A session can eventually contain:

- typed messages
- full-duplex voice
- streaming responses
- interruptions
- approvals
- code tasks
- screenshots and camera input
- artifacts
- device actions

Voice is one interaction modality attached to the same session. A provider room, transcription stream, or WebRTC connection is a replaceable runtime, not the identity of the user session.

## Architectural Decisions

### Gateway owns canonical interaction state

The Gateway is the authority because multiple clients and runtimes can compete for the same OpenClaw session. Client-local state alone cannot safely decide which runtime owns a session after reconnects, delayed responses, or cross-device takeover.

There is one process-local interaction actor for each canonical OpenClaw session key. The actor owns:

- a stable interaction-session identifier
- a monotonically increasing epoch
- at most one active runtime lease
- runtime replacement and closure projections
- stale lease rejection
- startup ordering when runtimes become ready out of order

The current actor is intentionally process-local. Durable interaction history and replay are a later layer and must not be inferred from this actor.

### Runtime adapters are lease-bound

Realtime voice, managed rooms, and transcription remain separate adapters. Each adapter must acquire and retain a lease before it can act for a session.

A lease carries:

- canonical session key
- interaction-session identifier
- epoch
- opaque lease identifier
- exact runtime identifier
- closed runtime kind

Every externally visible runtime operation is fenced by the lease. Replacing a runtime advances the epoch before revocation callbacks execute, so reentrant cleanup cannot regain authority.

### Takeover is explicit

An ordinary start request must not silently replace a runtime owned by another client or modality. The UI exposes an explicit move-here action when canonical ownership belongs elsewhere.

Configuration changes may restart the provider runtime while preserving the same interaction session binding. A provider restart is not a user-visible session move.

### The iOS client consumes a projection

iOS does not independently decide canonical ownership. It subscribes to `interaction.session.changed`, obtains an `interaction.session.get` snapshot, and reduces both into a local projection store.

The synchronization order is subscribe first, snapshot second. Events arriving during a snapshot are buffered and replayed afterward. This closes the race where a transition occurs between snapshot and subscription.

Each requested key tracks snapshot generation and failure independently. Canonical aliases returned by the Gateway are retained so an input key and its resolved key represent the same session.

Any event sequence gap or decode failure makes affected state stale until snapshots recover both the focused Chat session and the pinned Talk session.

## State Model

### Runtime states

The protocol exposes a closed union:

- `active`: the exact runtime currently owns the interaction session
- `replaced`: that runtime lost ownership to a newer epoch
- `closed`: that runtime ended without a replacement projection attached to it

Snapshot lookup returns only an active projection or no projection. Terminal projections are events, not current snapshots.

### Ordering rules

For one interaction-session identifier:

1. A higher epoch supersedes a lower epoch.
2. A terminal event applies only when session identifier, epoch, and runtime identifier exactly match the active projection.
3. A stale release cannot clear a replacement runtime.
4. The newest accepted startup request wins even if an older provider connection becomes ready later.
5. Revocation and projection callbacks cannot roll back an actor transition.

### Client availability

The iOS projection store distinguishes:

- disconnected
- unsupported by an older Gateway
- syncing
- current
- stale

Starting a canonical realtime runtime is permitted only from current ownership state. Legacy local behavior is isolated to the unsupported-Gateway path.

## Protocol Surface

Request:

```text
interaction.session.get
```

Event:

```text
interaction.session.changed
```

The request accepts a non-blank session key. The Gateway trims and canonicalizes it through the normal session-store key resolver before actor lookup. The response includes the canonical key even when no runtime is active.

Protocol additions are additive and do not require a protocol version bump. TypeBox remains the source, JSON Schema is generated from it, and Swift models are generated from the schema.

## Implementation Map

### Gateway authority

- `src/gateway/interaction-session-actor.ts`
- `src/gateway/interaction-session-events.ts`
- `src/gateway/server-methods/interaction-session.ts`

The actor registry, startup tickets, epoch and lease fencing, projection broadcasting, and snapshot method live here.

### Runtime adapters

- `src/gateway/talk-realtime-relay.ts`
- `src/gateway/talk-transcription-relay.ts`
- `src/gateway/talk-handoff.ts`

The adapters bind provider lifecycle to canonical ownership. Construction failures, connection failures, aborts, expiry, delivery errors, and repeated teardown must release ownership without throwing or leaking a registry entry.

### Protocol

- `packages/gateway-protocol/src/schema/interaction-sessions.ts`
- `packages/gateway-protocol/src/index.ts`
- `apps/shared/OpenClawKit/Sources/OpenClawProtocol/GatewayModels.swift`

### iOS projection and control

- `apps/ios/Sources/Interaction/InteractionSessionStore.swift`
- `apps/ios/Sources/Model/NodeAppModel.swift`
- `apps/ios/Sources/Voice/TalkModeManager.swift`
- `apps/ios/Sources/Voice/RealtimeTalkRelaySession.swift`
- `apps/shared/OpenClawKit/Sources/OpenClawChatUI/ChatTalkControl.swift`

The active Talk session key is immutable for that runtime. Changing focused Chat does not retarget an active Talk runtime. Pending relay identity handles event-before-response and late-response races.

## Foundation Acceptance Criteria

The current foundation is complete when all of the following hold:

- one canonical actor exists per normalized session key
- only one runtime lease can be authoritative at an epoch
- stale providers cannot mutate or release newer ownership
- delayed startup cannot defeat a newer accepted startup
- all three existing realtime adapters bind to the actor
- protocol snapshots and transition events are typed and generated for Swift
- iOS recovers from subscription races, sequence gaps, decode failures, and partial snapshot failure
- focused Chat and active Talk can track different session keys safely
- moving a runtime between sessions requires an explicit user action
- provider configuration restart preserves the active session binding
- older Gateways retain a separate, bounded compatibility path

## Validation Record

The implemented foundation has passed:

- broad Gateway suite: 5,932 tests across 381 files
- focused Gateway interaction slice: 199 tests across 17 files
- focused protocol schema tests
- focused iOS and shared Swift interaction tests
- shared Swift package tests
- deterministic protocol generation checks
- Oxlint, Oxfmt, SwiftFormat, Swift parse, and `git diff --check`
- Simulator build, launch, accessibility inspection, start, and stop interaction
- targeted independent review with no remaining actionable finding

The canonical local Xcode project could not complete manifest compilation on the corporate machine because endpoint security terminated package-manifest processes containing the project names. The same source modules built and tested successfully in a neutral temporary harness. That workaround changed no canonical project or formatter configuration.

This distinction matters: source behavior has broad automated proof, while a clean canonical-project build still needs proof on an unrestricted Apple host.

## Remote Apple Test Lab

A Linux server alone cannot run Xcode or the iOS Simulator. The preferred remote validation topology is:

```text
developer or automation
  -> dedicated Apple Silicon host
      -> Xcode, Simulator, XcodeBuildMCP, UI tests
      -> signed TestFlight build
  -> Linux OpenClaw test Gateway
      -> realtime providers and fault injection
  -> physical iPhone
      -> audio, interruption, background, and network validation
```

The Apple host may be rented dedicated hardware or a self-hosted Mac mini. It should provide SSH and remote desktop access, pin Xcode and Simulator versions, and publish test artifacts such as `xcresult` bundles, logs, screenshots, and videos.

The Linux Gateway can run on Hetzner or another provider. Keeping the Apple host and Gateway on one private network reduces setup, but an authenticated public test Gateway also permits TestFlight builds on physical devices.

Simulator proof covers ownership, reducer behavior, reconnects, UI, and deterministic injected media. Physical-device proof remains necessary for microphone and speaker latency, echo cancellation, Bluetooth routing, system interruptions, backgrounding, and cellular or Wi-Fi transitions.

## Next Layer

Do not add another UI layer yet. The next architectural unit should be a typed interaction event envelope and reducer contract above transport-specific events.

That layer should define:

- stable event identity and ordering
- text, audio, interruption, approval, task, and artifact variants
- partial and terminal lifecycle semantics
- idempotent reduction
- reconnect and replay boundaries
- capability negotiation without provider names in the product model
- observability correlation with interaction-session identifier and epoch

The event layer must remain distinct from durable history. First define the live typed stream and reducer. Then design persistence and replay with an explicit SQLite owner and migration strategy.

## Deferred Work

- durable interaction history and replay across Gateway restart
- typed multimodal event envelope and reducer
- unified Chat and Talk product redesign
- camera, screen, and device interaction modalities
- Android and other client projections
- cross-device continuity beyond explicit runtime ownership
- physical-device realtime performance and interruption testing
- production observability, quotas, and abuse controls

## Non-Goals

- placing realtime between the agent and harness
- making a provider room the user session identity
- coupling canonical state to OpenAI or another provider
- silently taking over a runtime during an ordinary start
- persisting runtime state in JSON or sidecar files
- treating Simulator-only testing as proof of physical audio behavior

## Continuation Checklist

Before extending this work:

1. Read this specification and the interaction-session actor tests.
2. Confirm the working branch contains every file in the implementation map.
3. Run focused Gateway, protocol, and iOS projection tests before changing behavior.
4. Preserve the actor, adapter, protocol, and client-projection ownership boundaries.
5. Add the typed event envelope without expanding Chat or Talk UI structure.
6. Validate the canonical Xcode project on an unrestricted Apple host.
7. Keep remote-provider and physical-device proof separate from deterministic unit proof.
