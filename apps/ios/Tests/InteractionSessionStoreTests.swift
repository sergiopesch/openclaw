import Foundation
import OpenClawChatUI
import OpenClawKit
import OpenClawProtocol
import Testing
@testable import OpenClaw

@MainActor
private final class InteractionTestPCMPlayer: PCMStreamingAudioPlaying {
    func play(stream: AsyncThrowingStream<Data, Error>, sampleRate: Double) async -> StreamingPlaybackResult {
        fatalError("Playback is not used by this test")
    }

    func stop() -> Double? {
        nil
    }
}

@MainActor
struct InteractionSessionStoreTests {
    @Test func `snapshot then buffered event keeps newest runtime`() {
        let store = InteractionSessionStore()
        let generation = store.beginSnapshot(for: "main")
        store.recordEvent(Self.active(id: "interaction-2", runtimeID: "relay-2", epoch: 1))
        store.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "relay-1", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        #expect(store.availability == .current)
        #expect(store.runtime(for: "main")?.runtimeID == "relay-2")
        #expect(store.runtime(for: "main")?.state == .active)
    }

    @Test func `stale terminal event cannot clear replacement runtime`() {
        let store = InteractionSessionStore()
        let generation = store.beginSnapshot(for: "main")
        store.completeSnapshot(
            Self.activeSnapshot(id: "interaction-2", runtimeID: "relay-2", epoch: 2),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)
        store.recordEvent(Self.closed(id: "interaction-1", runtimeID: "relay-1", epoch: 1))

        #expect(store.runtime(for: "main")?.runtimeID == "relay-2")
        #expect(store.runtime(for: "main")?.state == .active)
    }

    @Test func `terminal event must match the active epoch and runtime`() {
        let store = InteractionSessionStore()
        let generation = store.beginSnapshot(for: "main")
        store.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "relay-2", epoch: 2),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)
        store.recordEvent(Self.replaced(id: "interaction-1", runtimeID: "relay-1", epoch: 1))

        #expect(store.runtime(for: "main")?.runtimeID == "relay-2")
        store.recordEvent(Self.replaced(id: "interaction-1", runtimeID: "relay-2", epoch: 2))
        #expect(store.runtime(for: "main")?.state == .replaced)
    }

    @Test func `sequence gap makes projection unavailable until snapshot completes`() {
        let store = InteractionSessionStore()
        let generation = store.beginSnapshot(for: "main")
        store.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "relay-1", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)
        store.markStale()

        #expect(store.availability == .stale)
        let refreshedGeneration = store.beginSnapshot(for: "main")
        store.completeSnapshot(
            nil,
            for: "main",
            canonicalSessionKey: "main",
            generation: refreshedGeneration)
        #expect(store.availability == .current)
        #expect(store.runtime(for: "main") == nil)
    }

    @Test func `empty snapshot records canonical alias for later events`() {
        let store = InteractionSessionStore()
        let generation = store.beginSnapshot(for: "main")
        store.completeSnapshot(
            nil,
            for: "main",
            canonicalSessionKey: "agent:ops:primary",
            generation: generation)

        store.recordEvent(Self.active(
            id: "interaction-1",
            runtimeID: "relay-1",
            epoch: 1,
            sessionKey: "agent:ops:primary"))

        #expect(store.runtime(for: "main")?.runtimeID == "relay-1")
    }

    @Test func `older snapshot cannot complete A newer refresh`() {
        let store = InteractionSessionStore()
        let firstGeneration = store.beginSnapshot(for: "main")
        let secondGeneration = store.beginSnapshot(for: "main")

        store.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "relay-old", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: firstGeneration)
        #expect(store.availability == .syncing)
        #expect(store.runtime(for: "main") == nil)

        store.completeSnapshot(
            Self.activeSnapshot(id: "interaction-2", runtimeID: "relay-new", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: secondGeneration)
        #expect(store.runtime(for: "main")?.runtimeID == "relay-new")
    }

    @Test func `overlapping snapshots preserve unrelated session events`() {
        let store = InteractionSessionStore()
        let firstGeneration = store.beginSnapshot(for: "session-a")
        store.completeSnapshot(
            Self.activeSnapshot(
                id: "interaction-a",
                runtimeID: "relay-a-1",
                epoch: 1,
                sessionKey: "session-a"),
            for: "session-a",
            canonicalSessionKey: "session-a",
            generation: firstGeneration)

        let sessionBGeneration = store.beginSnapshot(for: "session-b")
        store.recordEvent(Self.active(
            id: "interaction-a",
            runtimeID: "relay-a-2",
            epoch: 2,
            sessionKey: "session-a"))
        let sessionCGeneration = store.beginSnapshot(for: "session-c")

        store.completeSnapshot(
            nil,
            for: "session-c",
            canonicalSessionKey: "session-c",
            generation: sessionCGeneration)
        #expect(store.availability == .syncing)
        store.completeSnapshot(
            nil,
            for: "session-b",
            canonicalSessionKey: "session-b",
            generation: sessionBGeneration)

        #expect(store.availability == .current)
        #expect(store.isCurrent(for: "session-a"))
        #expect(store.runtime(for: "session-a")?.runtimeID == "relay-a-2")
    }

    @Test func `successful sibling snapshot cannot hide a failed recovery key`() {
        let store = InteractionSessionStore()
        let focusedGeneration = store.beginSnapshot(for: "session-focused")
        store.failSnapshot(for: "session-focused", generation: focusedGeneration)

        let pinnedGeneration = store.beginSnapshot(for: "session-pinned")
        store.completeSnapshot(
            nil,
            for: "session-pinned",
            canonicalSessionKey: "session-pinned",
            generation: pinnedGeneration)

        #expect(store.availability == .stale)
        #expect(!store.isCurrent(for: "session-focused"))
        #expect(store.isCurrent(for: "session-pinned"))

        let retryGeneration = store.beginSnapshot(for: "session-focused")
        store.completeSnapshot(
            nil,
            for: "session-focused",
            canonicalSessionKey: "session-focused",
            generation: retryGeneration)

        #expect(store.availability == .current)
        #expect(store.isCurrent(for: "session-focused"))
    }

    @Test func `talk start rejects disconnected syncing and stale ownership`() {
        UserDefaults.standard.removeObject(forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        talkMode.updateGatewayConnected(true)
        let appModel = NodeAppModel(talkMode: talkMode)

        appModel.setTalkEnabled(true)
        #expect(!talkMode.isEnabled)
        #expect(!UserDefaults.standard.bool(forKey: "talk.enabled"))

        _ = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.setTalkEnabled(true)
        #expect(!talkMode.isEnabled)
        #expect(!UserDefaults.standard.bool(forKey: "talk.enabled"))

        appModel.interactionSessions.markStale()
        appModel.setTalkEnabled(true)
        #expect(!talkMode.isEnabled)
        #expect(!UserDefaults.standard.bool(forKey: "talk.enabled"))
    }

    @Test func `active talk session remains bound while focus changes`() {
        UserDefaults.standard.removeObject(forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        appModel.interactionSessions.markUnsupported()

        appModel.setTalkEnabled(true, sessionKey: "session-a")
        #expect(talkMode.interactionSessionKey == "session-a")
        #expect(appModel.interactionActionState(for: "session-a") == .localActive)
        #expect(appModel.interactionActionState(for: "session-b") == .unavailable)

        appModel.focusChatSession("session-b")
        appModel.setTalkEnabled(true, sessionKey: "session-b")

        #expect(talkMode.isEnabled)
        #expect(talkMode.interactionSessionKey == "session-a")
        appModel.setTalkEnabled(false)
    }

    @Test func `focus of current session does not invalidate immediate talk start`() {
        UserDefaults.standard.removeObject(forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            nil,
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        appModel.focusChatSession("main")
        #expect(appModel.interactionSessions.availability == .current)

        appModel.setTalkEnabled(true, sessionKey: "main")
        #expect(talkMode.isEnabled)
        #expect(talkMode.interactionSessionKey == "main")
        appModel.setTalkEnabled(false)
    }

    @Test func `action state comes from canonical availability and ownership`() {
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        #expect(appModel.interactionActionState(for: "main") == .unavailable)

        talkMode.updateGatewayConnected(true)
        appModel.interactionSessions.markUnsupported()
        #expect(appModel.interactionActionState(for: "main") == .idle)
        talkMode.isEnabled = true
        #expect(appModel.interactionActionState(for: "main") == .localActive)

        talkMode.isEnabled = false
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "remote-relay", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)
        #expect(appModel.interactionActionState(for: "main") == .unavailable)

        talkMode.enterScreenshotFixtureMode()
        #expect(appModel.interactionActionState(for: "main") == .remoteActive)

        talkMode.isEnabled = true
        appModel.interactionSessions.markStale()
        #expect(appModel.interactionActionState(for: "main") == .localActive)
        talkMode.isEnabled = false
        #expect(appModel.interactionActionState(for: "main") == .unavailable)
    }

    @Test func `canonical replacement uses app level talk cleanup`() {
        let relaySession = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: InteractionTestPCMPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })
        relaySession._test_setRelaySessionId("relay-1")
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        talkMode.pcmPlayer = InteractionTestPCMPlayer()
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode._test_prepareEnabledRealtimeSessionForClose(relaySession: relaySession)
        UserDefaults.standard.set(true, forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }

        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "relay-1", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)
        appModel.applyInteractionSessionProjection(
            Self.replaced(id: "interaction-1", runtimeID: "relay-1", epoch: 1))

        #expect(!talkMode.isEnabled)
        #expect(talkMode.activeRealtimeRelayRuntimeID == nil)
        #expect(!UserDefaults.standard.bool(forKey: "talk.enabled"))
    }

    @Test func `client local talk intent remains stoppable without a canonical runtime`() {
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode.updateGatewayConnected(true)
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            nil,
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        talkMode.isEnabled = true
        #expect(appModel.interactionActionState(for: "main") == .localActive)

        UserDefaults.standard.set(true, forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }
        appModel.applyInteractionSessionProjection(
            Self.active(id: "interaction-1", runtimeID: "remote-relay", epoch: 1))
        #expect(!talkMode.isEnabled)
        #expect(!UserDefaults.standard.bool(forKey: "talk.enabled"))
        #expect(appModel.interactionActionState(for: "main") == .unavailable)
    }

    @Test func `unavailable remote runtime blocks client local talk start`() {
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode.updateGatewayConnected(true)
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "remote-relay", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        appModel.setTalkEnabled(true)

        #expect(!talkMode.isEnabled)
        #expect(talkMode.statusText == "Active on another device")
        #expect(!UserDefaults.standard.bool(forKey: "talk.enabled"))
    }

    @Test func `remote runtime takeover requires explicit chat action`() {
        UserDefaults.standard.removeObject(forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode.enterScreenshotFixtureMode()
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "remote-relay", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        appModel.setTalkEnabled(true, sessionKey: "main")
        #expect(!talkMode.isEnabled)

        appModel.setTalkEnabled(
            true,
            sessionKey: "main",
            allowCanonicalTakeover: true)
        #expect(talkMode.isEnabled)
        #expect(talkMode.interactionSessionKey == "main")
        appModel.setTalkEnabled(false)
    }

    @Test func `provider restart preserves active interaction session binding`() {
        UserDefaults.standard.removeObject(forKey: "talk.enabled")
        defer { UserDefaults.standard.removeObject(forKey: "talk.enabled") }
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        appModel.interactionSessions.markUnsupported()
        appModel.setTalkEnabled(true, sessionKey: "session-a")
        appModel.focusChatSession("session-b")

        talkMode.applyProviderSelectionChanged()

        #expect(talkMode.isEnabled)
        #expect(talkMode.interactionSessionKey == "session-a")
        appModel.setTalkEnabled(false)
    }

    @Test func `early active projection remains local until relay creation resolves`() {
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        let generation = appModel.interactionSessions.beginSnapshot(for: "session-a")
        appModel.interactionSessions.completeSnapshot(
            nil,
            for: "session-a",
            canonicalSessionKey: "session-a",
            generation: generation)
        talkMode._test_preparePendingRealtimeRelayCreation(sessionKey: "session-a")

        appModel.applyInteractionSessionProjection(Self.active(
            id: "interaction-a",
            runtimeID: "relay-local",
            epoch: 1,
            sessionKey: "session-a"))
        #expect(talkMode.isEnabled)

        let relaySession = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "session-a", provider: nil, model: nil, voice: nil),
            pcmPlayer: InteractionTestPCMPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })
        relaySession._test_setRelaySessionId("relay-local")
        talkMode._test_resolvePendingRealtimeRelayCreation(relaySession: relaySession)

        #expect(talkMode.isEnabled)
        #expect(talkMode.ownsRealtimeRelayRuntime("relay-local"))
        appModel.setTalkEnabled(false)
    }

    @Test func `ordinary delayed remote active stops known local relay`() {
        let relaySession = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: InteractionTestPCMPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })
        relaySession._test_setRelaySessionId("relay-local")
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode._test_prepareEnabledRealtimeSessionForClose(relaySession: relaySession)
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            nil,
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        appModel.applyInteractionSessionProjection(Self.active(
            id: "interaction-a",
            runtimeID: "relay-remote",
            epoch: 1))

        #expect(!talkMode.isEnabled)
        #expect(!talkMode.ownsRealtimeRelayRuntime("relay-local"))
    }

    @Test func `explicit takeover tolerates old active after local relay ID is known`() {
        let relaySession = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: InteractionTestPCMPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })
        relaySession._test_setRelaySessionId("relay-local")
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode._test_prepareEnabledRealtimeSessionForClose(relaySession: relaySession)
        talkMode._test_setCanonicalTakeoverInProgress(true)
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            nil,
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        appModel.applyInteractionSessionProjection(Self.active(
            id: "interaction-a",
            runtimeID: "relay-old",
            epoch: 1))

        #expect(talkMode.isEnabled)
        #expect(talkMode.ownsRealtimeRelayRuntime("relay-local"))
        talkMode._test_setCanonicalTakeoverInProgress(false)
        appModel.setTalkEnabled(false)
    }

    @Test func `old terminal event cannot stop pending provider restart`() {
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode._test_preparePendingRealtimeRelayCreation(sessionKey: "main")
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")
        appModel.interactionSessions.completeSnapshot(
            Self.activeSnapshot(id: "interaction-old", runtimeID: "relay-old", epoch: 1),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        appModel.applyInteractionSessionProjection(
            Self.closed(id: "interaction-old", runtimeID: "relay-old", epoch: 1))

        #expect(talkMode.isEnabled)
        appModel.setTalkEnabled(false)
    }

    @Test func `activity in another session does not stop bound local talk`() {
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode.updateMainSessionKey("session-a")
        talkMode.isEnabled = true
        let generation = appModel.interactionSessions.beginSnapshot(for: "session-a")
        appModel.interactionSessions.completeSnapshot(
            nil,
            for: "session-a",
            canonicalSessionKey: "session-a",
            generation: generation)

        appModel.applyInteractionSessionProjection(Self.active(
            id: "interaction-b",
            runtimeID: "remote-b",
            epoch: 1,
            sessionKey: "session-b"))

        #expect(talkMode.isEnabled)
    }

    @Test func `buffered older event cannot stop snapshot confirmed local owner`() {
        let relaySession = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: InteractionTestPCMPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })
        relaySession._test_setRelaySessionId("relay-local")
        let talkMode = TalkModeManager(allowSimulatorCapture: true)
        talkMode.pcmPlayer = InteractionTestPCMPlayer()
        let appModel = NodeAppModel(talkMode: talkMode)
        talkMode._test_prepareEnabledRealtimeSessionForClose(relaySession: relaySession)
        let generation = appModel.interactionSessions.beginSnapshot(for: "main")

        appModel.applyInteractionSessionProjection(
            Self.active(id: "interaction-1", runtimeID: "relay-old", epoch: 1))
        appModel.interactionSessions.completeSnapshot(
            Self.activeSnapshot(id: "interaction-1", runtimeID: "relay-local", epoch: 2),
            for: "main",
            canonicalSessionKey: "main",
            generation: generation)

        #expect(talkMode.isEnabled)
        #expect(appModel.interactionSessions.runtime(for: "main")?.runtimeID == "relay-local")
    }

    @Test func `gap refresh makes only refreshed session current`() {
        let store = InteractionSessionStore()
        let firstGeneration = store.beginSnapshot(for: "session-a")
        store.completeSnapshot(
            Self.activeSnapshot(
                id: "interaction-a",
                runtimeID: "relay-a",
                epoch: 1,
                sessionKey: "session-a"),
            for: "session-a",
            canonicalSessionKey: "session-a",
            generation: firstGeneration)
        let secondGeneration = store.beginSnapshot(for: "session-b")
        store.completeSnapshot(
            Self.activeSnapshot(
                id: "interaction-b",
                runtimeID: "relay-b",
                epoch: 1,
                sessionKey: "session-b"),
            for: "session-b",
            canonicalSessionKey: "session-b",
            generation: secondGeneration)
        store.markStale()

        let refreshedGeneration = store.beginSnapshot(for: "session-a")
        store.completeSnapshot(
            nil,
            for: "session-a",
            canonicalSessionKey: "session-a",
            generation: refreshedGeneration)

        #expect(store.isCurrent(for: "session-a"))
        #expect(!store.isCurrent(for: "session-b"))
        #expect(store.runtime(for: "session-b") == nil)
    }

    private static func active(
        id: String,
        runtimeID: String,
        epoch: Int,
        sessionKey: String = "main") -> InteractionSessionProjection
    {
        .active(.init(
            interactionsessionid: id,
            sessionkey: sessionKey,
            epoch: epoch,
            runtimeid: runtimeID,
            runtimekind: .realtimeVoice,
            state: "active"))
    }

    private static func activeSnapshot(
        id: String,
        runtimeID: String,
        epoch: Int,
        sessionKey: String = "main") -> InteractionSessionActiveProjection
    {
        .init(
            interactionsessionid: id,
            sessionkey: sessionKey,
            epoch: epoch,
            runtimeid: runtimeID,
            runtimekind: .realtimeVoice,
            state: "active")
    }

    private static func replaced(id: String, runtimeID: String, epoch: Int) -> InteractionSessionProjection {
        .replaced(.init(
            interactionsessionid: id,
            sessionkey: "main",
            epoch: epoch,
            runtimeid: runtimeID,
            runtimekind: .realtimeVoice,
            state: "replaced"))
    }

    private static func closed(id: String, runtimeID: String, epoch: Int) -> InteractionSessionProjection {
        .closed(.init(
            interactionsessionid: id,
            sessionkey: "main",
            epoch: epoch,
            runtimeid: runtimeID,
            runtimekind: .realtimeVoice,
            state: "closed"))
    }
}
