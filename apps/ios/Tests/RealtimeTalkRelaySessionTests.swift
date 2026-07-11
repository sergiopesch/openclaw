import Foundation
import OpenClawKit
import OpenClawProtocol
import Testing
@testable import OpenClaw

@MainActor
private final class UnusedPCMStreamingAudioPlayer: PCMStreamingAudioPlaying {
    func play(stream: AsyncThrowingStream<Data, Error>, sampleRate: Double) async -> StreamingPlaybackResult {
        fatalError("Playback is not used by this test")
    }

    func stop() -> Double? {
        nil
    }
}

@MainActor
struct RealtimeTalkRelaySessionTests {
    @Test func `output playback finish clears barge in start time`() {
        var speakingStates: [Bool] = []
        let session = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { speakingStates.append($0) })

        session._test_markOutputAudioStarted(nowMs: 100)
        #expect(session._test_isOutputPlaying())
        #expect(session._test_outputStartedAtMs() == 100)

        session._test_markOutputPlaybackFinished()
        #expect(!session._test_isOutputPlaying())
        #expect(session._test_outputStartedAtMs() == nil)
        #expect(speakingStates == [false])

        session._test_markOutputAudioStarted(nowMs: 500)
        #expect(session._test_outputStartedAtMs() == 500)
    }

    @Test func `close after classified error does not replace issue`() async {
        var issues: [TalkRuntimeIssue] = []
        var statuses: [String] = []
        let session = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: "openai", model: "gpt-realtime-2", voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { statuses.append($0) },
            onIssue: { issues.append($0) },
            onSpeakingChanged: { _ in })
        session._test_setRelaySessionId("relay-1")

        await session._test_handleGatewayEvent(EventFrame(
            type: "event",
            event: "talk.event",
            payload: AnyCodable([
                "relaySessionId": "relay-1",
                "type": "error",
                "message": "OpenAI API key rejected with 401",
                "code": "realtime_unavailable",
                "provider": "openai",
                "model": "gpt-realtime-2",
                "transport": "gateway-relay",
                "phase": "connect",
            ]),
            seq: nil,
            stateversion: nil))
        await session._test_handleGatewayEvent(EventFrame(
            type: "event",
            event: "talk.event",
            payload: AnyCodable([
                "relaySessionId": "relay-1",
                "type": "close",
                "reason": "error",
            ]),
            seq: nil,
            stateversion: nil))

        #expect(issues.map(\.code) == [.realtimeUnavailable])
        #expect(statuses == ["OpenAI API key rejected with 401"])
    }

    @Test func `closed relay does not wait for startup ready`() async {
        let session = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: "openai", model: "gpt-realtime-2", voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })

        session.stop()

        #expect(await session._test_waitForStartupCancelled(timeoutSeconds: 1))
    }

    @Test func `startup ready wait covers gateway connect budget`() {
        let session = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: "openai", model: "gpt-realtime-2", voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })

        #expect(session._test_startupReadyTimeoutSeconds() >= 12)
    }

    @Test func `active runtime identity tracks relay lifecycle`() {
        let session = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })

        #expect(session.activeRuntimeID == nil)
        session._test_setRelaySessionId("relay-1")
        #expect(session.activeRuntimeID == "relay-1")

        session.stop()
        #expect(session.activeRuntimeID == nil)
    }

    @Test func `late relay create response closes after cancellation`() async {
        var closedRelayIDs: [String] = []
        let session = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { _ in },
            closeRelaySession: { closedRelayIDs.append($0) },
            onSpeakingChanged: { _ in })
        session.stop()

        let adopted = await session._test_adoptCreatedRelaySessionID("relay-late")

        #expect(!adopted)
        #expect(closedRelayIDs == ["relay-late"])
        #expect(session.activeRuntimeID == nil)
    }

    @Test func `relay ownership matches only the active runtime identity`() async {
        let relaySession = RealtimeTalkRelaySession(
            gateway: GatewayNodeSession(),
            options: .init(sessionKey: "main", provider: nil, model: nil, voice: nil),
            pcmPlayer: UnusedPCMStreamingAudioPlayer(),
            onStatus: { _ in },
            onSpeakingChanged: { _ in })
        relaySession._test_setRelaySessionId("relay-1")
        let manager = TalkModeManager(allowSimulatorCapture: true)
        manager.pcmPlayer = UnusedPCMStreamingAudioPlayer()
        manager._test_prepareEnabledRealtimeSessionForClose(relaySession: relaySession)
        manager._test_handleRealtimeRelayStatus("Listening (Realtime)")
        manager.isSpeaking = true
        manager.isUserSpeechDetected = true
        manager.isPushToTalkActive = true

        #expect(!manager.ownsRealtimeRelayRuntime("relay-other"))
        #expect(manager.ownsRealtimeRelayRuntime("relay-1"))

        manager.stop()
        await Task.yield()
        #expect(!manager.ownsRealtimeRelayRuntime("relay-1"))
    }

    @Test func `canonical takeover failure never allows native fallback`() {
        #expect(!TalkModeManager._test_allowsNativeFallback(canonicalTakeoverPending: true))
        #expect(TalkModeManager._test_allowsNativeFallback(canonicalTakeoverPending: false))
    }
}
