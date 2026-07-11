import Testing
@testable import OpenClawChatUI

struct ChatTalkControlTests {
    @Test func `action states provide canonical button presentations`() {
        let cases: [(OpenClawChatTalkControl.ActionState, String, String, String, Bool)] = [
            (.idle, "Talk", "waveform", "Start realtime chat", true),
            (.localActive, "Stop", "stop.fill", "Stop realtime chat", true),
            (.remoteActive, "Move Here", "arrow.right.circle.fill", "Move realtime chat to this device", true),
            (.unavailable, "Talk", "waveform.slash", "Realtime chat unavailable", false),
        ]

        for (state, title, systemImage, accessibilityLabel, isEnabled) in cases {
            let presentation = state.presentation
            #expect(presentation.title == title)
            #expect(presentation.systemImage == systemImage)
            #expect(presentation.accessibilityLabel == accessibilityLabel)
            #expect(presentation.isEnabled == isEnabled)
        }
    }

    @Test @MainActor func `talk control preserves media telemetry and performs its action`() {
        var performedSessionKey: String?
        let control = OpenClawChatTalkControl(
            actionState: .remoteActive,
            isListening: true,
            isSpeaking: false,
            isGatewayConnected: true,
            statusText: "Listening",
            providerLabel: "Realtime",
            performAction: { performedSessionKey = $0 })

        #expect(control.actionState == .remoteActive)
        #expect(control.isListening)
        #expect(!control.isSpeaking)
        #expect(control.isGatewayConnected)
        #expect(control.statusText == "Listening")
        #expect(control.providerLabel == "Realtime")

        control.performAction("agent:main")
        #expect(performedSessionKey == "agent:main")
    }
}
