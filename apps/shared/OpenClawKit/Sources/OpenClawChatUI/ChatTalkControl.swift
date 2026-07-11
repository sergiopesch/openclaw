import SwiftUI

public struct OpenClawChatTalkControl {
    public enum ActionState: Equatable, Sendable {
        case idle
        case localActive
        case remoteActive
        case unavailable
    }

    public var actionState: ActionState
    public var isListening: Bool
    public var isSpeaking: Bool
    public var isGatewayConnected: Bool
    public var statusText: String
    public var providerLabel: String
    public var performAction: @MainActor (_ sessionKey: String) -> Void

    public init(
        actionState: ActionState,
        isListening: Bool,
        isSpeaking: Bool,
        isGatewayConnected: Bool,
        statusText: String,
        providerLabel: String,
        performAction: @escaping @MainActor (_ sessionKey: String) -> Void)
    {
        self.actionState = actionState
        self.isListening = isListening
        self.isSpeaking = isSpeaking
        self.isGatewayConnected = isGatewayConnected
        self.statusText = statusText
        self.providerLabel = providerLabel
        self.performAction = performAction
    }
}

extension OpenClawChatTalkControl.ActionState {
    struct Presentation: Equatable {
        let title: String
        let systemImage: String
        let accessibilityLabel: String
        let helpAction: String
        let isEnabled: Bool
        let isProminent: Bool
    }

    var presentation: Presentation {
        switch self {
        case .idle:
            Presentation(
                title: "Talk", systemImage: "waveform",
                accessibilityLabel: "Start realtime chat", helpAction: "Start realtime chat for",
                isEnabled: true, isProminent: false)
        case .localActive:
            Presentation(
                title: "Stop", systemImage: "stop.fill",
                accessibilityLabel: "Stop realtime chat", helpAction: "Stop realtime chat for",
                isEnabled: true, isProminent: true)
        case .remoteActive:
            Presentation(
                title: "Move Here", systemImage: "arrow.right.circle.fill",
                accessibilityLabel: "Move realtime chat to this device",
                helpAction: "Move realtime chat to this device for",
                isEnabled: true, isProminent: true)
        case .unavailable:
            Presentation(
                title: "Talk", systemImage: "waveform.slash",
                accessibilityLabel: "Realtime chat unavailable",
                helpAction: "Realtime chat is unavailable for",
                isEnabled: false, isProminent: false)
        }
    }
}
