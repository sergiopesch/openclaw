import Observation
import OpenClawProtocol

@MainActor
@Observable
final class InteractionSessionStore {
    enum Availability: Equatable {
        case disconnected
        case unsupported
        case syncing
        case current
        case stale
    }

    struct Runtime: Equatable {
        enum State: Equatable {
            case active
            case replaced
            case closed
        }

        let interactionSessionID: String
        let sessionKey: String
        let epoch: Int
        let runtimeID: String
        let runtimeKind: InteractionRuntimeKind
        let state: State
    }

    private(set) var availability: Availability = .disconnected
    private var runtimesBySessionKey: [String: Runtime] = [:]
    private var canonicalKeysByRequestedKey: [String: String] = [:]
    private var currentSessionKeys: Set<String> = []
    private struct PendingSnapshot {
        let generation: UInt64
        var bufferedEvents: [Runtime] = []
    }

    private var pendingSnapshotsByRequestedKey: [String: PendingSnapshot] = [:]
    private var failedSnapshotRequestedKeys: Set<String> = []
    private var snapshotGeneration: UInt64 = 0

    func runtime(for sessionKey: String) -> Runtime? {
        let requestedKey = Self.normalizedKey(sessionKey)
        let canonicalKey = self.canonicalKeysByRequestedKey[requestedKey] ?? requestedKey
        return self.runtimesBySessionKey[canonicalKey]
    }

    func isCurrent(for sessionKey: String) -> Bool {
        let requestedKey = Self.normalizedKey(sessionKey)
        let canonicalKey = self.canonicalKeysByRequestedKey[requestedKey] ?? requestedKey
        return self.currentSessionKeys.contains(requestedKey)
            || self.currentSessionKeys.contains(canonicalKey)
    }

    func representsSameSession(_ lhs: String, _ rhs: String) -> Bool {
        self.canonicalKey(for: lhs) == self.canonicalKey(for: rhs)
    }

    func markUnsupported() {
        self.clearRuntimeState()
        self.availability = .unsupported
    }

    func markDisconnected() {
        self.clearRuntimeState()
        self.availability = .disconnected
    }

    func markStale() {
        self.runtimesBySessionKey.removeAll()
        self.currentSessionKeys.removeAll()
        self.pendingSnapshotsByRequestedKey.removeAll()
        self.failedSnapshotRequestedKeys.removeAll()
        self.availability = .stale
    }

    func beginSnapshot(for sessionKey: String) -> UInt64 {
        self.snapshotGeneration &+= 1
        let requestedKey = Self.normalizedKey(sessionKey)
        self.failedSnapshotRequestedKeys.remove(requestedKey)
        self.currentSessionKeys.remove(requestedKey)
        if let canonicalKey = self.canonicalKeysByRequestedKey[requestedKey] {
            self.currentSessionKeys.remove(canonicalKey)
        }
        self.pendingSnapshotsByRequestedKey[requestedKey] = PendingSnapshot(
            generation: self.snapshotGeneration)
        self.availability = .syncing
        return self.snapshotGeneration
    }

    func recordEvent(_ projection: InteractionSessionProjection) {
        let runtime = Self.runtime(from: projection)
        self.apply(runtime)
        let requestedKeys = Array(self.pendingSnapshotsByRequestedKey.keys)
        for requestedKey in requestedKeys {
            self.pendingSnapshotsByRequestedKey[requestedKey]?.bufferedEvents.append(runtime)
        }
    }

    @discardableResult
    func completeSnapshot(
        _ projection: InteractionSessionActiveProjection?,
        for sessionKey: String,
        canonicalSessionKey: String,
        generation: UInt64) -> Bool
    {
        let requestedKey = Self.normalizedKey(sessionKey)
        let canonicalKey = Self.normalizedKey(canonicalSessionKey)
        guard let pendingSnapshot = self.pendingSnapshotsByRequestedKey[requestedKey],
              pendingSnapshot.generation == generation,
              !canonicalKey.isEmpty
        else { return false }

        self.canonicalKeysByRequestedKey[requestedKey] = canonicalKey
        self.currentSessionKeys.insert(requestedKey)
        self.currentSessionKeys.insert(canonicalKey)
        if let projection {
            let runtime = Self.runtime(from: projection)
            self.apply(runtime)
        } else {
            self.runtimesBySessionKey.removeValue(forKey: canonicalKey)
        }

        self.pendingSnapshotsByRequestedKey.removeValue(forKey: requestedKey)
        self.failedSnapshotRequestedKeys.remove(requestedKey)
        for event in pendingSnapshot.bufferedEvents {
            self.apply(event)
        }
        self.updateAvailabilityAfterSnapshotWork()
        return true
    }

    func failSnapshot(for sessionKey: String, generation: UInt64) {
        let requestedKey = Self.normalizedKey(sessionKey)
        guard self.pendingSnapshotsByRequestedKey[requestedKey]?.generation == generation
        else { return }
        self.pendingSnapshotsByRequestedKey.removeValue(forKey: requestedKey)
        self.failedSnapshotRequestedKeys.insert(requestedKey)
        self.updateAvailabilityAfterSnapshotWork()
    }

    private func apply(_ incoming: Runtime) {
        let current = self.runtimesBySessionKey[incoming.sessionKey]
        switch incoming.state {
        case .active:
            if let current,
               current.interactionSessionID == incoming.interactionSessionID,
               current.epoch > incoming.epoch
            {
                return
            }
            self.runtimesBySessionKey[incoming.sessionKey] = incoming
        case .replaced, .closed:
            guard let current,
                  current.state == .active,
                  current.interactionSessionID == incoming.interactionSessionID,
                  current.epoch == incoming.epoch,
                  current.runtimeID == incoming.runtimeID
            else { return }
            self.runtimesBySessionKey[incoming.sessionKey] = incoming
        }
    }

    private func clearRuntimeState() {
        self.runtimesBySessionKey.removeAll()
        self.canonicalKeysByRequestedKey.removeAll()
        self.currentSessionKeys.removeAll()
        self.pendingSnapshotsByRequestedKey.removeAll()
        self.failedSnapshotRequestedKeys.removeAll()
    }

    private func updateAvailabilityAfterSnapshotWork() {
        if !self.pendingSnapshotsByRequestedKey.isEmpty {
            self.availability = .syncing
        } else if !self.failedSnapshotRequestedKeys.isEmpty {
            self.availability = .stale
        } else {
            self.availability = .current
        }
    }

    private static func runtime(from projection: InteractionSessionProjection) -> Runtime {
        switch projection {
        case let .active(value):
            Runtime(
                interactionSessionID: value.interactionsessionid,
                sessionKey: value.sessionkey,
                epoch: value.epoch,
                runtimeID: value.runtimeid,
                runtimeKind: value.runtimekind,
                state: .active)
        case let .replaced(value):
            Runtime(
                interactionSessionID: value.interactionsessionid,
                sessionKey: value.sessionkey,
                epoch: value.epoch,
                runtimeID: value.runtimeid,
                runtimeKind: value.runtimekind,
                state: .replaced)
        case let .closed(value):
            Runtime(
                interactionSessionID: value.interactionsessionid,
                sessionKey: value.sessionkey,
                epoch: value.epoch,
                runtimeID: value.runtimeid,
                runtimeKind: value.runtimekind,
                state: .closed)
        }
    }

    private static func runtime(from projection: InteractionSessionActiveProjection) -> Runtime {
        Runtime(
            interactionSessionID: projection.interactionsessionid,
            sessionKey: projection.sessionkey,
            epoch: projection.epoch,
            runtimeID: projection.runtimeid,
            runtimeKind: projection.runtimekind,
            state: .active)
    }

    private static func normalizedKey(_ sessionKey: String) -> String {
        sessionKey.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func canonicalKey(for sessionKey: String) -> String {
        let requestedKey = Self.normalizedKey(sessionKey)
        return self.canonicalKeysByRequestedKey[requestedKey] ?? requestedKey
    }
}
