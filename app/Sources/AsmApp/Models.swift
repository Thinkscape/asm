import Foundation

// App-side value types the views render. `CoreBridge.swift` maps the generated
// UniFFI records onto these, so the views stay independent of binding details.

enum RequestKind: String, Equatable, Sendable {
    case pair, get, update, add

    var title: String {
        switch self {
        case .pair: "Pair"
        case .get: "Get"
        case .update: "Update"
        case .add: "Add"
        }
    }

    var symbol: String {
        switch self {
        case .pair: "link"
        case .get: "key"
        case .update: "pencil"
        case .add: "plus.circle"
        }
    }
}

struct HostInfoItem: Equatable, Sendable {
    var hostname: String
    var os: String
    var osVersion: String
    var kernel: String
    var arch: String
    var username: String
    var addresses: [String]
    var asmVersion: String
    var container: Bool
}

struct CollectionItem: Identifiable, Hashable, Sendable {
    var id: String
    var name: String
}

struct AddTargetItem: Identifiable, Equatable, Sendable {
    var id: String { vaultID }
    var vaultID: String
    var vaultName: String
    var kind: VaultKind
    var collections: [CollectionItem]
    var personalAllowed: Bool
}

enum RequestDetail: Equatable, Sendable {
    case pair(info: HostInfoItem, observedAddress: String, code: String)
    case get(GetDetail)
    case update(name: String, vaultID: String, vaultName: String, field: String, oldValue: String, newValue: String)
    case add(name: String, value: String, targets: [AddTargetItem])
}

struct GetDetail: Equatable, Sendable {
    var name: String
    var vaultName: String
    var fields: [String]
    var reason: String
    var rawRequested: Bool
    var requestedHosts: [String]
    /// Pre-filled (never `*` or broad patterns).
    var initialHosts: [HostPatternCheckItem]
    /// Offered but not pre-filled.
    var suggestedHosts: [HostPatternCheckItem]
    var defaultDurationSecs: UInt64?
}

struct PendingItem: Identifiable, Equatable, Sendable {
    var id: String
    var kind: RequestKind
    var createdAt: Date
    var expiresAt: Date
    var hostLabel: String
    var agent: String
    var summary: String
    var error: String?
    var detail: RequestDetail
}

struct RecentItem: Identifiable, Equatable, Sendable {
    var id: String
    var kind: RequestKind
    var summary: String
    var hostLabel: String
    /// `approved`, `denied`, `denied: <reason>`, `expired` or `cancelled`.
    var outcome: String
    var approved: Bool
    var resolvedAt: Date
}

enum VaultKind: String, Equatable, Sendable {
    case bitwarden, envFile, keychain

    var title: String {
        switch self {
        case .bitwarden: "Bitwarden"
        case .envFile: ".env file"
        case .keychain: "macOS Keychain"
        }
    }
}

enum VaultState: Equatable, Sendable {
    case ready, locked, error(String)

    var title: String {
        switch self {
        case .ready: "Ready"
        case .locked: "Locked"
        case let .error(message): "Error: \(message)"
        }
    }
}

struct BitwardenConfig: Equatable, Sendable {
    var serverURL: String = ""
    var email: String = ""
    var clientID: String = ""
    var collectionIDs: [String] = []
    var exposePersonal: Bool = false
    var bwPath: String = ""
}

enum VaultConfigItem: Equatable, Sendable {
    case bitwarden(BitwardenConfig)
    case envFile(path: String)
    case keychain
}

struct VaultItem: Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var kind: VaultKind
    var state: VaultState
    /// `nil` when the vault cannot be listed.
    var secretCount: Int?
    var note: String?
    var config: VaultConfigItem
}

/// What the vault sheets submit. Empty secret strings keep the stored value.
enum VaultDraftItem: Sendable {
    case bitwarden(id: String?, name: String, config: BitwardenConfig, clientSecret: String, masterPassword: String)
    case envFile(id: String?, name: String, path: String)
    case keychain(id: String?, name: String)
}

struct AgentSeenItem: Equatable, Sendable {
    var agent: String
    var lastSeen: Date
}

struct HostItem: Identifiable, Equatable, Sendable {
    var id: String
    var info: HostInfoItem
    var observedAddress: String
    var agents: [AgentSeenItem]
    var pairedAt: Date
    var lastSeen: Date?
    var activeLeases: Int

    var osLine: String { "\(info.os) \(info.osVersion) (\(info.arch))" }
    var addressLine: String {
        let others = info.addresses.filter { $0 != observedAddress }
        return ([observedAddress] + others).filter { !$0.isEmpty }.joined(separator: ", ")
    }
    var agentLine: String { agents.map(\.agent).filter { !$0.isEmpty }.joined(separator: ", ") }
}

struct PairingCodeItem: Identifiable, Equatable, Sendable {
    var id: String
    var label: String
    var createdAt: Date
    var expiresAt: Date?
    var uses: Int
    var maxUses: Int?
    /// `active`, `expired` or `used up`.
    var status: String
}

enum LeaseMode: String, Equatable, Sendable {
    case sentinel, raw
}

enum LeaseStatus: String, Equatable, Sendable {
    case active, expired, revoked
}

struct LeaseItem: Identifiable, Equatable, Sendable {
    var id: String
    var hostLabel: String
    var source: String
    var name: String
    var mode: LeaseMode
    var hosts: [String]
    var createdAt: Date
    var expiresAt: Date?
    var status: LeaseStatus
    var suspended: Bool
    var rawDelivered: Bool

    // Sort keys for `Table` columns.
    var hostsLine: String {
        if mode == .raw { return "none (raw value)" }
        return hosts == ["*"] ? "any host" : hosts.joined(separator: ", ")
    }
    var modeLine: String {
        if mode == .sentinel { return "sentinel" }
        return rawDelivered ? "raw value delivered" : "raw"
    }
    var statusLine: String {
        if status == .active && suspended { return "suspended (vault unavailable)" }
        return status.rawValue
    }
    /// Unlimited leases sort after every dated one in ascending order.
    var expiresSortKey: Date { expiresAt ?? .distantFuture }
}

struct ProxySettingsItem: Equatable, Sendable {
    var bindAddress: String = "0.0.0.0"
    var port: Int = 7412
    var hints: [String] = []
    var httpPort: Int = 7413
    var httpsPort: Int = 7414
    var managementPort: Int = 7415
    var metricsPort: Int = 7416
    var maxRequestBodyBytes: Int = 10_485_760
    var allowPlainHTTP: Bool = false
}

struct ProxyStatusItem: Equatable, Sendable {
    var running: Bool = false
    var pid: Int?
    var lastReload: Date?
    var healthy: Bool = false
    var caExpiry: Date?
    var caPath: String = ""
    var caPEM: String = ""
    var error: String?
    var activeEntries: Int = 0
    var suspendedLeases: Int = 0
}

struct GeneralSettingsItem: Equatable, Sendable {
    var apiBindAddress: String = "0.0.0.0"
    var apiPort: Int = 7411
    var defaultLeaseSecs: UInt64? = 3600
    var pendingLifetimeSecs: UInt64 = 600
    var bwPath: String = ""
    var version: String = ""
    /// Read-only: SHA-256 of the manager API certificate (hex).
    var certSHA256: String = ""
    /// Read-only: address the API listener is bound to now.
    var listeningOn: String = ""
}

/// The approval popup's choice for one request.
enum DecisionItem: Sendable {
    case deny(reason: String)
    case approvePair
    case approveGet(raw: Bool, durationSecs: UInt64?, hosts: [String])
    case approveWrite(vaultID: String, collectionID: String?)
}

struct HostPatternCheckItem: Equatable, Sendable {
    var normalized: String
    var broad: Bool
}

/// Lease durations offered in the popup and in Settings; the list comes from the
/// core (`CoreBridge.leaseDurations`).
struct LeaseDuration: Identifiable, Hashable, Sendable {
    var seconds: UInt64?
    var title: String
    var id: UInt64 { seconds ?? 0 }
}
