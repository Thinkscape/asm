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

/// A collection of a Bitwarden vault being edited; `enabled` = currently exposed.
struct CollectionChoiceItem: Identifiable, Hashable, Sendable {
    var id: String
    var name: String
    var enabled: Bool
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
    case pair(info: HostInfoItem, observedAddress: String, code: String, repair: RepairItem?)
    case get(GetDetail)
    case update(name: String, vaultID: String, vaultName: String, field: String, oldValue: String, newValue: String)
    case add(name: String, value: String, targets: [AddTargetItem])
}

/// The pairing machine looks like an already paired host.
struct RepairItem: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        /// The CLI proved it holds the old host's token: the same record is re-paired.
        case sameInstall
        /// Machine-id hint only: the operator may replace the old pairing.
        case sameMachine
    }

    var hostID: String
    var hostName: String
    var pairedAt: Date
    var kind: Kind
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
    /// The host's friendly name (pairing requests: the reported hostname).
    var hostLabel: String
    /// The requesting machine's reported hostname.
    var hostname: String
    var agent: String
    /// Address the request came from, as the manager saw it.
    var address: String
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
    /// Friendly name (the reported hostname unless renamed).
    var name: String
    var info: HostInfoItem
    var observedAddress: String
    var agents: [AgentSeenItem]
    var pairedAt: Date
    var lastSeen: Date?
    var activeLeases: Int
    /// Other active hosts that look like the same machine (machine-id hint).
    var machineHintMatches: Int

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
    /// Normalised CIDR ranges a pairing host's address must be in; empty = any address.
    var allowedNetworks: [String]

    var networksLine: String { allowedNetworks.isEmpty ? "any" : allowedNetworks.joined(separator: ", ") }
}

enum LeaseMode: String, Equatable, Sendable {
    case sentinel, raw
}

enum LeaseStatus: String, Equatable, Sendable {
    case active, expired, revoked
}

struct LeaseItem: Identifiable, Equatable, Sendable {
    var id: String
    /// The host's friendly name.
    var hostLabel: String
    /// The host's reported hostname.
    var hostname: String
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

/// Proxy health as the core reports it (`ProxyState`).
enum ProxyHealth: Equatable, Sendable {
    case running
    /// Just started, or restarting after a failure for under 5 s.
    case starting
    /// Not running for at least 5 s; `reason` is the most relevant cause.
    case down(reason: String, since: Date)
    /// Running, but its health check has failed for more than 10 s.
    case unhealthy(since: Date)
}

struct ProxyStatusItem: Equatable, Sendable {
    var running: Bool = false
    var pid: Int?
    var lastReload: Date?
    var healthy: Bool = false
    var health: ProxyHealth = .starting
    /// Failed starts since the proxy was last healthy.
    var consecutiveFailures: Int = 0
    var caExpiry: Date?
    var caPath: String = ""
    var caPEM: String = ""
    var error: String?
    var activeEntries: Int = 0
    var suspendedLeases: Int = 0

    /// Down, or unhealthy for over 10 s: agents cannot use their leases.
    var needsAttention: Bool {
        switch health {
        case .down, .unhealthy: true
        case .running, .starting: false
        }
    }

    /// When the current problem started (Down or Unhealthy).
    var problemSince: Date? {
        switch health {
        case let .down(_, since), let .unhealthy(since): since
        case .running, .starting: nil
        }
    }

    /// One-line headline of the problem; `nil` while fine.
    var problemTitle: String? {
        switch health {
        case .down: "Proxy is not running: agents can't use their leases"
        case .unhealthy: "Proxy is not responding: agents can't use their leases"
        case .running, .starting: nil
        }
    }

    /// The cause shown under the headline.
    var problemReason: String? {
        switch health {
        case let .down(reason, _): reason
        case .unhealthy: error ?? "Its health check has failed for more than 10 seconds."
        case .running, .starting: nil
        }
    }
}

/// What the macOS Application Firewall does to incoming connections (`FirewallState`).
enum FirewallStateItem: Equatable, Sendable {
    case allowed
    case blocked
    /// "Block all incoming connections" is on.
    case blockAll
    case firewallOff
    /// No rule yet: macOS asks the first time another machine connects.
    case unknown
}

/// Whether other machines can reach one listener (`ListenerReach`).
struct ListenerReachItem: Equatable, Sendable {
    /// Bound to a non-loopback address: meant for other machines.
    var intentRemote: Bool = false
    var state: FirewallStateItem = .unknown
    /// Meant for other machines, and the firewall blocks it.
    var blocked: Bool = false
    var bindAddress: String = ""
    /// The executable the firewall rule names.
    var executable: String = ""

    /// `Other machines (0.0.0.0)` or `Local only (127.0.0.1)`.
    var intentTitle: String {
        intentRemote ? "Other machines (\(bindAddress))" : "Local only (\(bindAddress))"
    }

    /// The Terminal command that lifts the block (shown for the operator; never run).
    var fixCommand: String? {
        guard blocked else { return nil }
        return state == .blockAll
            ? "sudo \(FirewallStatusItem.tool) --setblockall off"
            : "sudo \(FirewallStatusItem.tool) --unblockapp \"\(executable)\""
    }
}

/// macOS Firewall reach of the proxy (iron-proxy) and the manager API (this app).
struct FirewallStatusItem: Equatable, Sendable {
    static let tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    var proxy = ListenerReachItem()
    var api = ListenerReachItem()
    /// `nil` until the first check finished.
    var checkedAt: Date?
    var stealthMode: Bool = false

    /// A listener meant for other machines is blocked.
    var needsAttention: Bool { proxy.blocked || api.blocked }

    /// Banner headline; `nil` while nothing is blocked.
    var problemTitle: String? {
        switch (proxy.blocked, api.blocked) {
        case (true, false): "macOS Firewall blocks iron-proxy: other machines can't use their leases"
        case (false, true): "macOS Firewall blocks Agents Secrets Manager: other machines can't pair or request secrets"
        case (true, true): "macOS Firewall blocks iron-proxy and Agents Secrets Manager: other machines can't pair or use their leases"
        case (false, false): nil
        }
    }

    /// Short label for the menu bar icon and the sidebar badge.
    var problemLabel: String? {
        if proxy.blocked { return "Firewall blocks the proxy" }
        if api.blocked { return "Firewall blocks the manager API" }
        return nil
    }

    /// Commands that lift the blocks, proxy first, without duplicates.
    var fixCommands: [String] {
        var out: [String] = []
        for command in [proxy.fixCommand, api.fixCommand].compactMap({ $0 }) where !out.contains(command) {
            out.append(command)
        }
        return out
    }
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
    /// `replace`: revoke the matching old pairing (`same_machine`); `same_install` re-pairs
    /// the same record whatever it says.
    case approvePair(name: String, replace: Bool)
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

/// Categories of the activity log (core `ActivityEntry.category`).
enum ActivityCategory: String, CaseIterable, Identifiable, Sendable {
    case requests, leases, proxy, pairing, vaults

    var id: String { rawValue }

    var title: String {
        switch self {
        case .requests: "Requests"
        case .leases: "Leases"
        case .proxy: "Proxy"
        case .pairing: "Pairing"
        case .vaults: "Vaults"
        }
    }

    var symbol: String {
        switch self {
        case .requests: "tray.full"
        case .leases: "clock.badge.checkmark"
        case .proxy: "arrow.left.arrow.right"
        case .pairing: "link"
        case .vaults: "lock.rectangle.stack"
        }
    }
}

/// One activity log row. Never holds secret values.
struct ActivityItem: Identifiable, Equatable, Sendable {
    var id: Int64
    var at: Date
    var category: String
    var kind: String
    var hostID: String?
    /// The host's friendly name when the row was read; "" without a host.
    var hostLabel: String
    var secret: String?
    var summary: String
    /// JSON object text.
    var detail: String?
    /// `detail.lease_id`, when the row concerns a known lease.
    var leaseID: String?

    var knownCategory: ActivityCategory? { ActivityCategory(rawValue: category) }

    /// `detail` pretty-printed (sorted keys), or as stored when it is not JSON.
    var prettyDetail: String? {
        guard let detail else { return nil }
        guard let data = detail.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                  withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
              ),
              let text = String(data: pretty, encoding: .utf8)
        else { return detail }
        return text
    }
}

/// Filter and page of `listActivity`.
struct ActivityQueryItem: Equatable, Sendable {
    /// Category raw values; empty = all.
    var categories: [String] = []
    var hostID: String?
    var search: String = ""
    /// Rows older than this id; `nil` = newest page.
    var beforeID: Int64?
    var limit: UInt32 = 200
}

/// Asks the Settings window to show Leases searching for `search` and select `leaseID`
/// (Activity Log "Show lease"). `token` makes repeated requests distinct.
struct LeaseFocus: Equatable, Sendable {
    var leaseID: String
    var search: String
    var token = UUID()
}

/// Set by a click on a Recent entry of the menu bar panel; the Activity Log selects the
/// row (`rowID` nil: the entry is no longer in the log).
struct ActivityFocus: Equatable, Sendable {
    var rowID: Int64?
    var token = UUID()
}
