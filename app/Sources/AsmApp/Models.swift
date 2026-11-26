import Foundation

// App-side value types the views render. `CoreBridge.swift` maps the generated
// UniFFI records onto these, so the views stay independent of binding details.

enum RequestKind: String, Equatable, Sendable {
    case pair, get, update, add, login, ssh

    var title: String {
        switch self {
        case .pair: "Pair"
        case .get: "Get"
        case .update: "Update"
        case .add: "Add"
        case .login: "Sign in"
        case .ssh: "SSH access"
        }
    }

    var symbol: String {
        switch self {
        case .pair: "link"
        case .get: "key"
        case .update: "pencil"
        case .add: "plus.circle"
        case .login: "person.badge.key"
        case .ssh: "terminal"
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

/// `asm add`: a new secret the operator saves to one of the offered destinations.
struct AddDetail: Equatable, Sendable {
    var name: String
    var value: String
    var targets: [AddTargetItem]
    /// The agent's suggested vault name (`asm add --vault`); the manager does not check it.
    var suggestedVault: String?
    /// The agent's suggested Bitwarden collection name; only set with `suggestedVault`.
    var suggestedCollection: String?
    /// Operator-only labels ("<vault>: collection X") of items with this name that are not
    /// exposed to agents.
    var hiddenMatches: [String]
    /// Vaults whose unexposed items could not be checked, as "<vault>: <message>".
    var hiddenCheckErrors: [String]
}

enum RequestDetail: Equatable, Sendable {
    case pair(info: HostInfoItem, observedAddress: String, code: String, repair: RepairItem?)
    case get(GetDetail)
    case update(name: String, vaultID: String, vaultName: String, field: String, oldValue: String, newValue: String)
    case add(AddDetail)
    case login(LoginDetail)
    case ssh(SshRequestItem)
    case sshExtend(SshExtendRequestItem)
}

/// The requester's account and site are hints, not the selected vault identity or an authorization.
struct LoginDetail: Hashable, Sendable {
    var url: String
    var site: String?
    var account: String?
    /// For a broker request, the primary origin is first, followed by optional extra origins.
    var fillOrigins: [String]
    var reason: String
    var broker: Bool
}

struct LoginChoiceItem: Identifiable, Equatable, Sendable {
    struct ID: Hashable, Sendable {
        var vaultID: String
        var key: String
    }

    var id: ID { ID(vaultID: vaultID, key: key) }
    var vaultID: String
    var key: String
    var title: String
    var vaultName: String
    var username: String?
    var savedHosts: [String]
    var hasTotp: Bool

    /// Match the core's bytewise equality rather than Swift String's canonical equivalence.
    static func == (lhs: Self, rhs: Self) -> Bool {
        let sameUsername = switch (lhs.username, rhs.username) {
        case (nil, nil): true
        case let (left?, right?): left.utf8.elementsEqual(right.utf8)
        default: false
        }
        return lhs.vaultID == rhs.vaultID && lhs.key.utf8.elementsEqual(rhs.key.utf8)
            && lhs.title.utf8.elementsEqual(rhs.title.utf8) && lhs.vaultName.utf8.elementsEqual(rhs.vaultName.utf8)
            && sameUsername && lhs.savedHosts == rhs.savedHosts && lhs.hasTotp == rhs.hasTotp
    }
}

struct LoginChoicesItem: Equatable, Sendable {
    var items: [LoginChoiceItem]
    var unavailableVaults: [String]
}

/// An approved `asm login` whose sign-in browser is open.
struct BrokerSessionItem: Identifiable, Equatable, Sendable {
    var id: String { requestID }
    var requestID: String
    var url: String
    var account: String?
    var hostLabel: String
    var startedAt: Date
    var status: String
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
    var vaultID: String?
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
    var isGenerated: Bool = false
    var generatorChoices: [GeneratorApprovalChoiceItem] = []
    var requestedGeneration: GenerationRequestItem?
    var sentinelRequired: Bool = false
    var hasSubstitutableFields: Bool = true
    /// The paired client negotiated accepting an explicitly operator-selected generated grant.
    var operatorSelectedGrant: Bool = false
    /// The paired client accepts a managed Google grant for a project other than the one it requested.
    var operatorSelectedGcloudProject: Bool = false
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


enum SourceKindItem: Equatable, Sendable {
    case vault, generator, ssh
}

// MARK: - SSH

/// SSH access; access as another user carries its name.
enum SshAccessItem: Hashable, Sendable {
    case privileged, restricted
    case user(String)

    var title: String {
        switch self {
        case .privileged: String(localized: "privileged")
        case .restricted: String(localized: "restricted (asm-ops)")
        case let .user(name): String(localized: "as \(name)")
        }
    }
}

/// A user agents may log in as on a target.
struct SshTargetUserItem: Hashable, Sendable {
    var name: String
    /// How the user can become root (`in group sudo`); nil when asm found no way.
    var admin: String?
}

/// One account of a host, as asm listed it while choosing a target's users.
struct SshHostUserItem: Identifiable, Equatable, Sendable {
    var name: String
    var uid: UInt32
    /// A daemon account (outside the host's UID_MIN..UID_MAX).
    var system: Bool
    /// Its shell can run a login session; asm runs /bin/sh otherwise.
    var loginShell: Bool
    /// How it can become root; nil when asm found no way.
    var admin: String?

    var id: String { name }
}

/// One target of a pending SSH request, as configured now.
struct SshApprovalTargetItem: Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    /// Address agents use.
    var hostname: String
    var port: UInt16
    var privilegedLogin: String
    var allowPrivileged: Bool
    var logUnits: [String]
    var restartUnits: [String]
    var reloadUnits: [String]
    var readFiles: [String]
    var users: [SshTargetUserItem]
    /// Enrolled at the requested revision with the current CA.
    var ready: Bool
    var issue: String?
    var hostKeyFingerprints: [String]
    /// The longest lease this target allows (0 when it was removed).
    var maxDurationSecs: UInt64

    /// Every restricted grant the target allows: logs, restart, reload, read, in that order.
    var grants: [String] {
        logUnits.map { "logs:\($0)" } + restartUnits.map { "restart:\($0)" }
            + reloadUnits.map { "reload:\($0)" } + readFiles.map { "read:\($0)" }
    }
}

struct SshRequestItem: Equatable, Sendable {
    var reason: String
    var access: SshAccessItem
    /// `logs:<unit>`, `restart:<unit>`, `reload:<unit>`, `read:<path>` (restricted access only).
    var grants: [String]
    var targets: [SshApprovalTargetItem]
    var defaultDurationSecs: UInt64
    var maxDurationSecs: UInt64
}

/// The operator's decision for one approved target of an SSH request.
struct SshTargetDecisionItem: Equatable, Sendable {
    var targetID: String
    var access: SshAccessItem
    /// The operations of restricted access.
    var grants: [String]
}

/// One target of a lease an extension request names, with the access the lease has there.
struct SshExtendTargetItem: Identifiable, Equatable, Sendable {
    var target: SshApprovalTargetItem
    var access: SshAccessItem
    var grants: [String]

    var id: String { target.id }
}

/// An agent asks to extend one of its active SSH leases. Access, grants and targets are the
/// lease's and can't be edited.
struct SshExtendRequestItem: Equatable, Sendable {
    var leaseID: String
    var reason: String
    var targets: [SshExtendTargetItem]
    var expiresAt: Date
    /// Set when the lease can no longer be extended.
    var issue: String?
    var defaultDurationSecs: UInt64
    var maxDurationSecs: UInt64
}

enum SshCleanupStateItem: Equatable, Sendable {
    case pending, retrying, done, failed
}

struct SshLeaseTargetItem: Equatable, Sendable {
    var name: String
    var login: String
    var access: SshAccessItem
    var grants: [String]
    /// `nil` while the lease is active.
    var cleanup: SshCleanupStateItem?
    var cleanupDetail: String
    /// Watched files that changed on the host during the lease (at most 20), reported when
    /// it ended there.
    var changes: [String]
    var changesTotal: UInt32
}

struct SshLeaseDetailItem: Equatable, Sendable {
    var targets: [SshLeaseTargetItem]
}

struct SshHostKeyItem: Hashable, Sendable {
    /// `<type> <b64>`.
    var line: String
    /// `SHA256:…`.
    var fingerprint: String
}

struct SshHostKeyLookupItem: Equatable, Sendable {
    var hostname: String
    var port: UInt16
    /// Empty when the operator's known_hosts doesn't know the destination.
    var keys: [SshHostKeyItem]
    /// The ProxyJump hops ssh uses to reach the destination.
    var proxyJump: String?
    /// The operator's ssh config reaches the destination through a ProxyCommand.
    var proxyCommand: Bool
}

/// A host key check: before a target is saved (with a login), or a review (without).
enum SshHostCheckItem: Equatable, Sendable {
    case verified
    /// The host proved none of the pinned keys; it offers these instead (unverified).
    case keyMismatch(presented: [SshHostKeyItem])
    /// The host wasn't reached, so nothing was checked.
    case unreachable(String)
}

enum SshTargetStateItem: Equatable, Sendable {
    case notEnrolled, enrolling, enrolled, needsReenroll, failed, removing

    var title: String {
        switch self {
        case .notEnrolled: String(localized: "Not enrolled")
        case .enrolling: String(localized: "Enrolling…")
        case .enrolled: String(localized: "Enrolled")
        case .needsReenroll: String(localized: "Enroll again (settings changed)")
        case .failed: String(localized: "Failed")
        case .removing: String(localized: "Removing from host…")
        }
    }
}

struct SshTargetItem: Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var destination: String
    var agentHostname: String
    var agentPort: UInt16
    var privilegedLogin: String
    var hostKeys: [SshHostKeyItem]
    var allowPrivileged: Bool
    var logUnits: [String]
    var restartUnits: [String]
    var reloadUnits: [String]
    var readFiles: [String]
    var users: [SshTargetUserItem]
    var maxDurationSecs: UInt64
    var revision: UInt64
    var state: SshTargetStateItem
    var error: String?
    /// Enrolled with older host scripts than this asm ships.
    var scriptsOutdated: Bool
    var activeLeases: UInt32
    /// The last run on the target failed its host key check.
    var hostKeyChanged: Bool

    /// The state as Settings shows it.
    var stateTitle: String {
        state == .needsReenroll && scriptsOutdated
            ? String(localized: "Enroll again (asm updated its host scripts)") : state.title
    }
}

/// `id` nil adds a target; an edit passes its id and the revision it was read at.
struct SshTargetDraftItem: Sendable {
    var id: String?
    var expectedRevision: UInt64?
    var name: String
    var destination: String
    var agentHostname: String
    var agentPort: UInt16
    var privilegedLogin: String
    var hostKeys: [String]
    var allowPrivileged: Bool
    var logUnits: [String]
    var restartUnits: [String]
    var reloadUnits: [String]
    var readFiles: [String]
    var users: [SshTargetUserItem]
    var maxDurationSecs: UInt64
}

/// Duration choices of the SSH approval popup and the target sheet's "Max lease".
enum SshDurations {
    static let approval: [LeaseDuration] = [
        LeaseDuration(seconds: 900, title: "15 min"),
        LeaseDuration(seconds: 3600, title: "1 h"),
        LeaseDuration(seconds: 14_400, title: "4 h"),
        LeaseDuration(seconds: 28_800, title: "8 h"),
        LeaseDuration(seconds: 86_400, title: "24 h"),
    ]
    static let maxLease: [LeaseDuration] = approval + [LeaseDuration(seconds: 604_800, title: "7 days")]

    /// `choices`, plus `extra` (titled from its length) when it is not one of them.
    static func including(_ extra: UInt64, in choices: [LeaseDuration]) -> [LeaseDuration] {
        guard !choices.contains(where: { $0.seconds == extra }) else { return choices }
        let title = Duration.seconds(Int64(extra)).formatted(.units(allowed: [.days, .hours, .minutes], width: .abbreviated))
        return (choices + [LeaseDuration(seconds: extra, title: title)]).sorted { $0.id < $1.id }
    }
}

enum GithubPermissionLevel: String, CaseIterable, Comparable, Hashable, Sendable {
    case read, write, admin

    private var rank: Int {
        switch self {
        case .read: 1
        case .write: 2
        case .admin: 3
        }
    }

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

struct GithubPermissionItem: Identifiable, Hashable, Sendable {
    var id: String { name }
    var name: String
    var level: GithubPermissionLevel

    var scopeLabel: String {
        if name.hasPrefix("organization_") || name == "members" {
            return "\(name) (organization-wide)"
        }
        if name.hasPrefix("enterprise_") { return "\(name) (enterprise-wide)" }
        if Self.accountPermissions.contains(name) {
            return "\(name) (account-wide)"
        }
        if Self.repositoryPermissions.contains(name) { return name }
        return "\(name) (not assumed repository-scoped)"
    }

    var allowedLevels: [GithubPermissionLevel] {
        GithubPermissionLevel.allCases.filter(permits)
    }

    func permits(_ candidate: GithubPermissionLevel) -> Bool {
        guard candidate <= level else { return false }
        return switch name {
        case "metadata": candidate == .read
        case "workflows", "profile": candidate == .write
        default: true
        }
    }

    private static let accountPermissions: Set<String> = [
        "blocking", "codespaces_user_secrets", "emails", "followers", "gists", "gpg_keys",
        "git_signing_ssh_public_keys", "interaction_limits", "keys", "plan", "profile",
        "repository_invitations", "starring", "user_events", "watching",
    ]

    private static let repositoryPermissions: Set<String> = [
        "actions", "administration", "artifact_metadata", "attestations", "checks", "codespaces",
        "codespaces_lifecycle_admin", "codespaces_metadata", "codespaces_secrets", "commit_statuses",
        "contents", "custom_properties", "dependabot_secrets", "deployments", "discussions",
        "environments", "issues", "merge_queues", "metadata", "packages", "pages", "projects",
        "pull_requests", "repository_advisories", "repository_custom_properties", "repository_hooks",
        "repository_projects", "secret_scanning_alerts", "secrets", "security_events", "single_file",
        "statuses", "vulnerability_alerts", "workflows",
    ]
}

struct GithubRepositoryItem: Identifiable, Hashable, Sendable {
    var id: UInt64
    var fullName: String
}

/// Resolve requested names only when a single immutable repository ID matches.
struct GithubRequestedRepositories {
    struct Unavailable: Identifiable {
        var id: String { name }
        let name: String
        let ambiguous: Bool
    }

    private(set) var matchedIDs: Set<UInt64> = []
    private(set) var ambiguousIDs: Set<UInt64> = []
    private(set) var unavailable: [Unavailable] = []

    init(_ requested: [String], in repositories: [GithubRepositoryItem]) {
        guard !requested.isEmpty else { return }
        let names = Set(requested.lazy.map { $0.lowercased() })
        var matches: [String: UInt64] = [:]
        var ambiguousNames: Set<String> = []
        for repository in repositories {
            let name = repository.fullName.lowercased()
            guard names.contains(name) else { continue }
            if let previous = matches.updateValue(repository.id, forKey: name) {
                ambiguousNames.insert(name)
                ambiguousIDs.insert(previous)
                ambiguousIDs.insert(repository.id)
            }
        }
        for requestedName in requested {
            let name = requestedName.lowercased()
            if ambiguousNames.contains(name) {
                unavailable.append(Unavailable(name: requestedName, ambiguous: true))
            } else if let id = matches[name] {
                matchedIDs.insert(id)
            } else {
                unavailable.append(Unavailable(name: requestedName, ambiguous: false))
            }
        }
    }
}

struct GithubScopeRequestItem: Equatable, Sendable {
    var repositories: [String]?
    var permissions: [GithubPermissionItem]?

    var effectivePermissions: [GithubPermissionItem] {
        let requested = permissions ?? []
        if requested.contains(where: { $0.name == "metadata" }) { return requested }
        return requested + [.init(name: "metadata", level: .read)]
    }
}

struct GcloudScopeRequestItem: Equatable, Sendable {
    var scopes: [String]?
}

enum GcloudPermissionItem: CaseIterable, Hashable, Sendable {
    case storageRead
    case storageCreate
    case computeRead
    case runRead
    case logsRead
    case bigqueryMetadataRead

    var claim: String { CoreBridge.gcloudPermissionDetails(self).claim }
    var role: String { CoreBridge.gcloudPermissionDetails(self).role }
    var scope: String { CoreBridge.gcloudPermissionDetails(self).scope }

    var approvalTitle: LocalizedStringResource {
        switch self {
        case .storageRead: "Read Cloud Storage objects"
        case .storageCreate: "Create Cloud Storage objects"
        case .computeRead: "Read Compute Engine resources"
        case .runRead: "Read Cloud Run resources"
        case .logsRead: "Read Cloud Logging entries"
        case .bigqueryMetadataRead: "Read BigQuery metadata"
        }
    }
}

struct GcloudAccessRequestItem: Equatable, Sendable {
    let projectID: String
    var permissions: [GcloudPermissionItem]

    /// Use the reviewed project and retain protocol enum order when editing permissions.
    func selecting(projectID: String, permissions selection: Set<GcloudPermissionItem>) -> Self {
        Self(projectID: projectID, permissions: GcloudPermissionItem.allCases.filter(selection.contains))
    }
}

enum GenerationRequestItem: Equatable, Sendable {
    case githubApp(GithubScopeRequestItem)
    case gcloud(GcloudScopeRequestItem)
    case gcloudAccess(GcloudAccessRequestItem)
}

struct GithubGrantItem: Identifiable, Equatable, Sendable {
    var id: UInt64 { installationID }
    var installationID: UInt64
    var repositories: [GithubRepositoryItem]
    var permissions: [GithubPermissionItem]

    // Persisted ceilings carry canonical GitHub repository names, not the login
    // from discovery. Only describe an owner when those names agree.
    var repositoryOwner: String? {
        guard let first = repositories.first?.fullName.prefix(while: { $0 != "/" }),
              !first.isEmpty else { return nil }
        let owner = first.lowercased()
        guard repositories.allSatisfy({ $0.fullName.prefix(while: { $0 != "/" }).lowercased() == owner }) else {
            return nil
        }
        return String(first)
    }

    func exactlyMatches(_ request: GithubScopeRequestItem) -> Bool {
        guard let requested = request.repositories, !requested.isEmpty else { return false }
        let match = GithubRequestedRepositories(requested, in: repositories)
        guard match.unavailable.isEmpty, match.matchedIDs.count == repositories.count else { return false }
        return Set(request.effectivePermissions) == Set(permissions)
    }
}

struct GcloudGrantItem: Equatable, Sendable {
    var serviceAccountUniqueID: String
    var serviceAccountEmail: String
    var scopes: [String]
    var projectID: String? = nil
}

enum GcloudAccessGrantItem: Equatable, Sendable {
    case connection
    case requested(access: GcloudAccessRequestItem)
    case issued(access: GcloudAccessRequestItem, serviceAccountUniqueID: String, serviceAccountEmail: String)
}

enum GenerationGrantItem: Equatable, Sendable {
    case githubApp(GithubGrantItem)
    case gcloud(GcloudGrantItem)
    case gcloudAccess(GcloudAccessGrantItem)
}

struct GenerationChoiceItem: Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var revision: UInt64
    var ceiling: GenerationGrantItem
    var available: Bool
    var unavailableReason: String?
}

struct GeneratorApprovalChoiceItem: Identifiable, Equatable, Sendable {
    struct ID: Hashable, Sendable {
        var generatorID: String
        var installationID: UInt64?
    }

    var id: ID {
        let installationID: UInt64? = switch choice.ceiling {
        case let .githubApp(grant): grant.installationID
        case .gcloud, .gcloudAccess: nil
        }
        return ID(generatorID: choice.id, installationID: installationID)
    }
    var choice: GenerationChoiceItem
    var scopeIssues: [String]
    var scopeCatalog: [GcloudScopeOptionItem] = []
    var defaultProjectID: String? = nil
    var gcloudReady: GcloudAccessGrantItem? = nil
}

struct GenerationSelectionItem: Equatable, Sendable {
    var generatorID: String
    var generatorRevision: UInt64
    var grant: GenerationGrantItem
}

struct GithubAppConfigItem: Equatable, Sendable {
    var clientID: String
    var installations: [GithubGrantItem]
}

struct GcloudServiceItem: Identifiable, Hashable, Sendable {
    var id: String { name }
    var name: String
    var title: String
    var enabled: Bool
}

struct GcloudScopeOptionItem: Identifiable, Hashable, Sendable {
    var id: String { uri }
    var uri: String
    var description: String
    var services: [GcloudServiceItem]
}

struct GcloudConfigItem: Equatable, Sendable {
    var sdkPath: String
    var accountSubject: String
    var accountEmail: String
    var projectID: String
    var projectNumber: String
    var ceiling: GcloudGrantItem
    var scopeCatalog: [GcloudScopeOptionItem]
}

struct GcloudConnectionConfigItem: Equatable, Sendable {
    var sdkPath: String
    var accountSubject: String
    var accountEmail: String
}

enum GeneratorConfigItem: Equatable, Sendable {
    case githubApp(GithubAppConfigItem)
    case gcloud(GcloudConfigItem)
    case gcloudConnection(GcloudConnectionConfigItem)

    var providerName: String {
        switch self {
        case .githubApp: "GitHub App"
        case .gcloud: "Google Cloud (legacy)"
        case .gcloudConnection: "Google Cloud"
        }
    }

    var outputName: String {
        switch self {
        case .githubApp: "GH_TOKEN"
        case .gcloud, .gcloudConnection: "CLOUDSDK_AUTH_ACCESS_TOKEN"
        }
    }
}

struct GeneratorItem: Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var config: GeneratorConfigItem
    var revision: UInt64
    var state: VaultState
    var warning: String?
    var requireExactScopeMatch = false
}

enum GeneratorCredentialsItem: Sendable {
    case keep
    case githubPrivateKey(pem: String)
    case gcloudSession(sessionID: String)
}

struct GeneratorDraftItem: Sendable {
    var id: String?
    var name: String
    var config: GeneratorConfigItem
    var credentials: GeneratorCredentialsItem
    var requireExactScopeMatch = false
}

struct GithubInstallationItem: Equatable, Sendable {
    var installationID: UInt64
    var accountLogin: String
    var repositories: [GithubRepositoryItem]
    var permissions: [GithubPermissionItem]
    var warning: String?
}

struct GithubInstallationAccountItem: Identifiable, Equatable, Sendable {
    var id: UInt64 { installationID }
    var installationID: UInt64
    var account: String
}

struct GcloudSdkItem: Equatable, Sendable {
    var path: String
    var version: String
}

struct GcloudIdentityItem: Equatable, Sendable {
    var subject: String
    var email: String
}

struct GcloudProfilePlanItem: Equatable, Sendable {
    var planID: String?
    var ready: Bool
    var projectID: String
    var serviceAccountName: String
    var serviceAccountEmail: String
    var serviceAccountUniqueID: String?
    var serviceAccountRole: String
    var projectRoles: [String]
    var scopes: [String]
    var adminPrincipal: String
    var messages: [String]
}

enum GcloudOwnedAccountStateItem: Equatable, Sendable {
    case creating, created, projectBound, tokenCreatorBound, ready, deletionPending, deleted

    var label: String {
        switch self {
        case .creating: String(localized: "Creation unverified")
        case .created: String(localized: "Created")
        case .projectBound: String(localized: "Project access granted")
        case .tokenCreatorBound: String(localized: "Impersonation granted")
        case .ready: String(localized: "Ready")
        case .deletionPending: String(localized: "Deletion pending")
        case .deleted: String(localized: "Deleted")
        }
    }
}

struct GcloudOwnedAccountLeaseItem: Identifiable, Equatable, Sendable {
    let id: String
    let hostLabel: String
    let agentLabel: String
    let status: LeaseStatus
    let deadline: Date?
}

struct GcloudOwnedAccountItem: Identifiable, Equatable, Sendable {
    let id: Int64
    let generatorID: String
    let generatorName: String?
    let generatorRevision: UInt64?
    let generatorStatus: VaultState?
    let projectID: String
    let accountName: String
    let accountEmail: String
    let accountUniqueID: String?
    let operatorEmail: String
    let permissions: [GcloudPermissionItem]
    let state: GcloudOwnedAccountStateItem
    let superseded: Bool
    let deletable: Bool
    let blockingReason: String?
    let leases: [GcloudOwnedAccountLeaseItem]
}

/// Repository IDs, not editable display names, are the authority in a selected scope.
struct GithubClaimsSelection: Equatable {
    var repositoryIDs: Set<UInt64> = []
    var permissions: [String: GithubPermissionLevel] = ["metadata": .read]

    init() {}

    init(ceiling: GithubGrantItem) {
        repositoryIDs = Set(ceiling.repositories.map(\.id))
        permissions = Dictionary(uniqueKeysWithValues: ceiling.permissions.map { ($0.name, $0.level) })
    }

    static func requested(_ request: GithubScopeRequestItem?, within ceiling: GithubGrantItem) -> Self {
        var selection = Self()
        guard let request else { return selection }
        selection.repositoryIDs = GithubRequestedRepositories(request.repositories ?? [], in: ceiling.repositories).matchedIDs
        let levels = Dictionary((request.permissions ?? []).map { ($0.name, $0.level) }, uniquingKeysWith: { first, _ in first })
        for permission in ceiling.permissions where permission.name != "metadata" {
            if let level = levels[permission.name], permission.permits(level) {
                selection.permissions[permission.name] = level
            }
        }
        return selection
    }

    subscript(repository id: UInt64) -> Bool {
        get { repositoryIDs.contains(id) }
        set {
            if newValue { repositoryIDs.insert(id) } else { repositoryIDs.remove(id) }
        }
    }

    func grant(within ceiling: GithubGrantItem) -> GithubGrantItem {
        GithubGrantItem(
            installationID: ceiling.installationID,
            repositories: ceiling.repositories.filter { repositoryIDs.contains($0.id) },
            permissions: ceiling.permissions.compactMap { permission in
                guard let level = permissions[permission.name], permission.permits(level) else { return nil }
                return GithubPermissionItem(name: permission.name, level: level)
            }
        )
    }
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
    /// Agents see which exposed collections hold each item, and an approved add reports
    /// the collection chosen.
    var shareCollectionNames: Bool = false
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

/// Visible items (what agents can list) sharing one name, within a vault or across vaults.
struct NameConflictGroupItem: Identifiable, Equatable, Sendable {
    var id: String { name }
    var name: String
    var items: [NameConflictEntryItem]
}

struct NameConflictEntryItem: Identifiable, Equatable, Sendable {
    var id: String { "\(vaultID)\u{1}\(key)" }
    /// The shared item name.
    var name: String
    var vaultID: String
    var vaultName: String
    /// Provider key (Bitwarden item id).
    var key: String
    /// What agents must type for it now, e.g. "DB_PASS~1a2b3c4d" or "work/DB_PASS".
    var agentName: String
    /// "collection Infra, Shared" / "personal vault"; `nil` outside Bitwarden.
    var location: String?
    /// Only Bitwarden items can be renamed from the app.
    var renamable: Bool
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
    var sourceKind: SourceKindItem = .vault
    var sourceID: String = ""
    var fields: [String] = []
    var generation: GenerationSelectionItem?
    var generatorName: String?
    var credentialExpiresAt: Date?
    var credentialVersion: UInt64?
    var suspensionReason: String?
    /// Set for SSH leases only.
    var ssh: SshLeaseDetailItem?

    // Sort keys for `Table` columns.
    var hostsLine: String {
        if ssh != nil { return "—" }
        if mode == .raw { return "none (raw value)" }
        return hosts == ["*"] ? "any host" : hosts.joined(separator: ", ")
    }
    var modeLine: String {
        if ssh != nil { return "SSH certificate" }
        if mode == .sentinel { return "sentinel" }
        return rawDelivered ? "raw value delivered" : "raw"
    }
    var statusLine: String {
        if status == .active && suspended {
            return "suspended (\(suspensionReason ?? (sourceKind == .generator ? "credential unavailable" : "vault unavailable")))"
        }
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
    var requireAuth: Bool = false
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
    case approveGet(raw: Bool, durationSecs: UInt64?, hosts: [String], generation: GenerationSelectionItem?)
    case approveWrite(vaultID: String, collectionID: String?)
    /// `fillOrigins` is empty for a single-use grant.
    case approveLogin(selection: LoginChoiceItem, durationSecs: UInt64?, fillOrigins: [String])
    /// One decision per approved target; a requested target left out is denied.
    case approveSsh(targets: [SshTargetDecisionItem], durationSecs: UInt64)
    case approveSshExtend(durationSecs: UInt64)
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
    case requests, leases, proxy, pairing, vaults, generators, ssh

    var id: String { rawValue }

    var title: String {
        switch self {
        case .requests: "Requests"
        case .leases: "Leases"
        case .proxy: "Proxy"
        case .pairing: "Pairing"
        case .vaults: "Vaults"
        case .generators: "Generators"
        case .ssh: "SSH"
        }
    }

    var symbol: String {
        switch self {
        case .requests: "tray.full"
        case .leases: "clock.badge.checkmark"
        case .proxy: "arrow.left.arrow.right"
        case .pairing: "link"
        case .vaults: "lock.rectangle.stack"
        case .generators: "key.horizontal"
        case .ssh: "terminal"
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
