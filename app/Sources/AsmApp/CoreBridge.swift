import AsmCore
import Foundation

/// Forwards core change notifications (called on manager threads) to the app model.
final class ObserverBridge: ManagerObserver, @unchecked Sendable {
    let onChange: @Sendable (String) -> Void

    init(onChange: @escaping @Sendable (String) -> Void) {
        self.onChange = onChange
    }

    func changed(topic: String) {
        onChange(topic)
    }
}

/// The only file that touches the generated UniFFI bindings: synchronous wrappers
/// around `Manager` that map its records to the app's value types. `AppModel` calls
/// these off the main thread. `Manager` is an `Arc` of a thread-safe Rust object.
final class CoreBridge: @unchecked Sendable {
    /// Observer topics, in initial-load order.
    static let topics = ["settings", "vaults", "generators", "gcloud_accounts", "hosts", "leases", "proxy", "firewall", "requests"]

    /// Lease duration choices, in display order (`id` 0 = unlimited).
    static let leaseDurations: [LeaseDuration] = AsmCore.leaseDurations().map {
        LeaseDuration(seconds: $0.secs, title: $0.label)
    }

    private static let gcloudPermissionMetadata = Dictionary(uniqueKeysWithValues: GcloudPermissionItem.allCases.map { permission in
        let details = AsmCore.gcloudPermissionDetails(permission: GcloudPermission(permission))
        return (permission, (claim: details.claim, role: details.role, scope: details.scope))
    })

    static func gcloudPermissionDetails(_ permission: GcloudPermissionItem) -> (claim: String, role: String, scope: String) {
        // The map is built from all cases of this closed Swift enum.
        gcloudPermissionMetadata[permission]!
    }

    private let manager: Manager
    private let observer: ObserverBridge

    private init(manager: Manager, observer: ObserverBridge) {
        self.manager = manager
        self.observer = observer
    }

    static func start(dataDir: String, binDir: String, onChange: @escaping @Sendable (String) -> Void) throws -> CoreBridge {
        #if DEBUG
        // The core then honours ASM_DEBUG_* environment overrides (e.g. a firewall fixture).
        enableDebugOverrides()
        #endif
        let observer = ObserverBridge(onChange: onChange)
        let manager = try mapped { try Manager.start(dataDir: dataDir, binDir: binDir, observer: observer) }
        return CoreBridge(manager: manager, observer: observer)
    }

    static func checkHostPattern(_ pattern: String) -> Result<HostPatternCheckItem, AppError> {
        do {
            let check = try mapped { try AsmCore.checkHostPattern(pattern: pattern) }
            return .success(HostPatternCheckItem(check))
        } catch let error as AppError {
            return .failure(error)
        } catch {
            return .failure(AppError(message: error.localizedDescription))
        }
    }

    static func hintSuggestions() -> [String] {
        AsmCore.hintSuggestions()
    }

    /// The Mac's own subnets, as pairing-code network suggestions.
    static func subnetSuggestions() -> [String] {
        AsmCore.subnetSuggestions()
    }

    /// One pairing-code network entry, normalised; the core's message when invalid.
    static func checkNetwork(_ entry: String) -> Result<String, AppError> {
        do {
            return .success(try mapped { try AsmCore.checkNetwork(entry: entry) })
        } catch let error as AppError {
            return .failure(error)
        } catch {
            return .failure(AppError(message: error.localizedDescription))
        }
    }

    // MARK: Requests

    func snapshot() throws -> (pending: [PendingItem], recent: [RecentItem]) {
        let snapshot = manager.snapshot()
        return (snapshot.pending.map(PendingItem.init), snapshot.recent.map(RecentItem.init))
    }

    func resolve(id: String, decision: DecisionItem) throws {
        try Self.mapped { try manager.resolveRequest(id: id, decision: Self.coreDecision(decision)) }
    }

    private static func coreDecision(_ decision: DecisionItem) -> Decision {
        switch decision {
        case let .deny(reason): .deny(reason: reason)
        case let .approvePair(name, replace): .approvePair(name: name, replace: replace)
        case let .approveGet(raw, durationSecs, hosts, generation):
            .approveGet(mode: raw ? .raw : .sentinel, durationSecs: durationSecs, hosts: hosts,
                        generation: generation.map(GenerationSelection.init))
        case let .approveWrite(vaultID, collectionID): .approveWrite(vaultId: vaultID, collectionId: collectionID)
        }
    }

    // MARK: Vaults

    func listVaults() throws -> [VaultItem] {
        manager.listVaults().map(VaultItem.init)
    }

    func saveVault(_ draft: VaultDraftItem) throws {
        _ = try Self.mapped { try manager.saveVault(draft: VaultDraft(draft)) }
    }

    func removeVault(_ id: String) throws {
        try Self.mapped { try manager.removeVault(id: id) }
    }

    func bitwardenConnect(_ draft: VaultDraftItem) throws -> [CollectionItem] {
        try Self.mapped { try manager.bitwardenConnect(draft: VaultDraft(draft)) }.map(CollectionItem.init)
    }

    /// Collections for the edit sheet: all of them when the vault is unlocked, else the exposed ones.
    func vaultCollections(_ id: String) throws -> [CollectionChoiceItem] {
        try Self.mapped { try manager.vaultCollections(vaultId: id) }.map(CollectionChoiceItem.init)
    }

    func syncVault(_ id: String) throws {
        try Self.mapped { try manager.syncVault(id: id) }
    }

    func unlockVault(_ id: String, masterPassword: String) throws {
        try Self.mapped { try manager.unlockVault(vaultId: id, masterPassword: masterPassword) }
    }

    // MARK: Generators

    func listGenerators() throws -> [GeneratorItem] {
        manager.listGenerators().map(GeneratorItem.init)
    }

    func saveGenerator(_ draft: GeneratorDraftItem) throws -> GeneratorItem {
        GeneratorItem(try Self.mapped { try manager.saveGenerator(draft: GeneratorDraft(draft)) })
    }

    func removeGenerator(_ id: String) throws {
        try Self.mapped { try manager.removeGenerator(id: id) }
    }

    func githubConnect(_ draft: GeneratorDraftItem) throws -> GithubInstallationItem {
        GithubInstallationItem(try Self.mapped { try manager.githubConnect(draft: GeneratorDraft(draft)) })
    }

    func githubListInstallations(_ draft: GeneratorDraftItem) throws -> [GithubInstallationAccountItem] {
        try Self.mapped { try manager.githubListInstallations(draft: GeneratorDraft(draft)) }.map {
            GithubInstallationAccountItem(installationID: $0.installationId, account: $0.account)
        }
    }

    func gcloudCheckSdk(path: String?) throws -> GcloudSdkItem {
        let sdk = try Self.mapped { try manager.gcloudCheckSdk(path: path) }
        return GcloudSdkItem(path: sdk.path, version: sdk.version)
    }

    func gcloudBeginLogin(sdkPath: String) throws -> String {
        try Self.mapped { try manager.gcloudBeginLogin(sdkPath: sdkPath) }
    }

    func gcloudFinishLogin(sessionID: String) throws -> GcloudIdentityItem {
        let identity = try Self.mapped { try manager.gcloudFinishLogin(sessionId: sessionID) }
        return GcloudIdentityItem(subject: identity.subject, email: identity.email)
    }

    func gcloudCancelLogin(sessionID: String) throws {
        try Self.mapped { try manager.gcloudCancelLogin(sessionId: sessionID) }
    }

    func gcloudApprovalProjects(
        requestID: String, generatorID: String, generatorRevision: UInt64
    ) throws -> [String] {
        try Self.mapped {
            try manager.gcloudApprovalProjects(
                requestId: requestID, generatorId: generatorID, generatorRevision: generatorRevision
            )
        }
    }

    func gcloudProfilePlan(
        requestID: String, decision: DecisionItem
    ) throws -> (GcloudProfilePlanItem, Date?) {
        let plan = try Self.mapped {
            try manager.gcloudProfilePlan(requestId: requestID, decision: Self.coreDecision(decision))
        }
        return (GcloudProfilePlanItem(plan), plan.expiresAt.map { Date(timeIntervalSince1970: Double($0)) })
    }

    func gcloudApproveProfile(requestID: String, planID: String, decision: DecisionItem) throws {
        try Self.mapped {
            try manager.gcloudApproveProfile(
                requestId: requestID, planId: planID, decision: Self.coreDecision(decision)
            )
        }
    }

    func gcloudCancelProfile(planID: String) throws {
        try Self.mapped { try manager.gcloudCancelProfile(planId: planID) }
    }

    func hasRecordedGcloudAccounts() throws -> Bool {
        try Self.mapped { try manager.hasRecordedGcloudAccounts() }
    }

    func listGcloudOwnedAccounts() throws -> [GcloudOwnedAccountItem] {
        try Self.mapped { try manager.listGcloudOwnedAccounts() }.map(GcloudOwnedAccountItem.init)
    }

    func deleteGcloudOwnedAccount(_ account: GcloudOwnedAccountItem) throws {
        guard account.deletable, let revision = account.generatorRevision, let uniqueID = account.accountUniqueID else {
            throw AppError(message: account.blockingReason ?? String(localized: "This account cannot be deleted."))
        }
        let target = GcloudOwnedAccountDelete(
            profileId: account.id, generatorId: account.generatorID, generatorRevision: revision,
            projectId: account.projectID, accountName: account.accountName, accountEmail: account.accountEmail,
            accountUniqueId: uniqueID, expectedLeaseIds: account.leases.map(\.id), confirmed: true
        )
        try Self.mapped { try manager.deleteGcloudOwnedAccount(target: target) }
    }

    // MARK: Hosts and pairing codes

    func listHosts() throws -> [HostItem] {
        manager.listHosts().map(HostItem.init)
    }

    func revokeHost(_ id: String) throws {
        try Self.mapped { try manager.revokeHost(hostId: id) }
    }

    func renameHost(_ id: String, name: String) throws {
        try Self.mapped { try manager.renameHost(hostId: id, name: name) }
    }

    /// Returns the `asm pair …` command holding the new code (shown once).
    func createPairingCode(label: String, expirySecs: UInt64?, maxUses: UInt32?, networks: [String]) throws -> String {
        try Self.mapped {
            try manager.createPairingCode(label: label, expirySecs: expirySecs, maxUses: maxUses, allowedNetworks: networks)
        }.command
    }

    func listPairingCodes() throws -> [PairingCodeItem] {
        manager.listPairingCodes().map(PairingCodeItem.init)
    }

    func revokePairingCode(_ id: String) throws {
        try Self.mapped { try manager.revokePairingCode(id: id) }
    }

    // MARK: Leases

    func listLeases() throws -> [LeaseItem] {
        manager.listLeases().map(LeaseItem.init)
    }

    func revokeLease(_ id: String) throws {
        try Self.mapped { try manager.revokeLease(leaseId: id) }
    }

    // MARK: Proxy and settings

    func proxySettings() throws -> ProxySettingsItem {
        ProxySettingsItem(manager.proxySettings())
    }

    func setProxySettings(_ settings: ProxySettingsItem) throws {
        let core = try ProxySettings(settings)
        try Self.mapped { try manager.setProxySettings(settings: core) }
    }

    func proxyStatus() throws -> ProxyStatusItem {
        ProxyStatusItem(manager.proxyStatus())
    }

    func restartProxy() throws {
        try Self.mapped { try manager.restartProxy() }
    }

    func firewallStatus() throws -> FirewallStatusItem {
        FirewallStatusItem(manager.firewallStatus())
    }

    /// Runs `socketfilterfw` now (blocking).
    func checkFirewall() throws -> FirewallStatusItem {
        FirewallStatusItem(manager.checkFirewall())
    }

    func proxyLogTail(_ lines: UInt32) throws -> [String] {
        manager.proxyLogTail(lines: lines)
    }

    // MARK: Activity log

    func listActivity(_ query: ActivityQueryItem) throws -> [ActivityItem] {
        manager.listActivity(query: ActivityQuery(
            categories: query.categories, hostId: query.hostID, search: query.search,
            beforeId: query.beforeID, limit: query.limit
        )).map(ActivityItem.init)
    }

    /// Activity row recording how a resolved request ended; nil when pruned.
    func activityRowForRequest(_ id: String) throws -> Int64? {
        manager.activityRowForRequest(requestId: id)
    }

    func generalSettings() throws -> GeneralSettingsItem {
        GeneralSettingsItem(manager.generalSettings())
    }

    func setGeneralSettings(_ settings: GeneralSettingsItem) throws {
        var core = manager.generalSettings()
        core.apiBindAddress = settings.apiBindAddress
        core.apiPort = try validPort(settings.apiPort, "API port")
        core.defaultLeaseSecs = settings.defaultLeaseSecs
        core.pendingLifetimeSecs = settings.pendingLifetimeSecs
        let bw = settings.bwPath.trimmingCharacters(in: .whitespaces)
        core.bwPath = bw.isEmpty ? nil : bw
        try Self.mapped { try manager.setGeneralSettings(settings: core) }
    }

    func onWake() throws {
        manager.onWake()
    }

    func shutdown() {
        manager.shutdown()
    }

    /// Rethrows core errors as `AppError` carrying the core's message and code.
    private static func mapped<T>(_ work: () throws -> T) throws -> T {
        do {
            return try work()
        } catch let ManagerError.Failed(code, message) {
            throw AppError(message: message, code: code)
        }
    }
}

private func validPort(_ value: Int, _ what: String) throws -> UInt16 {
    guard let port = UInt16(exactly: value), port > 0 else {
        throw AppError(message: "\(what) must be between 1 and 65535.")
    }
    return port
}

// MARK: - Record mapping

private extension HostPatternCheckItem {
    init(_ c: HostPatternCheck) {
        self.init(normalized: c.normalized, broad: c.broad)
    }
}

private extension HostInfoItem {
    init(_ h: HostInfo) {
        self.init(
            hostname: h.hostname, os: h.os, osVersion: h.osVersion, kernel: h.kernel, arch: h.arch,
            username: h.username, addresses: h.addresses, asmVersion: h.asmVersion, container: h.container
        )
    }
}

private extension CollectionItem {
    init(_ c: CollectionInfo) {
        self.init(id: c.id, name: c.name)
    }
}

private extension CollectionChoiceItem {
    init(_ c: CollectionChoice) {
        self.init(id: c.id, name: c.name, enabled: c.enabled)
    }
}

private extension VaultKind {
    init(_ k: AsmCore.VaultKind) {
        switch k {
        case .bitwarden: self = .bitwarden
        case .envFile: self = .envFile
        case .keychain: self = .keychain
        }
    }
}

private extension RequestKind {
    init(_ k: AsmCore.RequestKind) {
        switch k {
        case .pair: self = .pair
        case .get: self = .get
        case .update: self = .update
        case .add: self = .add
        }
    }
}

private extension RepairItem {
    /// `nil` for a kind this build does not know.
    init?(_ r: RepairInfo) {
        let kind: Kind
        switch r.kind {
        case "same_install": kind = .sameInstall
        case "same_machine": kind = .sameMachine
        default: return nil
        }
        self.init(hostID: r.hostId, hostName: r.hostName, pairedAt: r.pairedAt, kind: kind)
    }
}

private extension PendingItem {
    init(_ r: PendingRequest) {
        let detail: RequestDetail = switch r.detail {
        case let .pair(hostInfo, observedAddress, code, repair):
            .pair(info: HostInfoItem(hostInfo), observedAddress: observedAddress, code: code, repair: repair.flatMap(RepairItem.init))
        case let .get(name, vaultID, vaultName, _, fields, reason, rawRequested, requestedHosts,
                      initialHosts, suggestedHosts, defaultDurationSecs, isGenerated, generatorChoices,
                      requestedGeneration, sentinelRequired, hasSubstitutableFields, operatorSelectedGrant,
                      operatorSelectedGcloudProject):
            .get(GetDetail(
                name: name, vaultID: vaultID, vaultName: vaultName, fields: fields, reason: reason, rawRequested: rawRequested,
                requestedHosts: requestedHosts,
                initialHosts: initialHosts.map(HostPatternCheckItem.init),
                suggestedHosts: suggestedHosts.map(HostPatternCheckItem.init),
                defaultDurationSecs: defaultDurationSecs,
                isGenerated: isGenerated,
                generatorChoices: generatorChoices.map(GeneratorApprovalChoiceItem.init),
                requestedGeneration: requestedGeneration.map(GenerationRequestItem.init),
                sentinelRequired: sentinelRequired, hasSubstitutableFields: hasSubstitutableFields,
                operatorSelectedGrant: operatorSelectedGrant, operatorSelectedGcloudProject: operatorSelectedGcloudProject
            ))
        case let .update(name, vaultId, vaultName, field, oldValue, newValue):
            .update(name: name, vaultID: vaultId, vaultName: vaultName, field: field, oldValue: oldValue, newValue: newValue)
        case let .add(name, value, targets):
            .add(name: name, value: value, targets: targets.map { t in
                AddTargetItem(
                    vaultID: t.vaultId, vaultName: t.vaultName, kind: VaultKind(t.kind),
                    collections: t.collections.map(CollectionItem.init), personalAllowed: t.personalAllowed
                )
            })
        }
        self.init(
            id: r.id, kind: RequestKind(r.kind), createdAt: r.createdAt, expiresAt: r.expiresAt,
            hostLabel: r.hostLabel, hostname: r.hostInfo?.hostname ?? "", agent: r.agent, address: r.address,
            summary: r.summary, error: r.error, detail: detail
        )
    }
}

private extension RecentItem {
    init(_ r: RecentRequest) {
        let outcome: String = switch r.outcome {
        case .approved: "approved"
        case .denied: r.denyReason.map { $0.isEmpty ? "denied" : "denied: \($0)" } ?? "denied"
        case .expired: "expired"
        case .cancelled: "cancelled"
        }
        self.init(
            id: r.id, kind: RequestKind(r.kind), summary: r.summary, hostLabel: r.hostLabel,
            outcome: outcome, approved: r.outcome == .approved, resolvedAt: r.resolvedAt
        )
    }
}

private extension VaultState {
    init(_ status: VaultStatus, locked: VaultState = .locked) {
        self = switch status {
        case .ready: .ready
        case .locked: locked
        case let .error(message): .error(message)
        }
    }
}

private extension VaultItem {
    init(_ v: VaultInfo) {
        let config: VaultConfigItem = switch v.config {
        case let .bitwarden(serverUrl, email, clientId, collectionIds, exposePersonal, bwPath):
            .bitwarden(BitwardenConfig(
                serverURL: serverUrl, email: email, clientID: clientId, collectionIDs: collectionIds,
                exposePersonal: exposePersonal, bwPath: bwPath ?? ""
            ))
        case let .envFile(path): .envFile(path: path)
        case .keychain: .keychain
        }
        self.init(
            id: v.id, name: v.name, kind: VaultKind(v.kind), state: VaultState(v.status),
            secretCount: v.secretCount.map(Int.init), note: v.note, config: config
        )
    }
}

private extension VaultDraft {
    init(_ d: VaultDraftItem) {
        switch d {
        case let .bitwarden(id, name, c, clientSecret, masterPassword):
            let bw = c.bwPath.trimmingCharacters(in: .whitespaces)
            self.init(
                id: id, name: name,
                config: .bitwarden(
                    serverUrl: c.serverURL.trimmingCharacters(in: .whitespaces), email: c.email.trimmingCharacters(in: .whitespaces),
                    clientId: c.clientID.trimmingCharacters(in: .whitespaces), collectionIds: c.collectionIDs,
                    exposePersonal: c.exposePersonal, bwPath: bw.isEmpty ? nil : bw
                ),
                clientSecret: clientSecret, masterPassword: masterPassword
            )
        case let .envFile(id, name, path):
            self.init(id: id, name: name, config: .envFile(path: path), clientSecret: "", masterPassword: "")
        case let .keychain(id, name):
            self.init(id: id, name: name, config: .keychain, clientSecret: "", masterPassword: "")
        }
    }
}

private extension HostItem {
    init(_ h: HostRecord) {
        self.init(
            id: h.hostId, name: h.name, info: HostInfoItem(h.info), observedAddress: h.observedAddress,
            agents: h.agents.map { AgentSeenItem(agent: $0.agent, lastSeen: $0.lastSeen) },
            pairedAt: h.pairedAt, lastSeen: h.lastSeen, activeLeases: Int(h.activeLeases),
            machineHintMatches: Int(h.machineHintMatches)
        )
    }
}

private extension PairingCodeItem {
    init(_ c: PairingCodeInfo) {
        let status: String = switch c.status {
        case .active: "active"
        case .expired: "expired"
        case .usedUp: "used up"
        }
        self.init(
            id: c.id, label: c.label, createdAt: c.createdAt, expiresAt: c.expiresAt,
            uses: Int(c.uses), maxUses: c.maxUses.map(Int.init), status: status,
            allowedNetworks: c.allowedNetworks
        )
    }
}

private extension LeaseStatus {
    init(_ status: AsmCore.LeaseStatus) {
        self = switch status {
        case .active: .active
        case .expired: .expired
        case .revoked: .revoked
        }
    }
}

private extension LeaseItem {
    init(_ l: LeaseInfo) {
        self.init(
            id: l.leaseId, hostLabel: l.hostLabel, hostname: l.hostname, source: l.vaultName, name: l.name,
            mode: l.mode == .raw ? .raw : .sentinel, hosts: l.hosts, createdAt: l.createdAt,
            expiresAt: l.expiresAt, status: LeaseStatus(l.status), suspended: l.suspended, rawDelivered: l.rawDelivered,
            sourceKind: l.sourceKind == .generator ? .generator : .vault, sourceID: l.vaultId, fields: l.fields,
            generation: l.generation.map(GenerationSelectionItem.init), generatorName: l.generatorName,
            credentialExpiresAt: l.credentialExpiresAt, credentialVersion: l.credentialVersion,
            suspensionReason: l.suspensionReason
        )
    }
}

private extension ActivityItem {
    init(_ e: ActivityEntry) {
        var leaseID: String?
        if let data = e.detail?.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            leaseID = object["lease_id"] as? String
        }
        self.init(
            id: e.id, at: e.at, category: e.category, kind: e.kind, hostID: e.hostId,
            hostLabel: e.hostLabel, secret: e.secret, summary: e.summary, detail: e.detail, leaseID: leaseID
        )
    }
}

private extension ProxySettingsItem {
    init(_ s: ProxySettings) {
        self.init(
            bindAddress: s.bindAddress, port: Int(s.port), hints: s.hints, httpPort: Int(s.httpPort),
            httpsPort: Int(s.httpsPort), managementPort: Int(s.managementPort), metricsPort: Int(s.metricsPort),
            maxRequestBodyBytes: Int(s.maxRequestBodyBytes), allowPlainHTTP: s.allowPlainHttp
        )
    }
}

private extension ProxySettings {
    init(_ s: ProxySettingsItem) throws {
        guard let maxBody = UInt64(exactly: s.maxRequestBodyBytes), maxBody > 0 else {
            throw AppError(message: "Max request body must be a positive number of bytes.")
        }
        self.init(
            bindAddress: s.bindAddress.trimmingCharacters(in: .whitespaces), port: try validPort(s.port, "Proxy port"),
            hints: s.hints, httpPort: try validPort(s.httpPort, "Internal HTTP port"),
            httpsPort: try validPort(s.httpsPort, "Internal HTTPS port"),
            managementPort: try validPort(s.managementPort, "Management port"),
            metricsPort: try validPort(s.metricsPort, "Metrics port"),
            maxRequestBodyBytes: maxBody, allowPlainHttp: s.allowPlainHTTP
        )
    }
}

private extension ListenerReachItem {
    init(_ r: ListenerReach) {
        let state: FirewallStateItem = switch r.state {
        case .allowed: .allowed
        case .blocked: .blocked
        case .blockAll: .blockAll
        case .firewallOff: .firewallOff
        case .unknown: .unknown
        }
        self.init(
            intentRemote: r.intentRemote, state: state, blocked: r.blocked,
            bindAddress: r.bindAddress, executable: r.executable
        )
    }
}

private extension FirewallStatusItem {
    init(_ s: FirewallStatus) {
        self.init(
            proxy: ListenerReachItem(s.proxy), api: ListenerReachItem(s.api),
            checkedAt: s.checkedAt, stealthMode: s.stealthMode
        )
    }
}

private extension ProxyStatusItem {
    init(_ s: ProxyStatus) {
        let health: ProxyHealth = switch s.state {
        case .running: .running
        case .starting: .starting
        case let .down(reason, since): .down(reason: reason, since: since)
        case let .unhealthy(since): .unhealthy(since: since)
        }
        self.init(
            running: s.running, pid: s.pid.map(Int.init), lastReload: s.lastReload, healthy: s.healthy,
            health: health, consecutiveFailures: Int(s.consecutiveFailures),
            caExpiry: s.caExpiry, caPath: s.caPath, caPEM: s.caPem ?? "", error: s.error,
            activeEntries: Int(s.activeEntries), suspendedLeases: Int(s.suspendedLeases)
        )
    }
}

private extension GeneralSettingsItem {
    init(_ s: GeneralSettings) {
        self.init(
            apiBindAddress: s.apiBindAddress, apiPort: Int(s.apiPort), defaultLeaseSecs: s.defaultLeaseSecs,
            pendingLifetimeSecs: s.pendingLifetimeSecs, bwPath: s.bwPath ?? "", version: s.version,
            certSHA256: s.certSha256, listeningOn: s.listeningOn
        )
    }
}

// MARK: - Generator record mapping

private extension GithubPermissionLevel {
    init(_ level: AsmCore.GithubPermission) {
        switch level {
        case .read: self = .read
        case .write: self = .write
        case .admin: self = .admin
        }
    }
}

private extension AsmCore.GithubPermission {
    init(_ level: GithubPermissionLevel) {
        switch level {
        case .read: self = .read
        case .write: self = .write
        case .admin: self = .admin
        }
    }
}

private extension GithubPermissionItem {
    init(_ permission: GithubPermissionEntry) {
        self.init(name: permission.name, level: GithubPermissionLevel(permission.level))
    }
}

private extension GithubPermissionEntry {
    init(_ permission: GithubPermissionItem) {
        self.init(name: permission.name, level: AsmCore.GithubPermission(permission.level))
    }
}

private func repositoryDisplayOrder(_ lhs: String, _ rhs: String) -> Bool {
    lhs.localizedStandardCompare(rhs) == .orderedAscending
}

private func displayRepositories(_ repositories: [GithubRepository]) -> [GithubRepositoryItem] {
    var items = repositories.map { GithubRepositoryItem(id: $0.id, fullName: $0.fullName) }
    items.sort { repositoryDisplayOrder($0.fullName, $1.fullName) }
    return items
}

private extension GithubRepository {
    init(_ repository: GithubRepositoryItem) {
        self.init(id: repository.id, fullName: repository.fullName)
    }
}

private extension GithubGrantItem {
    init(_ grant: GithubGrant) {
        self.init(installationID: grant.installationId, repositories: displayRepositories(grant.repositories),
                  permissions: grant.permissions.map(GithubPermissionItem.init))
    }
}

private extension GithubGrant {
    init(_ grant: GithubGrantItem) {
        self.init(installationId: grant.installationID, repositories: grant.repositories.map(GithubRepository.init),
                  permissions: grant.permissions.map(GithubPermissionEntry.init))
    }
}

private extension GcloudGrantItem {
    init(_ grant: GcloudGrant) {
        self.init(serviceAccountUniqueID: grant.serviceAccountUniqueId, serviceAccountEmail: grant.serviceAccountEmail,
                  scopes: grant.scopes, projectID: grant.projectId)
    }
}

private extension GcloudGrant {
    init(_ grant: GcloudGrantItem) {
        self.init(serviceAccountUniqueId: grant.serviceAccountUniqueID, serviceAccountEmail: grant.serviceAccountEmail,
                  scopes: grant.scopes, projectId: grant.projectID)
    }
}

private extension GcloudPermissionItem {
    init(_ permission: GcloudPermission) {
        self = switch permission {
        case .storageRead: .storageRead
        case .storageCreate: .storageCreate
        case .computeRead: .computeRead
        case .runRead: .runRead
        case .logsRead: .logsRead
        case .bigqueryMetadataRead: .bigqueryMetadataRead
        }
    }
}

private extension GcloudPermission {
    init(_ permission: GcloudPermissionItem) {
        self = switch permission {
        case .storageRead: .storageRead
        case .storageCreate: .storageCreate
        case .computeRead: .computeRead
        case .runRead: .runRead
        case .logsRead: .logsRead
        case .bigqueryMetadataRead: .bigqueryMetadataRead
        }
    }
}

private extension GcloudAccessRequestItem {
    init(_ access: GcloudAccessRequest) {
        self.init(projectID: access.projectId, permissions: access.permissions.map(GcloudPermissionItem.init))
    }
}

private extension GcloudAccessRequest {
    init(_ access: GcloudAccessRequestItem) {
        self.init(projectId: access.projectID, permissions: access.permissions.map(GcloudPermission.init))
    }
}

private extension GcloudAccessGrantItem {
    init(_ grant: GcloudAccessGrant) {
        self = switch grant {
        case .connection: .connection
        case let .requested(access):
            .requested(access: GcloudAccessRequestItem(access))
        case let .issued(access, uniqueID, email):
            .issued(access: GcloudAccessRequestItem(access), serviceAccountUniqueID: uniqueID, serviceAccountEmail: email)
        }
    }
}

private extension GcloudAccessGrant {
    init(_ grant: GcloudAccessGrantItem) {
        self = switch grant {
        case .connection: .connection
        case let .requested(access):
            .requested(access: GcloudAccessRequest(access))
        case let .issued(access, uniqueID, email):
            .issued(access: GcloudAccessRequest(access), serviceAccountUniqueId: uniqueID, serviceAccountEmail: email)
        }
    }
}

private extension GenerationGrantItem {
    init(_ grant: GenerationGrant) {
        switch grant {
        case let .githubApp(scope): self = .githubApp(GithubGrantItem(scope))
        case let .gcloud(scope): self = .gcloud(GcloudGrantItem(scope))
        case let .gcloudAccess(grant): self = .gcloudAccess(GcloudAccessGrantItem(grant))
        }
    }
}

private extension GenerationGrant {
    init(_ grant: GenerationGrantItem) {
        switch grant {
        case let .githubApp(scope): self = .githubApp(scope: GithubGrant(scope))
        case let .gcloud(scope): self = .gcloud(scope: GcloudGrant(scope))
        case let .gcloudAccess(grant): self = .gcloudAccess(grant: GcloudAccessGrant(grant))
        }
    }
}

private extension GenerationRequestItem {
    init(_ request: GenerationRequest) {
        switch request {
        case let .githubApp(scope):
            self = .githubApp(GithubScopeRequestItem(
                repositories: scope.repositories?.sorted(by: repositoryDisplayOrder), permissions: scope.permissions?.map(GithubPermissionItem.init)
            ))
        case let .gcloud(scope):
            self = .gcloud(GcloudScopeRequestItem(scopes: scope.scopes))
        case let .gcloudAccess(access):
            self = .gcloudAccess(GcloudAccessRequestItem(access))
        }
    }
}

private extension GenerationChoiceItem {
    init(_ choice: GenerationChoice) {
        self.init(id: choice.generatorId, name: choice.name, revision: choice.revision,
                  ceiling: GenerationGrantItem(choice.ceiling), available: choice.available,
                  unavailableReason: choice.unavailableReason)
    }
}

private extension GeneratorApprovalChoiceItem {
    init(_ choice: GeneratorApprovalChoice) {
        self.init(choice: GenerationChoiceItem(choice.choice),
                  scopeIssues: choice.scopeIssues,
                  scopeCatalog: choice.scopeCatalog.map(GcloudScopeOptionItem.init),
                  defaultProjectID: choice.defaultProjectId,
                  gcloudReady: choice.gcloudReady.map(GcloudAccessGrantItem.init))
    }
}

private extension GenerationSelectionItem {
    init(_ selection: GenerationSelection) {
        self.init(generatorID: selection.generatorId, generatorRevision: selection.generatorRevision,
                  grant: GenerationGrantItem(selection.grant))
    }
}

private extension GenerationSelection {
    init(_ selection: GenerationSelectionItem) {
        self.init(generatorId: selection.generatorID, generatorRevision: selection.generatorRevision,
                  grant: GenerationGrant(selection.grant))
    }
}

private extension GcloudServiceItem {
    init(_ service: GcloudService) {
        self.init(name: service.name, title: service.title, enabled: service.enabled)
    }
}

private extension GcloudService {
    init(_ service: GcloudServiceItem) {
        self.init(name: service.name, title: service.title, enabled: service.enabled)
    }
}

private extension GcloudScopeOptionItem {
    init(_ option: GcloudScopeOption) {
        self.init(uri: option.uri, description: option.description, services: option.services.map(GcloudServiceItem.init))
    }
}

private extension GcloudScopeOption {
    init(_ option: GcloudScopeOptionItem) {
        self.init(uri: option.uri, description: option.description, services: option.services.map(GcloudService.init))
    }
}

private extension GcloudProfilePlanItem {
    init(_ plan: GcloudProfilePlan) {
        self.init(planID: plan.planId, ready: plan.ready, projectID: plan.projectId,
                  serviceAccountName: plan.serviceAccountName, serviceAccountEmail: plan.serviceAccountEmail,
                  serviceAccountUniqueID: plan.serviceAccountUniqueId, serviceAccountRole: plan.serviceAccountRole,
                  projectRoles: plan.projectRoles,
                  scopes: plan.scopes, adminPrincipal: plan.adminPrincipal, messages: plan.messages)
    }
}

private extension GcloudOwnedAccountStateItem {
    init(_ state: GcloudOwnedAccountState) {
        self = switch state {
        case .creating: .creating
        case .created: .created
        case .projectBound: .projectBound
        case .tokenCreatorBound: .tokenCreatorBound
        case .ready: .ready
        case .deletionPending: .deletionPending
        case .deleted: .deleted
        }
    }
}

private extension GcloudOwnedAccountItem {
    init(_ account: GcloudOwnedAccount) {
        self.init(
            id: account.id, generatorID: account.generatorId, generatorName: account.generatorName,
            generatorRevision: account.generatorRevision,
            generatorStatus: account.generatorStatus.map { VaultState($0, locked: .error(gcloudGeneratorLockedMessage)) },
            projectID: account.projectId, accountName: account.accountName, accountEmail: account.accountEmail,
            accountUniqueID: account.accountUniqueId, operatorEmail: account.operatorEmail,
            permissions: account.permissions.map(GcloudPermissionItem.init), state: GcloudOwnedAccountStateItem(account.state),
            superseded: account.superseded, deletable: account.deletable, blockingReason: account.blockingReason,
            leases: account.leases.map {
                GcloudOwnedAccountLeaseItem(
                    id: $0.id, hostLabel: $0.hostLabel, agentLabel: $0.agentLabel,
                    status: LeaseStatus($0.status), deadline: $0.deadline
                )
            }
        )
    }
}

private extension GeneratorConfigItem {
    init(_ config: GeneratorConfig) {
        switch config {
        case let .githubApp(config):
            self = .githubApp(GithubAppConfigItem(
                clientID: config.clientId, installations: config.installations.map(GithubGrantItem.init)
            ))
        case let .gcloud(config):
            self = .gcloud(GcloudConfigItem(
                sdkPath: config.sdkPath, accountSubject: config.accountSubject, accountEmail: config.accountEmail,
                projectID: config.projectId, projectNumber: config.projectNumber, ceiling: GcloudGrantItem(config.ceiling),
                scopeCatalog: config.scopeCatalog.map(GcloudScopeOptionItem.init)
            ))
        case let .gcloudConnection(config):
            self = .gcloudConnection(GcloudConnectionConfigItem(
                sdkPath: config.sdkPath, accountSubject: config.accountSubject, accountEmail: config.accountEmail
            ))
        }
    }
}

private extension GeneratorConfig {
    init(_ config: GeneratorConfigItem) {
        switch config {
        case let .githubApp(config):
            self = .githubApp(config: GithubAppConfig(
                clientId: config.clientID, installations: config.installations.map(GithubGrant.init)
            ))
        case let .gcloud(config):
            self = .gcloud(config: GcloudConfig(
                sdkPath: config.sdkPath, accountSubject: config.accountSubject, accountEmail: config.accountEmail,
                projectId: config.projectID, projectNumber: config.projectNumber, ceiling: GcloudGrant(config.ceiling),
                scopeCatalog: config.scopeCatalog.map(GcloudScopeOption.init)
            ))
        case let .gcloudConnection(config):
            self = .gcloudConnection(config: GcloudConnectionConfig(
                sdkPath: config.sdkPath, accountSubject: config.accountSubject, accountEmail: config.accountEmail
            ))
        }
    }
}

private let gcloudGeneratorLockedMessage = String(localized: "Google authorization unavailable; sign in again.")

private extension GeneratorItem {
    init(_ generator: GeneratorInfo) {
        let locked: VaultState = switch generator.config {
        case .githubApp: .error("Signing key unavailable")
        case .gcloud, .gcloudConnection: .error(gcloudGeneratorLockedMessage)
        }
        self.init(id: generator.id, name: generator.name, config: GeneratorConfigItem(generator.config),
                  revision: generator.revision, state: VaultState(generator.status, locked: locked), warning: generator.warning,
                  requireExactScopeMatch: generator.requireExactScopeMatch)
    }
}

private extension GeneratorCredentials {
    init(_ credentials: GeneratorCredentialsItem) {
        switch credentials {
        case .keep: self = .keep
        case let .githubPrivateKey(pem): self = .githubPrivateKey(pem: pem)
        case let .gcloudSession(sessionID): self = .gcloudSession(sessionId: sessionID)
        }
    }
}

private extension GeneratorDraft {
    init(_ draft: GeneratorDraftItem) {
        self.init(id: draft.id, name: draft.name, config: GeneratorConfig(draft.config),
                  credentials: GeneratorCredentials(draft.credentials), requireExactScopeMatch: draft.requireExactScopeMatch)
    }
}

private extension GithubInstallationItem {
    init(_ installation: GithubInstallation) {
        self.init(installationID: installation.installationId, accountLogin: installation.accountLogin,
                  repositories: displayRepositories(installation.repositories),
                  permissions: installation.permissions.map(GithubPermissionItem.init), warning: installation.warning)
    }
}
