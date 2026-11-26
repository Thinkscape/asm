import AppKit
import Foundation
import Observation

struct AppError: LocalizedError {
    var message: String
    /// Core error code (`invalid`, `exists`, …) when the error came from the core.
    var code: String?
    var errorDescription: String? { message }
}

/// All state the menu bar panel, the approval panel and the Settings window render.
/// Every call into the Rust core runs off the main thread (`call`); results are
/// applied here on the main actor.
@MainActor
@Observable
final class AppModel {
    private(set) var startError: String?
    /// True once the core is running and every topic has loaded; until then the
    /// model's lists are empty placeholders, not the stored state.
    private(set) var started = false

    private(set) var pending: [PendingItem] = []
    private(set) var recent: [RecentItem] = []
    /// Approved `asm login` requests whose sign-in browser is open (shown in the approval panel).
    private(set) var brokerSessions: [BrokerSessionItem] = []
    /// A failed "Hand over session" or "Cancel", by request ID.
    private(set) var brokerErrors: [String: String] = [:]
    private(set) var vaults: [VaultItem] = []
    /// Visible vault items sharing a name; agents must use a qualified name for them.
    private(set) var nameConflicts: [NameConflictGroupItem] = []
    private(set) var generators: [GeneratorItem] = []
    private(set) var hasRecordedGcloudAccounts = false
    private(set) var sshTargets: [SshTargetItem] = []
    private(set) var hosts: [HostItem] = []
    private(set) var pairingCodes: [PairingCodeItem] = []
    private(set) var leases: [LeaseItem] = []
    private(set) var proxySettings = ProxySettingsItem()
    private(set) var proxyStatus = ProxyStatusItem()
    private(set) var firewall = FirewallStatusItem()
    private(set) var proxyLog: [String] = []
    private(set) var general = GeneralSettingsItem()
    /// Bumped when the core reports new activity rows (topic `activity`); the Activity Log
    /// window fetches what is new.
    private(set) var activityRevision = 0
    /// Invalidation for the local Google account journal, including lease or label changes.
    private(set) var gcloudOwnedAccountsRevision = 0
    /// Set by the Activity Log's "Show lease"; the Settings window shows the lease.
    var leaseFocus: LeaseFocus?
    /// Set by a click on a Recent entry; the Activity Log window selects that row.
    var activityFocus: ActivityFocus?
    /// Set to show a pane in the Settings window (consumed by `SettingsView`).
    var settingsPaneRequest: SettingsPane?
    /// Set by an approval panel's target link; the SSH Targets pane selects that target.
    var sshTargetFocus: String?
    /// Opens a window scene by id; registered by the always-present menu bar label (SwiftUI
    /// hands `openWindow` to views only).
    @ObservationIgnored var openWindow: ((String) -> Void)?

    /// Request shown in the approval panel; `nil` when nothing is pending.
    private(set) var shownRequestID: String?
    private(set) var shownRequest: PendingItem?
    /// A new presentation must not reuse a first-use IAM plan discarded when the panel closed.
    private(set) var approvalPresentation: UInt64 = 0
    /// In-flight decisions and failures belong to requests, not panel presentations.
    private var requestResolutions: [String: RequestResolution] = [:]

    /// Vault whose unlock sheet is shown in the Settings window.
    var unlockingVaultID: String?

    var unlockingVault: VaultItem? {
        vaults.first { $0.id == unlockingVaultID }
    }

    /// Bitwarden vaults waiting for their master password (it is never stored).
    var lockedVaults: [VaultItem] {
        vaults.filter(\.canUnlock)
    }

    @ObservationIgnored private var bridge: CoreBridge?
    @ObservationIgnored private lazy var panel = ApprovalPanelController(model: self)
    @ObservationIgnored private var wakeObserver: NSObjectProtocol?
    @ObservationIgnored private let proxyAlerts = ProxyAlerts()

    // MARK: Lifecycle

    func start() async {
        let fm = FileManager.default
        let dataDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("asm", isDirectory: true)
        let binDir = Bundle.main.executableURL!.deletingLastPathComponent()
        do {
            try fm.createDirectory(at: dataDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let onChange: @Sendable (String) -> Void = { [weak self] topic in
                Task { @MainActor in await self?.refresh(topic) }
            }
            let bridge = try await Task.detached(priority: .userInitiated) {
                try CoreBridge.start(dataDir: dataDir.path, binDir: binDir.path, onChange: onChange)
            }.value
            self.bridge = bridge
            startError = nil
        } catch let error as AppError where error.code == "exists" {
            // Another copy owns the data directory (and the proxy ports).
            Self.quitAsSecondInstance(error.message)
            return
        } catch {
            startError = error.localizedDescription
            return
        }
        proxyAlerts.onRestart = { [weak self] in
            Task { _ = await self?.restartProxy() }
        }
        proxyAlerts.onShowDetails = { [weak self] in self?.showProxyDetails() }
        proxyAlerts.onShowLease = { [weak self] id in self?.showLeaseDetails(id) }
        proxyAlerts.install()
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in await self?.onWake() }
        }
        for topic in CoreBridge.topics {
            await refresh(topic)
        }
        started = true
    }

    /// Called from `applicationWillTerminate`; stops the API, the proxy and `bw serve`.
    func shutdown() {
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
        }
        bridge?.shutdown()
        bridge = nil
    }

    private func onWake() async {
        _ = try? await call { try $0.onWake() }
    }

    private func call<T: Sendable>(_ work: @escaping @Sendable (CoreBridge) throws -> T) async throws -> T {
        guard let bridge else { throw AppError(message: startError ?? "The manager is not running.") }
        return try await Task.detached(priority: .userInitiated) { try work(bridge) }.value
    }

    /// Runs a core call and returns its error message, or `nil` on success.
    func perform(_ work: @escaping @Sendable (CoreBridge) throws -> Void) async -> String? {
        do {
            try await call(work)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    // MARK: Refresh (observer topics)

    func refresh(_ topic: String) async {
        do {
            switch topic {
            case "requests":
                try await refreshRequests()
            case "leases":
                gcloudOwnedAccountsRevision &+= 1
                leases = try await call { try $0.listLeases() }
                proxyAlerts.updateSsh(leases)
                hosts = try await call { try $0.listHosts() }
                // Hosts and SSH targets show how many active leases they have.
                sshTargets = try await call { try $0.listSshTargets() }
            case "hosts":
                gcloudOwnedAccountsRevision &+= 1
                hosts = try await call { try $0.listHosts() }
                pairingCodes = try await call { try $0.listPairingCodes() }
            case "vaults":
                vaults = try await call { try $0.listVaults() }
                if pending.contains(where: { $0.kind == .add }) {
                    try await refreshRequests()
                }
                nameConflicts = try await call { $0.nameConflicts() }
            case "generators":
                gcloudOwnedAccountsRevision &+= 1
                generators = try await call { try $0.listGenerators() }
            case "gcloud_accounts":
                gcloudOwnedAccountsRevision &+= 1
                // Journal rows are retained for audit, so only promote false to true.
                if !hasRecordedGcloudAccounts, try await call({ try $0.hasRecordedGcloudAccounts() }) {
                    hasRecordedGcloudAccounts = true
                }
            case "ssh_targets":
                sshTargets = try await call { try $0.listSshTargets() }
                // A pending SSH request shows each target's current readiness.
                if pending.contains(where: { $0.kind == .ssh }) {
                    try await refreshRequests()
                }
            case "proxy":
                await refreshProxy()
            case "firewall":
                applyFirewall(try await call { try $0.firewallStatus() })
            case "settings":
                general = try await call { try $0.generalSettings() }
                proxySettings = try await call { try $0.proxySettings() }
            case "activity":
                activityRevision &+= 1
            default:
                break
            }
        } catch {
            // A failed refresh keeps the previous data; the next change retries.
        }
    }

    private func refreshRequests() async throws {
        let snapshot = try await call { try $0.snapshot() }
        applyRequests(pending: snapshot.pending, recent: snapshot.recent, brokerSessions: snapshot.brokerSessions)
    }

    func refreshProxy() async {
        guard let status = try? await call({ try $0.proxyStatus() }) else { return }
        proxyStatus = status
        proxyAlerts.update(status)
        if let log = try? await call({ try $0.proxyLogTail(200) }) {
            proxyLog = log
        }
    }

    private func applyFirewall(_ status: FirewallStatusItem) {
        firewall = status
        proxyAlerts.updateFirewall(status)
    }

    /// Checks the macOS Firewall now ("Check again" in Settings → Proxy).
    func checkFirewall() async {
        if let status = try? await call({ try $0.checkFirewall() }) {
            applyFirewall(status)
        }
    }

    private func applyRequests(
        pending newPending: [PendingItem], recent newRecent: [RecentItem], brokerSessions newSessions: [BrokerSessionItem]
    ) {
        let known = Set(pending.map(\.id))
        let arrived = newPending.contains { !known.contains($0.id) }
        pending = newPending
        for id in requestResolutions.keys where !isResolving(id) && !newPending.contains(where: { $0.id == id }) {
            requestResolutions.removeValue(forKey: id)
        }
        recent = newRecent
        brokerSessions = newSessions
        brokerErrors = brokerErrors.filter { id, _ in newSessions.contains { $0.id == id } }
        let next = newPending.first { $0.id == shownRequestID } ?? newPending.first
        show(next)
        if newPending.isEmpty && newSessions.isEmpty {
            panel.close()
        } else if arrived {
            panel.present(takeFocus: false)
        }
    }

    private func show(_ next: PendingItem?) {
        let redisplay = panel.prepare(for: next)
        shownRequestID = next?.id
        shownRequest = next
        // Open sign-in browsers keep the panel up after its last request resolves.
        if redisplay && (next != nil || !brokerSessions.isEmpty) { panel.present(takeFocus: false) }
    }

    // MARK: Approval

    func approvalPanelWillOpen() { approvalPresentation &+= 1 }

    /// Opens the approval panel on one request (menu bar click).
    func openApproval(for id: String) {
        guard let request = pending.first(where: { $0.id == id }) else { return }
        show(request)
        panel.present(takeFocus: true)
    }

    /// Opens the approval panel on the open sign-in browsers (menu bar click).
    func openBrokerSessions() {
        guard !brokerSessions.isEmpty else { return }
        panel.present(takeFocus: true)
    }

    func showNext(offset: Int) {
        guard let id = shownRequestID, let index = pending.firstIndex(where: { $0.id == id }), !pending.isEmpty else { return }
        let next = (index + offset + pending.count) % pending.count
        show(pending[next])
    }

    private enum RequestResolution: Equatable {
        case resolving(generating: Bool)
        case failed(String)
    }

    func isResolving(_ id: String) -> Bool {
        if case .resolving = requestResolutions[id] { return true }
        return false
    }

    func isGenerating(_ id: String) -> Bool {
        requestResolutions[id] == .resolving(generating: true)
    }

    func resolutionError(for id: String) -> String? {
        if case let .failed(message) = requestResolutions[id] { return message }
        return nil
    }

    func resolve(_ id: String, _ decision: DecisionItem, gcloudPlanID: String? = nil) {
        guard shownRequestID == id, !isResolving(id) else { return }
        let generating = if case let .approveGet(_, _, _, selection) = decision { selection != nil } else { false }
        // Claim synchronously, before another button, shortcut or menu can act.
        requestResolutions[id] = .resolving(generating: generating)
        Task {
            let error = await perform { bridge in
                if let gcloudPlanID {
                    try bridge.gcloudApproveProfile(requestID: id, planID: gcloudPlanID, decision: decision)
                } else {
                    try bridge.resolve(id: id, decision: decision)
                }
            }
            await refresh("requests")
            if let error, pending.contains(where: { $0.id == id }) {
                requestResolutions[id] = .failed(error)
            } else {
                requestResolutions.removeValue(forKey: id)
            }
        }
    }

    /// "Hand over session": the agent receives the sign-in browser's session.
    func handOverBrokerSession(_ id: String) {
        brokerAction(id) { try $0.brokerHandover(requestID: id) }
    }

    /// "Cancel": closes the sign-in browser and denies the request.
    func cancelBrokerSession(_ id: String) {
        brokerAction(id) { try $0.brokerCancel(requestID: id) }
    }

    private func brokerAction(_ id: String, _ work: @escaping @Sendable (CoreBridge) throws -> Void) {
        brokerErrors.removeValue(forKey: id)
        Task {
            let error = await perform(work)
            await refresh("requests")
            if let error, brokerSessions.contains(where: { $0.id == id }) {
                brokerErrors[id] = error
            }
        }
    }

    func checkHostPattern(_ pattern: String) -> Result<HostPatternCheckItem, AppError> {
        CoreBridge.checkHostPattern(pattern)
    }

    // MARK: Vaults

    func connectBitwarden(_ draft: VaultDraftItem) async throws -> [CollectionItem] {
        try await call { try $0.bitwardenConnect(draft) }
    }

    func vaultCollections(_ id: String) async throws -> [CollectionChoiceItem] {
        try await call { try $0.vaultCollections(id) }
    }

    func saveVault(_ draft: VaultDraftItem) async -> String? {
        let error = await perform { try $0.saveVault(draft) }
        await refresh("vaults")
        return error
    }

    func removeVault(_ id: String) async -> String? {
        let error = await perform { try $0.removeVault(id) }
        await refresh("vaults")
        return error
    }

    func syncVault(_ id: String) async -> String? {
        let error = await perform { try $0.syncVault(id) }
        await refresh("vaults")
        return error
    }

    /// Renames a Bitwarden item agents can see (Settings → Vaults → Name conflicts).
    func renameSecret(vaultID: String, key: String, newName: String) async -> String? {
        let error = await perform { try $0.renameSecret(vaultID: vaultID, key: key, newName: newName) }
        await refresh("vaults")
        return error
    }

    /// Unlocks a Locked Bitwarden vault; the password is kept only by the running manager.
    func unlockVault(_ id: String, masterPassword: String) async -> String? {
        let error = await perform { try $0.unlockVault(id, masterPassword: masterPassword) }
        await refresh("vaults")
        await refresh("leases")
        return error
    }

    // MARK: Generators

    func githubConnect(_ draft: GeneratorDraftItem) async throws -> GithubInstallationItem {
        try await call { try $0.githubConnect(draft) }
    }

    func githubListInstallations(_ draft: GeneratorDraftItem) async throws -> [GithubInstallationAccountItem] {
        try await call { try $0.githubListInstallations(draft) }
    }

    func gcloudCheckSdk(path: String? = nil) async throws -> GcloudSdkItem {
        try await call { try $0.gcloudCheckSdk(path: path) }
    }

    func gcloudBeginLogin(sdkPath: String) async throws -> String {
        try await call { try $0.gcloudBeginLogin(sdkPath: sdkPath) }
    }

    func gcloudFinishLogin(sessionID: String) async throws -> GcloudIdentityItem {
        try await call { try $0.gcloudFinishLogin(sessionID: sessionID) }
    }

    func gcloudCancelLogin(sessionID: String) async throws {
        try await call { try $0.gcloudCancelLogin(sessionID: sessionID) }
    }

    func gcloudApprovalProjects(
        requestID: String, generatorID: String, generatorRevision: UInt64
    ) async throws -> [String] {
        try await call {
            try $0.gcloudApprovalProjects(
                requestID: requestID, generatorID: generatorID, generatorRevision: generatorRevision
            )
        }
    }

    func gcloudProfilePlan(
        requestID: String, decision: DecisionItem
    ) async throws -> (GcloudProfilePlanItem, Date?) {
        try await call { try $0.gcloudProfilePlan(requestID: requestID, decision: decision) }
    }

    func gcloudCancelProfile(planID: String) async throws {
        try await call { try $0.gcloudCancelProfile(planID: planID) }
    }

    func gcloudOwnedAccounts() async throws -> [GcloudOwnedAccountItem] {
        try await call { try $0.listGcloudOwnedAccounts() }
    }

    /// Call only after explicit confirmation of this snapshot's identity and lease list.
    func deleteGcloudOwnedAccount(_ account: GcloudOwnedAccountItem) async throws {
        // A stale confirmation also needs a reload, even if the core rejected it without any mutation.
        defer { gcloudOwnedAccountsRevision &+= 1 }
        try await call { try $0.deleteGcloudOwnedAccount(account) }
    }

    func saveGenerator(_ draft: GeneratorDraftItem) async throws -> GeneratorItem {
        let generator = try await call { try $0.saveGenerator(draft) }
        await refresh("generators")
        await refresh("leases")
        await refresh("requests")
        return generator
    }

    func removeGenerator(_ id: String) async -> String? {
        let error = await perform { try $0.removeGenerator(id) }
        await refresh("generators")
        await refresh("leases")
        await refresh("requests")
        return error
    }

    // MARK: SSH targets

    func lookupSshHostKeys(_ destination: String) async throws -> SshHostKeyLookupItem {
        try await call { try $0.lookupSshHostKeys(destination) }
    }

    func fetchSshHostKeys(_ destination: String) async throws -> SshHostKeyLookupItem {
        try await call { try $0.fetchSshHostKeys(destination) }
    }

    /// Logs in as enrollment will; takes up to 30 s.
    func checkSshDestination(_ destination: String, login: String, hostKeys: [String]) async throws -> SshHostCheckItem {
        try await call { try $0.checkSshDestination(destination, login: login, hostKeys: hostKeys) }
    }

    /// Lists the host's accounts as the privileged login; takes up to 30 s.
    func listSshHostUsers(_ destination: String, login: String, hostKeys: [String]) async throws -> [SshHostUserItem] {
        try await call { try $0.listSshHostUsers(destination, login: login, hostKeys: hostKeys) }
    }

    /// Asks a target for its host keys and compares them with the pinned ones; the target
    /// list then shows the result.
    func reviewSshHostKeys(_ id: String) async throws -> SshHostCheckItem {
        let result = try await call { try $0.reviewSshHostKeys(id) }
        await refresh("ssh_targets")
        return result
    }

    /// Pins host keys the operator reviewed; ends the target's leases.
    func replaceSshHostKeys(_ id: String, expectedRevision: UInt64, keys: [String]) async -> String? {
        let error = await perform { _ = try $0.replaceSshHostKeys(id, expectedRevision: expectedRevision, keys: keys) }
        await refresh("ssh_targets")
        await refresh("leases")
        return error
    }

    func saveSshTarget(_ draft: SshTargetDraftItem) async -> String? {
        let error = await perform { _ = try $0.saveSshTarget(draft) }
        await refresh("ssh_targets")
        await refresh("leases")
        return error
    }

    func removeSshTarget(_ id: String) async -> String? {
        let error = await perform { try $0.removeSshTarget(id) }
        await refresh("ssh_targets")
        return error
    }

    /// Runs the enrollment script over the operator's ssh; takes up to two minutes.
    func enrollSshTarget(_ id: String, expectedRevision: UInt64) async -> String? {
        let error = await perform { try $0.enrollSshTarget(id, expectedRevision: expectedRevision) }
        await refresh("ssh_targets")
        return error
    }

    /// Ends the target's leases and removes asm from the host over the operator's ssh.
    func unenrollSshTarget(_ id: String) async -> String? {
        let error = await perform { try $0.unenrollSshTarget(id) }
        await refresh("ssh_targets")
        await refresh("leases")
        return error
    }

    func sshEnrollScript(_ id: String) async throws -> String {
        try await call { try $0.sshEnrollScript(id) }
    }

    // MARK: Hosts and pairing codes

    func revokeHost(_ id: String) async -> String? {
        let error = await perform { try $0.revokeHost(id) }
        await refresh("hosts")
        await refresh("leases")
        return error
    }

    func renameHost(_ id: String, name: String) async -> String? {
        let error = await perform { try $0.renameHost(id, name: name) }
        await refresh("hosts")
        await refresh("leases")
        await refresh("requests")
        return error
    }

    func createPairingCode(label: String, expirySecs: UInt64?, maxUses: UInt32?, networks: [String]) async throws -> String {
        let code = try await call {
            try $0.createPairingCode(label: label, expirySecs: expirySecs, maxUses: maxUses, networks: networks)
        }
        await refresh("hosts")
        return code
    }

    func revokePairingCode(_ id: String) async -> String? {
        let error = await perform { try $0.revokePairingCode(id) }
        await refresh("hosts")
        return error
    }

    // MARK: Leases

    func revokeLeases(_ ids: Set<String>) async -> String? {
        var firstError: String?
        for id in ids {
            if let error = await perform({ try $0.revokeLease(id) }), firstError == nil {
                firstError = error
            }
        }
        await refresh("leases")
        return firstError
    }

    func retrySshCleanup(_ leaseID: String) async -> String? {
        let error = await perform { try $0.retrySshCleanup(leaseID) }
        await refresh("leases")
        return error
    }

    // MARK: Activity log

    func listActivity(_ query: ActivityQueryItem) async throws -> [ActivityItem] {
        try await call { try $0.listActivity(query) }
    }

    /// Switches the Settings window to Leases, searching for `secret` with `leaseID` selected.
    func showLease(_ leaseID: String, secret: String) {
        leaseFocus = LeaseFocus(leaseID: leaseID, search: secret)
    }

    /// Asks the Activity Log to select the row of a resolved request (a Recent entry); the
    /// caller opens the window.
    func focusActivity(forRequest requestID: String) {
        Task {
            let rowID = try? await call { try $0.activityRowForRequest(requestID) }
            activityFocus = ActivityFocus(rowID: rowID)
        }
    }

    // MARK: Proxy and settings

    func saveProxySettings(_ settings: ProxySettingsItem) async -> String? {
        let error = await perform { try $0.setProxySettings(settings) }
        await refresh("settings")
        await refreshProxy()
        return error
    }

    func restartProxy() async -> String? {
        let error = await perform { try $0.restartProxy() }
        await refreshProxy()
        return error
    }

    /// Opens Settings → Proxy (notification click, banner "Details…").
    func showProxyDetails() {
        showSettings(.proxy)
    }

    /// Opens Settings → SSH Targets with one target selected (approval panel link).
    func showSshTarget(_ id: String) {
        sshTargetFocus = id
        showSettings(.sshTargets)
    }

    /// Opens Settings → Leases with one lease selected (SSH lease notification).
    func showLeaseDetails(_ leaseID: String) {
        leaseFocus = LeaseFocus(leaseID: leaseID, search: "")
        showSettings(.leases)
    }

    private func showSettings(_ pane: SettingsPane) {
        settingsPaneRequest = pane
        guard let openWindow else {
            ProxyAlerts.openMenuBarPanel()
            return
        }
        ActivationPolicyController.shared.openRegularWindow { openWindow("settings") }
    }

    /// This copy found another one running with the same data directory: say so, bring
    /// the other one forward and quit (the running copy keeps the manager and proxy).
    private static func quitAsSecondInstance(_ message: String) {
        let me = ProcessInfo.processInfo.processIdentifier
        let other = NSRunningApplication
            .runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "net.thinkscape.asm")
            .first { $0.processIdentifier != me }
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Agents Secrets Manager is already running"
        alert.informativeText = "\(message.prefix(1).uppercased())\(message.dropFirst()). This copy will quit; the running one stays in the menu bar."
        alert.addButton(withTitle: "Quit")
        alert.runModal()
        other?.activate()
        NSApp.terminate(nil)
    }

    func saveGeneralSettings(_ settings: GeneralSettingsItem) async -> String? {
        let error = await perform { try $0.setGeneralSettings(settings) }
        await refresh("settings")
        return error
    }
}

