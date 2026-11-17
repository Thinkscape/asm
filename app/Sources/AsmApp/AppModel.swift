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
    private(set) var started = false

    private(set) var pending: [PendingItem] = []
    private(set) var recent: [RecentItem] = []
    private(set) var vaults: [VaultItem] = []
    private(set) var generators: [GeneratorItem] = []
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
    /// Set by the Activity Log's "Show lease"; the Settings window shows the lease.
    var leaseFocus: LeaseFocus?
    /// Set by a click on a Recent entry; the Activity Log window selects that row.
    var activityFocus: ActivityFocus?
    /// Set to show a pane in the Settings window (consumed by `SettingsView`).
    var settingsPaneRequest: SettingsPane?
    /// Opens a window scene by id; registered by the always-present menu bar label (SwiftUI
    /// hands `openWindow` to views only).
    @ObservationIgnored var openWindow: ((String) -> Void)?

    /// Request shown in the approval panel; `nil` when nothing is pending.
    private(set) var shownRequestID: String?
    private(set) var shownRequest: PendingItem?
    /// Error from the last failed `resolve`, shown in the approval panel.
    var resolveError: String?

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
            started = true
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
        proxyAlerts.install()
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in await self?.onWake() }
        }
        for topic in CoreBridge.topics {
            await refresh(topic)
        }
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
                let snapshot = try await call { try $0.snapshot() }
                applyRequests(pending: snapshot.pending, recent: snapshot.recent)
            case "leases":
                leases = try await call { try $0.listLeases() }
                hosts = try await call { try $0.listHosts() }
            case "hosts":
                hosts = try await call { try $0.listHosts() }
                pairingCodes = try await call { try $0.listPairingCodes() }
            case "vaults":
                vaults = try await call { try $0.listVaults() }
            case "generators":
                generators = try await call { try $0.listGenerators() }
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

    private func applyRequests(pending newPending: [PendingItem], recent newRecent: [RecentItem]) {
        let known = Set(pending.map(\.id))
        let arrived = newPending.contains { !known.contains($0.id) }
        pending = newPending
        recent = newRecent
        if let id = shownRequestID, newPending.contains(where: { $0.id == id }) {
            shownRequest = newPending.first { $0.id == id }
        } else {
            // The shown request was resolved, expired or cancelled: show the next (oldest).
            show(newPending.first?.id)
        }
        if newPending.isEmpty {
            panel.close()
        } else if arrived {
            panel.present(takeFocus: false)
        }
    }

    private func show(_ id: String?) {
        if shownRequestID != id { resolveError = nil }
        shownRequestID = id
        shownRequest = pending.first { $0.id == id }
    }

    // MARK: Approval

    /// Opens the approval panel on one request (menu bar click).
    func openApproval(for id: String) {
        show(id)
        panel.present(takeFocus: true)
    }

    func showNext(offset: Int) {
        guard let id = shownRequestID, let index = pending.firstIndex(where: { $0.id == id }), !pending.isEmpty else { return }
        let next = (index + offset + pending.count) % pending.count
        show(pending[next].id)
    }

    func resolve(_ id: String, _ decision: DecisionItem) async {
        do {
            try await call { try $0.resolve(id: id, decision: decision) }
            resolveError = nil
            await refresh("requests")
        } catch {
            resolveError = error.localizedDescription
            await refresh("requests")
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
        settingsPaneRequest = .proxy
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

