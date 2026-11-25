import AppKit
import UserNotifications

/// Tells the operator when the proxy stops working: one macOS notification per incident
/// (Down, or unhealthy for 30 s) with a Restart action. Without notification permission
/// it opens the menu bar panel, whose banner says the same. Recovery removes the
/// notification and posts nothing. The macOS Firewall blocking a listener meant for other
/// machines is reported the same way, with an Open Firewall Settings action.
@MainActor
final class ProxyAlerts: NSObject, UNUserNotificationCenterDelegate {
    private static let category = "net.thinkscape.asm.proxy-problem"
    private static let restartAction = "restart"
    private static let requestID = "proxy-problem"
    private static let firewallCategory = "net.thinkscape.asm.firewall-blocked"
    private static let openFirewallAction = "open-firewall"
    private static let firewallRequestID = "firewall-blocked"
    /// An unhealthy (running but not answering) proxy is reported after this long.
    private static let unhealthyNotifyAfter: TimeInterval = 30

    /// Restart action of the notification.
    var onRestart: () -> Void = {}
    /// Click on the notification body: show Settings → Proxy.
    var onShowDetails: () -> Void = {}

    /// The current incident was reported (reset when the proxy runs again).
    private var reported = false
    private var unhealthyCheck: Task<Void, Never>?
    /// The current firewall incident was reported (reset once nothing is blocked).
    private var firewallReported = false
    /// `<lease id>/<target name>` of every SSH cleanup problem seen; `nil` until the first
    /// lease list.
    private var sshCleanupSeen: Set<String>?

    /// `nil` when the process has no bundle (`swift run`): the API then traps.
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : .current()
    }

    func install() {
        guard let center else { return }
        center.delegate = self
        let restart = UNNotificationAction(identifier: Self.restartAction, title: "Restart", options: [])
        let openFirewall = UNNotificationAction(identifier: Self.openFirewallAction, title: "Open Firewall Settings", options: [])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.category, actions: [restart], intentIdentifiers: [], options: []),
            UNNotificationCategory(identifier: Self.firewallCategory, actions: [openFirewall], intentIdentifiers: [], options: []),
        ])
    }

    /// Feed every new proxy status.
    func update(_ status: ProxyStatusItem) {
        switch status.health {
        case .running:
            unhealthyCheck?.cancel()
            if reported {
                reported = false
                center?.removeDeliveredNotifications(withIdentifiers: [Self.requestID])
            }
        case .starting:
            break
        case let .down(reason, _):
            unhealthyCheck?.cancel()
            report(title: "Proxy is not running", body: "Agents can't use their leases. \(reason)")
        case let .unhealthy(since):
            let due = since.addingTimeInterval(Self.unhealthyNotifyAfter)
            unhealthyCheck?.cancel()
            guard !reported else { return }
            let body = "It has not answered health checks since \(since.formatted(date: .omitted, time: .standard)). Agents can't use their leases."
            if due <= .now {
                report(title: "Proxy is not responding", body: body)
            } else {
                // The core sends nothing at the 30 s mark: check again then.
                unhealthyCheck = Task { [weak self] in
                    try? await Task.sleep(for: .seconds(due.timeIntervalSinceNow))
                    guard !Task.isCancelled else { return }
                    self?.report(title: "Proxy is not responding", body: body)
                }
            }
        }
    }

    /// Feed every new firewall status: one notification when a listener meant for other
    /// machines becomes blocked; removed once nothing is blocked.
    func updateFirewall(_ status: FirewallStatusItem) {
        guard status.needsAttention else {
            if firewallReported {
                firewallReported = false
                center?.removeDeliveredNotifications(withIdentifiers: [Self.firewallRequestID])
            }
            return
        }
        guard !firewallReported else { return }
        firewallReported = true
        let (title, body) = status.proxy.blocked
            ? ("macOS Firewall blocks iron-proxy",
               "Other machines can't use their leases. Allow incoming connections for iron-proxy in System Settings → Network → Firewall → Options.")
            : ("macOS Firewall blocks Agents Secrets Manager",
               "Other machines can't pair or request secrets. Allow incoming connections for it in System Settings → Network → Firewall → Options.")
        Task { await post(id: Self.firewallRequestID, category: Self.firewallCategory, title: title, body: body) }
    }

    /// Feed every new lease list: one notification per target of a privileged or
    /// another-user SSH lease whose session cleanup is retrying or failed. The first call
    /// only records the problems that already exist.
    func updateSshCleanup(_ leases: [LeaseItem]) {
        var problems: [(key: String, leaseID: String, target: SshLeaseTargetItem)] = []
        for lease in leases {
            guard let ssh = lease.ssh, ssh.access != .restricted else { continue }
            for target in ssh.targets where target.cleanup == .retrying || target.cleanup == .failed {
                problems.append(("\(lease.id)/\(target.name)", lease.id, target))
            }
        }
        guard var seen = sshCleanupSeen else {
            sshCleanupSeen = Set(problems.map(\.key))
            return
        }
        for problem in problems where seen.insert(problem.key).inserted {
            let title = "Ending SSH sessions on \(problem.target.name) failed"
            let body = "\(problem.target.cleanupDetail). Sessions of this lease may stay open; the host ends them when the lease expires."
            let id = "ssh-cleanup-\(problem.leaseID)-\(problem.target.name)"
            Task { await post(id: id, category: "", title: title, body: body) }
        }
        sshCleanupSeen = seen
    }

    private func report(title: String, body: String) {
        guard !reported else { return }
        reported = true
        Task { await post(id: Self.requestID, category: Self.category, title: title, body: body) }
    }

    private func post(id: String, category: String, title: String, body: String) async {
        guard let center, await authorized(center) else {
            Self.openMenuBarPanel()
            return
        }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.categoryIdentifier = category
        content.sound = .default
        do {
            try await center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
        } catch {
            Self.openMenuBarPanel()
        }
    }

    /// System Settings → Network → Firewall (the Network pane when that anchor is unknown).
    static func openFirewallSettings() {
        let firewall = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall")!
        let network = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension")!
        if !NSWorkspace.shared.open(firewall) {
            _ = NSWorkspace.shared.open(network)
        }
    }

    /// Asks for permission the first time a notification is needed.
    private func authorized(_ center: UNUserNotificationCenter) async -> Bool {
        switch await center.notificationSettings().authorizationStatus {
        case .authorized, .provisional:
            return true
        case .notDetermined:
            return (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
        default:
            return false
        }
    }

    /// Opens the menu bar item's panel (the SwiftUI `MenuBarExtra` status item).
    static func openMenuBarPanel() {
        let key = "statusItem"
        for window in NSApp.windows where window.className.contains("NSStatusBarWindow") {
            guard window.responds(to: NSSelectorFromString(key)),
                  let item = window.value(forKey: key) as? NSStatusItem,
                  let button = item.button else { continue }
            button.performClick(nil)
            return
        }
    }

    // MARK: UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        let action = response.actionIdentifier
        await MainActor.run {
            switch action {
            case Self.restartAction: onRestart()
            case Self.openFirewallAction: Self.openFirewallSettings()
            case UNNotificationDefaultActionIdentifier: onShowDetails()
            default: break
            }
        }
    }
}
