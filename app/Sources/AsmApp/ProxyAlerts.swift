import AppKit
import UserNotifications

/// Tells the operator when the proxy stops working: one macOS notification per incident
/// (Down, or unhealthy for 30 s) with a Restart action. Without notification permission
/// it opens the menu bar panel, whose banner says the same. Recovery removes the
/// notification and posts nothing.
@MainActor
final class ProxyAlerts: NSObject, UNUserNotificationCenterDelegate {
    private static let category = "net.thinkscape.asm.proxy-problem"
    private static let restartAction = "restart"
    private static let requestID = "proxy-problem"
    /// An unhealthy (running but not answering) proxy is reported after this long.
    private static let unhealthyNotifyAfter: TimeInterval = 30

    /// Restart action of the notification.
    var onRestart: () -> Void = {}
    /// Click on the notification body: show Settings → Proxy.
    var onShowDetails: () -> Void = {}

    /// The current incident was reported (reset when the proxy runs again).
    private var reported = false
    private var unhealthyCheck: Task<Void, Never>?

    /// `nil` when the process has no bundle (`swift run`): the API then traps.
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : .current()
    }

    func install() {
        guard let center else { return }
        center.delegate = self
        let restart = UNNotificationAction(identifier: Self.restartAction, title: "Restart", options: [])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.category, actions: [restart], intentIdentifiers: [], options: []),
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

    private func report(title: String, body: String) {
        guard !reported else { return }
        reported = true
        Task { await post(title: title, body: body) }
    }

    private func post(title: String, body: String) async {
        guard let center, await authorized(center) else {
            Self.openMenuBarPanel()
            return
        }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.categoryIdentifier = Self.category
        content.sound = .default
        do {
            try await center.add(UNNotificationRequest(identifier: Self.requestID, content: content, trigger: nil))
        } catch {
            Self.openMenuBarPanel()
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
            case UNNotificationDefaultActionIdentifier: onShowDetails()
            default: break
            }
        }
    }
}
