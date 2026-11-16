import AppKit
import SwiftUI

/// Puts the app in the Dock and the Cmd+Tab switcher while a regular window
/// (Settings) is open, and back to a menu-bar-only app when the last one closes.
/// The approval panel and the menu bar panel are never tracked.
@MainActor
final class ActivationPolicyController {
    static let shared = ActivationPolicyController()

    private let windows = NSHashTable<NSWindow>.weakObjects()
    private var observers: [NSObjectProtocol] = []

    private init() {
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { note in
            let window = note.object as? NSWindow
            MainActor.assumeIsolated {
                ActivationPolicyController.shared.windowChanged(window, closing: false)
            }
        })
        observers.append(center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { note in
            let window = note.object as? NSWindow
            MainActor.assumeIsolated {
                ActivationPolicyController.shared.windowChanged(window, closing: true)
            }
        })
    }

    /// Registers a window whose presence makes the app a regular app.
    func track(_ window: NSWindow) {
        windows.add(window)
        update(closing: nil)
    }

    private func windowChanged(_ window: NSWindow?, closing: Bool) {
        guard let window, windows.contains(window) else { return }
        update(closing: closing ? window : nil)
    }

    private func update(closing: NSWindow?) {
        // A minimised Settings window keeps the Dock icon: it is the way back to it.
        let open = windows.allObjects.contains { $0 !== closing && ($0.isVisible || $0.isMiniaturized) }
        let policy: NSApplication.ActivationPolicy = open ? .regular : .accessory
        guard NSApp.activationPolicy() != policy else { return }
        NSApp.setActivationPolicy(policy)
        if open { NSApp.activate() }
    }
}

/// Background view that registers its window with `ActivationPolicyController`.
struct RegularWindowMarker: NSViewRepresentable {
    final class MarkerView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { ActivationPolicyController.shared.track(window) }
        }
    }

    func makeNSView(context: Context) -> MarkerView { MarkerView() }
    func updateNSView(_ nsView: MarkerView, context: Context) {}
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // The manager API and the proxy serve other machines while no window is
        // open: macOS must not end this window-less app on its own.
        ProcessInfo.processInfo.automaticTerminationSupportEnabled = false
        ProcessInfo.processInfo.disableAutomaticTermination("The manager API and proxy are running.")
        ProcessInfo.processInfo.disableSuddenTermination()
        Task { await model.start() }
    }

    func applicationWillTerminate(_ notification: Notification) {
        model.shutdown()
    }

    /// Closing the Settings window must not quit a menu bar app.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

@main
struct AsmApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarPanel(model: appDelegate.model)
        } label: {
            MenuBarLabel(pendingCount: appDelegate.model.pending.count)
        }
        .menuBarExtraStyle(.window)

        Window("Agents Secrets Manager", id: "settings") {
            SettingsView(model: appDelegate.model)
        }
        .defaultSize(width: 920, height: 600)
    }
}
