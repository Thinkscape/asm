import AppKit
import SwiftUI

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
