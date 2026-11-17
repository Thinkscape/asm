import AppKit
import SwiftUI

enum SettingsPane: String, CaseIterable, Identifiable, Hashable {
    case vaults, hosts, leases, proxy, settings

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .vaults: "Vaults"
        case .hosts: "Hosts and Agents"
        case .leases: "Leases"
        case .proxy: "Proxy"
        case .settings: "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .vaults: "lock.rectangle.stack"
        case .hosts: "desktopcomputer"
        case .leases: "clock.badge.checkmark"
        case .proxy: "arrow.left.arrow.right"
        case .settings: "gearshape"
        }
    }
}

struct SettingsView: View {
    let model: AppModel
    @State private var selection: SettingsPane? = .vaults
    @State private var window = WindowRef()
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            List(SettingsPane.allCases, selection: $selection) { pane in
                HStack {
                    Label(pane.title, systemImage: pane.symbol)
                    if pane == .proxy && model.proxyStatus.needsAttention {
                        Spacer(minLength: 4)
                        Image(systemName: "exclamationmark.circle.fill")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, .red)
                            .help("Proxy not running")
                            .accessibilityLabel("Proxy not running")
                    }
                }
                .tag(pane)
            }
            .safeAreaInset(edge: .bottom, spacing: 0) { SidebarLogotype() }
            .navigationSplitViewColumnWidth(min: 200, ideal: 200, max: 200)
            .toolbar(removing: .sidebarToggle)
        } detail: {
            SettingsDetail(model: model, pane: selection ?? .vaults)
        }
        // Every pane shares this toolbar item. A pane without toolbar items (Hosts,
        // Proxy, Settings) would otherwise remove the window toolbar, shrinking the title
        // bar: the traffic lights and the sidebar jump when switching panes.
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    ActivationPolicyController.shared.openRegularWindow { openWindow(id: "activity") }
                } label: {
                    Label("Activity Log", systemImage: "list.bullet.rectangle")
                }
                .help("Show the activity log")
            }
        }
        .frame(minWidth: 820, minHeight: 520)
        .background(RegularWindowMarker { window.window = $0 })
        .onChange(of: model.unlockingVaultID, initial: true) { _, id in
            if id != nil { selection = .vaults }
        }
        .onChange(of: model.leaseFocus, initial: true) { _, focus in
            if focus != nil { selection = .leases }
        }
        .onChange(of: model.settingsPaneRequest, initial: true) { _, pane in
            guard let pane else { return }
            selection = pane
            model.settingsPaneRequest = nil
        }
        .sheet(item: Binding(
            get: { model.unlockingVault },
            set: { if $0 == nil { model.unlockingVaultID = nil } }
        ), onDismiss: {
            // The sheet may have been opened from the menu bar before this window was key;
            // when it ends, AppKit does not hand key status back to this window.
            if let window = window.window { ActivationPolicyController.shared.focus(window) }
        }) { vault in
            UnlockVaultSheet(model: model, vault: vault)
        }
    }
}

/// Logotype pinned to the bottom of the Settings sidebar: app icon, "ASM", version.
private struct SidebarLogotype: View {
    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
    }

    var body: some View {
        HStack(spacing: 8) {
            // The icon image carries the macOS grid margin (artwork 824/1024): draw it
            // larger than its layout frame so the artwork itself is 22 pt.
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .frame(width: 27, height: 27)
                .frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: "ASM")
                    .font(.system(size: 15, weight: .bold, design: .rounded))
                Text("Version \(version)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.leading, 20)
        .padding(.trailing, 16)
        .padding(.top, 8)
        .padding(.bottom, 14)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Agents Secrets Manager, version \(version)"))
    }
}

/// Weak reference to the window a view lives in.
@MainActor
final class WindowRef {
    weak var window: NSWindow?
}

private struct SettingsDetail: View {
    let model: AppModel
    let pane: SettingsPane

    var body: some View {
        VStack {
            switch pane {
            case .vaults: VaultsPane(model: model)
            case .hosts: HostsPane(model: model)
            case .leases: LeasesPane(model: model)
            case .proxy: ProxyPane(model: model)
            case .settings: GeneralPane(model: model)
            }
        }
        .navigationTitle(pane.title)
    }
}

/// Shows the error message of a failed settings action.
struct ErrorAlert: ViewModifier {
    @Binding var message: String?

    func body(content: Content) -> some View {
        content.alert(
            "Action failed",
            isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })
        ) {
            Button("OK") { message = nil }
        } message: {
            Text(verbatim: message ?? "")
        }
    }
}

extension View {
    func errorAlert(_ message: Binding<String?>) -> some View {
        modifier(ErrorAlert(message: message))
    }
}

/// Centered single line shown when a pane has nothing to list.
struct EmptyStateLine: View {
    let text: LocalizedStringKey

    var body: some View {
        Text(text)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
