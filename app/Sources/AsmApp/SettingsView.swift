import AppKit
import SwiftUI

enum SettingsPane: String, CaseIterable, Identifiable, Hashable {
    case vaults, generators, sshTargets, hosts, leases, proxy, settings

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .vaults: "Vaults"
        case .generators: "Generators"
        case .sshTargets: "SSH Targets"
        case .hosts: "Hosts and Agents"
        case .leases: "Leases"
        case .proxy: "Proxy"
        case .settings: "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .vaults: "lock.rectangle.stack"
        case .generators: "key.horizontal"
        case .sshTargets: "server.rack"
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

    var body: some View {
        NavigationSplitView {
            List(SettingsPane.allCases, selection: $selection) { pane in
                HStack {
                    Label(pane.title, systemImage: pane.symbol)
                    if pane == .proxy, let problem = proxyProblem {
                        Spacer(minLength: 4)
                        Image(systemName: "exclamationmark.circle.fill")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, .red)
                            .help(problem)
                            .accessibilityLabel(problem)
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

    /// Why the Proxy sidebar item carries a badge; `nil` while fine.
    private var proxyProblem: String? {
        model.proxyStatus.needsAttention ? "Proxy not running" : model.firewall.problemLabel
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
            if let startError = model.startError {
                Label {
                    Text(verbatim: startError)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if !model.started {
                // Empty panes would read as lost state while the core is still starting.
                ProgressView("Starting the manager…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                switch pane {
                case .vaults: VaultsPane(model: model)
                case .generators: GeneratorsPane(model: model)
                case .sshTargets: SshTargetsPane(model: model)
                case .hosts: HostsPane(model: model)
                case .leases: LeasesPane(model: model)
                case .proxy: ProxyPane(model: model)
                case .settings: GeneralPane(model: model)
                }
            }
        }
        .navigationTitle(pane.title)
        .toolbar {
            // Reserve toolbar space even on panes with no actions, so macOS keeps
            // the unified title bar and its window-control and sidebar insets.
            if #available(macOS 26, *) {
                ToolbarSpacer(.flexible)
            } else {
                ToolbarItem { Spacer(minLength: 0) }
            }
        }
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
