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

    var body: some View {
        NavigationSplitView {
            List(SettingsPane.allCases, selection: $selection) { pane in
                Label(pane.title, systemImage: pane.symbol).tag(pane)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            SettingsDetail(model: model, pane: selection ?? .vaults)
        }
        .frame(minWidth: 820, minHeight: 520)
    }
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
