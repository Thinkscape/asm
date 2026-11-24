import AppKit
import SwiftUI

struct ProxyPane: View {
    let model: AppModel
    @State private var draft = ProxySettingsItem()
    @State private var baseline = ProxySettingsItem()
    @State private var newHint = ""
    @State private var macNames: [String] = []
    @State private var saving = false
    @State private var error: String?

    private var dirty: Bool { draft != baseline }

    var body: some View {
        Form {
            ProxyStatusSection(status: model.proxyStatus) {
                Task { error = await model.restartProxy() }
            }

            NetworkAccessSection(firewall: model.firewall) { await model.checkFirewall() }

            Section("Listener") {
                TextField("Bind address", text: $draft.bindAddress)
                TextField("Port", value: $draft.port, format: .number.grouping(.never))
            }

            Section {
                ForEach(Array(draft.hints.enumerated()), id: \.element) { index, hint in
                    HintRow(
                        hint: hint,
                        canMoveUp: index > 0,
                        canMoveDown: index < draft.hints.count - 1,
                        move: { offset in draft.hints.swapAt(index, index + offset) },
                        remove: { draft.hints.remove(at: index) }
                    )
                }
                HStack {
                    TextField("Add hostname or address", text: $newHint)
                        .onSubmit(addTypedHint)
                    Button("Add", action: addTypedHint).disabled(newHint.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                let suggestions = macNames.filter { !draft.hints.contains($0) }
                if !suggestions.isEmpty {
                    LabeledContent("Suggestions") {
                        Menu("Add from this Mac") {
                            ForEach(suggestions, id: \.self) { name in
                                Button { addHint(name) } label: { Text(verbatim: name) }
                            }
                        }
                        .fixedSize()
                    }
                }
            } header: {
                Text("Hostname hints")
            } footer: {
                Text("Names agents use to reach this Mac, in order of preference (for example a Tailscale name). asm proxy-info recommends the first reachable one.")
            }

            Section("Advanced") {
                TextField("Internal HTTP port", value: $draft.httpPort, format: .number.grouping(.never))
                TextField("Internal HTTPS port", value: $draft.httpsPort, format: .number.grouping(.never))
                TextField("Management port", value: $draft.managementPort, format: .number.grouping(.never))
                TextField("Metrics and health port", value: $draft.metricsPort, format: .number.grouping(.never))
                TextField("Max request body (bytes)", value: $draft.maxRequestBodyBytes, format: .number)
                Toggle("Allow substitution over plain HTTP", isOn: $draft.allowPlainHTTP)
                if draft.allowPlainHTTP {
                    Text("Sentinels are then replaced in unencrypted requests, which anyone on the network path can read.")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
                Toggle("Require proxy authentication", isOn: $draft.requireAuth)
                Text("Each paired host signs in to the proxy with its own credentials, and login grants only work from the machine that requested them. Hosts running an asm CLI older than 0.8.0 can no longer use the proxy.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section {
                HStack {
                    Spacer()
                    if saving { ProgressView().controlSize(.small) }
                    Button("Revert") { draft = baseline }.disabled(!dirty || saving)
                    Button("Apply", action: apply).disabled(!dirty || saving).keyboardShortcut(.defaultAction)
                }
            }

            CertificateSection(path: model.proxyStatus.caPath, pem: model.proxyStatus.caPEM, expiry: model.proxyStatus.caExpiry)

            Section("Log (last 200 lines)") {
                ProxyLogView(lines: model.proxyLog)
            }
        }
        .formStyle(.grouped)
        .errorAlert($error)
        .onAppear { sync(model.proxySettings, force: true) }
        .onChange(of: model.proxySettings) { _, settings in sync(settings, force: false) }
        .task {
            macNames = await Task.detached(priority: .utility) { CoreBridge.hintSuggestions() }.value
        }
        .task {
            // The log and health change without observer events; poll while visible.
            while !Task.isCancelled {
                await model.refreshProxy()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func sync(_ settings: ProxySettingsItem, force: Bool) {
        if force || !dirty { draft = settings }
        baseline = settings
    }

    private func addHint(_ hint: String) {
        let hint = hint.trimmingCharacters(in: .whitespaces)
        guard !hint.isEmpty, !draft.hints.contains(hint) else { return }
        draft.hints.append(hint)
    }

    private func addTypedHint() {
        addHint(newHint)
        newHint = ""
    }

    private func apply() {
        saving = true
        let settings = draft
        Task {
            error = await model.saveProxySettings(settings)
            if error == nil { baseline = settings }
            saving = false
        }
    }
}

private struct ProxyStatusSection: View {
    let status: ProxyStatusItem
    let restart: () -> Void

    var body: some View {
        Section("Status") {
            LabeledContent("Proxy") {
                HStack(spacing: 6) {
                    Circle().fill(stateColor).frame(width: 8, height: 8)
                    Text(stateTitle)
                    if let pid = status.pid {
                        Text("pid \(pid)").foregroundStyle(.secondary).monospacedDigit()
                    }
                }
            }
            switch status.health {
            case let .down(reason, since):
                LabeledContent("Reason") {
                    Text(verbatim: reason).foregroundStyle(.red).textSelection(.enabled)
                }
                LabeledContent("Down since") { SinceText(date: since) }
            case let .unhealthy(since):
                LabeledContent("Not responding since") { SinceText(date: since) }
            case .running, .starting:
                if let error = status.error {
                    LabeledContent("Last error") {
                        Text(verbatim: error).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }
            if status.consecutiveFailures > 0 {
                LabeledContent("Failed starts") { Text("\(status.consecutiveFailures)").monospacedDigit() }
            }
            LabeledContent("Substituted fields") {
                Text(verbatim: status.suspendedLeases > 0
                    ? "\(status.activeEntries) (\(status.suspendedLeases) leases suspended: vault unavailable)"
                    : "\(status.activeEntries)")
            }
            LabeledContent("Last reload") {
                if let reload = status.lastReload {
                    Text(reload, format: .dateTime.month().day().hour().minute().second())
                } else {
                    Text("never").foregroundStyle(.secondary)
                }
            }
            LabeledContent("CA expires") {
                if let expiry = status.caExpiry {
                    Text(expiry, format: .dateTime.year().month().day())
                } else {
                    Text("unknown").foregroundStyle(.secondary)
                }
            }
            Button("Restart proxy", action: restart)
        }
    }

    private var stateTitle: LocalizedStringKey {
        switch status.health {
        case .running: "Running"
        case .starting: "Starting…"
        case .down: "Not running"
        case .unhealthy: "Not responding"
        }
    }

    private var stateColor: Color {
        switch status.health {
        case .running: .green
        case .starting: .orange
        case .down, .unhealthy: .red
        }
    }
}

/// Who can reach each listener, and whether the macOS Firewall lets them: bind intent and
/// firewall state of iron-proxy and the app, the fix command and Open Firewall Settings.
private struct NetworkAccessSection: View {
    let firewall: FirewallStatusItem
    let check: () async -> Void
    @State private var checking = false

    var body: some View {
        Section {
            LabeledContent("Proxy listens for") { Text(verbatim: firewall.proxy.intentTitle) }
            FirewallStateRow(title: "Firewall: iron-proxy", reach: firewall.proxy, checked: firewall.checkedAt != nil)
            LabeledContent("Manager API listens for") { Text(verbatim: firewall.api.intentTitle) }
            FirewallStateRow(title: "Firewall: Agents Secrets Manager", reach: firewall.api, checked: firewall.checkedAt != nil)
            if !firewall.fixCommands.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Allow incoming connections in System Settings → Network → Firewall → Options, or run in Terminal:")
                        .font(.callout)
                    ForEach(firewall.fixCommands, id: \.self) { CopyableCommand(command: $0) }
                }
            }
            HStack {
                Button("Open Firewall Settings") { ProxyAlerts.openFirewallSettings() }
                Button("Check again") {
                    checking = true
                    Task {
                        await check()
                        checking = false
                    }
                }
                .disabled(checking)
                if checking { ProgressView().controlSize(.small) }
            }
        } header: {
            Text("Network access")
        } footer: {
            Text("Listeners bound to a loopback address serve this Mac only. For the others, the macOS Firewall must allow incoming connections; asm only reads its settings and never changes them.")
        }
    }
}

private struct FirewallStateRow: View {
    let title: LocalizedStringKey
    let reach: ListenerReachItem
    let checked: Bool

    var body: some View {
        LabeledContent(title) {
            HStack(spacing: 6) {
                if let color { Circle().fill(color).frame(width: 8, height: 8) }
                Text(text)
                    .foregroundStyle(reach.blocked ? Color.red : color == nil ? Color.secondary : Color.primary)
                    .multilineTextAlignment(.trailing)
            }
            .help(Text(verbatim: reach.executable))
        }
    }

    private var text: LocalizedStringKey {
        guard reach.intentRemote else { return "Local only: firewall not involved" }
        guard checked else { return "Checking…" }
        return switch reach.state {
        case .allowed: "Allowed"
        case .blocked: "Blocked: other machines can't connect"
        case .blockAll: "Blocked: “Block all incoming connections” is on"
        case .firewallOff: "Firewall off"
        case .unknown: "Not decided yet: macOS will ask the first time another machine connects"
        }
    }

    private var color: Color? {
        guard reach.intentRemote, checked else { return nil }
        return switch reach.state {
        case .allowed, .firewallOff: .green
        case .blocked, .blockAll: .red
        case .unknown: nil
        }
    }
}

/// `Nov 17, 14:02:31 (3 min ago)`.
private struct SinceText: View {
    let date: Date

    var body: some View {
        HStack(spacing: 4) {
            Text(date, format: .dateTime.month().day().hour().minute().second())
            Text("(\(Text(date, style: .relative)) ago)").foregroundStyle(.secondary)
        }
        .monospacedDigit()
    }
}

private struct HintRow: View {
    let hint: String
    let canMoveUp: Bool
    let canMoveDown: Bool
    let move: (Int) -> Void
    let remove: () -> Void

    var body: some View {
        HStack {
            Text(verbatim: hint).monospaced()
            Spacer()
            Button { move(-1) } label: { Image(systemName: "arrow.up") }
                .buttonStyle(.borderless).disabled(!canMoveUp).help("Move up")
            Button { move(1) } label: { Image(systemName: "arrow.down") }
                .buttonStyle(.borderless).disabled(!canMoveDown).help("Move down")
            Button(action: remove) { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).help("Remove")
        }
    }
}

private struct CertificateSection: View {
    let path: String
    let pem: String
    let expiry: Date?

    var body: some View {
        Section {
            LabeledContent("Path") {
                Text(verbatim: path.isEmpty ? "not created yet" : path)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            HStack {
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
                .disabled(path.isEmpty)
                Button("Copy PEM") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(pem, forType: .string)
                }
                .disabled(pem.isEmpty)
            }
        } header: {
            Text("CA certificate")
        } footer: {
            Text("Agents trust this CA through asm proxy-env. Keep its key private: it can impersonate any HTTPS site to clients that trust it.")
        }
    }
}

private struct ProxyLogView: View {
    let lines: [String]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView([.vertical, .horizontal]) {
                Text(verbatim: lines.isEmpty ? "No log lines yet." : lines.joined(separator: "\n"))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                Color.clear.frame(height: 1).id("end")
            }
            .frame(height: 240)
            .onChange(of: lines) { proxy.scrollTo("end") }
        }
    }
}
