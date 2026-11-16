import ServiceManagement
import SwiftUI

struct GeneralPane: View {
    let model: AppModel
    @State private var draft = GeneralSettingsItem()
    @State private var baseline = GeneralSettingsItem()
    @State private var confirmingAddress = false
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var launchNote: String?
    @State private var saving = false
    @State private var error: String?

    private static let lifetimes: [UInt64] = [120, 300, 600, 900, 1800, 3600]

    private var dirty: Bool { draft != baseline }
    private var addressChanged: Bool {
        draft.apiBindAddress != baseline.apiBindAddress || draft.apiPort != baseline.apiPort
    }

    var body: some View {
        Form {
            Section {
                TextField("Bind address", text: $draft.apiBindAddress)
                TextField("Port", value: $draft.apiPort, format: .number.grouping(.never))
            } header: {
                Text("Manager API")
            } footer: {
                Text("Paired hosts keep the address they paired with; after a change they must pair again.")
            }

            Section("Requests and leases") {
                Picker("Default lease duration", selection: Binding(
                    get: { draft.defaultLeaseSecs ?? 0 },
                    set: { draft.defaultLeaseSecs = $0 == 0 ? nil : $0 }
                )) {
                    ForEach(CoreBridge.leaseDurations) { option in
                        Text(option.title).tag(option.id)
                    }
                }
                Picker("Pending request lifetime", selection: $draft.pendingLifetimeSecs) {
                    ForEach(Set(Self.lifetimes + [draft.pendingLifetimeSecs]).sorted(), id: \.self) { secs in
                        Text("\(secs / 60) minutes").tag(secs)
                    }
                }
            }

            Section("Bitwarden") {
                TextField("bw path", text: $draft.bwPath, prompt: Text(verbatim: "/opt/homebrew/bin/bw"))
            }

            Section {
                HStack {
                    Spacer()
                    if saving { ProgressView().controlSize(.small) }
                    Button("Revert") { draft = baseline }.disabled(!dirty || saving)
                    Button("Apply") {
                        if addressChanged { confirmingAddress = true } else { apply() }
                    }
                    .disabled(!dirty || saving)
                    .keyboardShortcut(.defaultAction)
                }
            }

            Section("App") {
                Toggle("Launch at login", isOn: Binding(get: { launchAtLogin }, set: setLaunchAtLogin))
                if let launchNote {
                    Text(verbatim: launchNote).font(.callout).foregroundStyle(.secondary)
                }
                LabeledContent("API listening on") {
                    Text(verbatim: model.general.listeningOn).textSelection(.enabled)
                }
                LabeledContent("API certificate SHA-256") {
                    Text(verbatim: model.general.certSHA256)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .lineLimit(2)
                }
                LabeledContent("Version") {
                    Text(verbatim: versionLine).textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Change the manager API address?", isPresented: $confirmingAddress) {
            Button("Change address") { apply() }
        } message: {
            Text("Paired hosts keep using the old address and must pair again.")
        }
        .errorAlert($error)
        .onAppear { sync(model.general, force: true) }
        .onChange(of: model.general) { _, settings in sync(settings, force: false) }
    }

    private var versionLine: String {
        let app = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return model.general.version.isEmpty ? "\(app) (\(build))" : "\(app) (\(build)), core \(model.general.version)"
    }

    private func sync(_ settings: GeneralSettingsItem, force: Bool) {
        if force || !dirty { draft = settings }
        baseline = settings
    }

    private func apply() {
        saving = true
        let settings = draft
        Task {
            error = await model.saveGeneralSettings(settings)
            if error == nil { baseline = settings }
            saving = false
        }
    }

    private func setLaunchAtLogin(_ on: Bool) {
        let service = SMAppService.mainApp
        do {
            if on {
                try service.register()
            } else {
                try service.unregister()
            }
        } catch {
            self.error = error.localizedDescription
        }
        launchAtLogin = service.status == .enabled
        launchNote = service.status == .requiresApproval
            ? "Allow the app under System Settings → General → Login Items."
            : nil
    }
}
