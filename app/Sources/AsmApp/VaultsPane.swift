import SwiftUI
import UniformTypeIdentifiers

private enum VaultSheet: Identifiable {
    case bitwarden(VaultItem?)
    case envFile(VaultItem?)
    case keychain(VaultItem?)

    var id: String {
        switch self {
        case let .bitwarden(vault): "bw-\(vault?.id ?? "new")"
        case let .envFile(vault): "env-\(vault?.id ?? "new")"
        case let .keychain(vault): "kc-\(vault?.id ?? "new")"
        }
    }
}

struct VaultsPane: View {
    let model: AppModel
    @State private var selection: String?
    @State private var sheet: VaultSheet?
    @State private var removing: VaultItem?
    @State private var error: String?

    private var hasKeychain: Bool { model.vaults.contains { $0.kind == .keychain } }

    var body: some View {
        VStack(spacing: 0) {
            if model.vaults.isEmpty {
                EmptyStateLine(text: "No vaults yet. Add a Bitwarden vault, a .env file or the macOS Keychain with +.")
            } else {
                Table(model.vaults, selection: $selection) {
                    TableColumn("Name") { vault in Text(verbatim: vault.name) }
                    TableColumn("Kind") { vault in Text(vault.kind.title) }
                    TableColumn("Status") { vault in VaultStatusCell(state: vault.state) }
                    TableColumn("Secrets") { vault in
                        Text(verbatim: vault.secretCount.map(String.init) ?? "–").monospacedDigit()
                    }
                    .width(60)
                    TableColumn("Note") { vault in
                        Text(verbatim: vault.note ?? "")
                            .foregroundStyle(.secondary)
                            .help(Text(verbatim: vault.note ?? ""))
                    }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let id = ids.first, let vault = model.vaults.first(where: { $0.id == id }) {
                        Button("Edit…") { edit(vault) }
                        if vault.kind == .bitwarden {
                            Button("Sync now") { sync(vault.id) }
                        }
                        Button("Remove…", role: .destructive) { removing = vault }
                    }
                } primaryAction: { ids in
                    if let id = ids.first, let vault = model.vaults.first(where: { $0.id == id }) { edit(vault) }
                }
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Menu {
                    Button("Bitwarden…") { sheet = .bitwarden(nil) }
                    Button(".env file…") { sheet = .envFile(nil) }
                    Button("macOS Keychain") { sheet = .keychain(nil) }.disabled(hasKeychain)
                } label: {
                    Label("Add vault", systemImage: "plus")
                }
                Button {
                    if let vault = selectedVault { edit(vault) }
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .disabled(selectedVault == nil)
                Button {
                    removing = selectedVault
                } label: {
                    Label("Remove", systemImage: "minus")
                }
                .disabled(selectedVault == nil)
            }
        }
        .sheet(item: $sheet) { sheet in
            switch sheet {
            case let .bitwarden(vault): BitwardenSheet(model: model, vault: vault)
            case let .envFile(vault): EnvFileSheet(model: model, vault: vault)
            case let .keychain(vault): KeychainSheet(model: model, vault: vault)
            }
        }
        .confirmationDialog(
            "Remove vault “\(removing?.name ?? "")”?",
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            presenting: removing
        ) { vault in
            Button("Remove", role: .destructive) {
                Task { error = await model.removeVault(vault.id) }
            }
        } message: { _ in
            Text("Its secrets disappear from every host; its leases stop working.")
        }
        .errorAlert($error)
    }

    private var selectedVault: VaultItem? {
        model.vaults.first { $0.id == selection }
    }

    private func edit(_ vault: VaultItem) {
        switch vault.kind {
        case .bitwarden: sheet = .bitwarden(vault)
        case .envFile: sheet = .envFile(vault)
        case .keychain: sheet = .keychain(vault)
        }
    }

    private func sync(_ id: String) {
        Task { error = await model.syncVault(id) }
    }
}

private struct VaultStatusCell: View {
    let state: VaultState

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon).foregroundStyle(color)
            Text(verbatim: state.title).lineLimit(1).truncationMode(.tail)
        }
        .help(Text(verbatim: state.title))
    }

    private var icon: String {
        switch state {
        case .ready: "checkmark.circle.fill"
        case .locked: "lock.fill"
        case .error: "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        switch state {
        case .ready: .green
        case .locked: .orange
        case .error: .red
        }
    }
}

/// Vault names: 1–64 characters, no `/` (plan step 4).
private func vaultNameProblem(_ name: String) -> String? {
    let trimmed = name.trimmingCharacters(in: .whitespaces)
    if trimmed.isEmpty { return "Enter a name." }
    if trimmed.count > 64 { return "Names have at most 64 characters." }
    if trimmed.contains("/") { return "Names cannot contain “/”." }
    return nil
}

// MARK: - Bitwarden

private struct BitwardenSheet: View {
    let model: AppModel
    let vault: VaultItem?
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var config = BitwardenConfig()
    @State private var clientSecret = ""
    @State private var masterPassword = ""
    @State private var collections: [CollectionItem] = []
    @State private var selected: Set<String> = []
    @State private var connecting = false
    @State private var connected = false
    @State private var error: String?
    @State private var saving = false
    @State private var loaded = false

    private var isNew: Bool { vault == nil }

    private var draft: VaultDraftItem {
        var config = config
        config.collectionIDs = collections.isEmpty ? config.collectionIDs : collections.map(\.id).filter(selected.contains)
        return .bitwarden(id: vault?.id, name: name.trimmingCharacters(in: .whitespaces), config: config, clientSecret: clientSecret, masterPassword: masterPassword)
    }

    private var problem: String? {
        if let problem = vaultNameProblem(name) { return problem }
        if config.serverURL.isEmpty || config.email.isEmpty || config.clientID.isEmpty { return "Fill in the server URL, email and client id." }
        if isNew && (clientSecret.isEmpty || masterPassword.isEmpty) { return "Enter the client secret and master password." }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Vault") {
                    TextField("Name", text: $name)
                    TextField("Server URL", text: $config.serverURL, prompt: Text(verbatim: "https://vault.bitwarden.com"))
                    TextField("Email", text: $config.email)
                }
                Section {
                    TextField("Client id", text: $config.clientID, prompt: Text(verbatim: "user.…"))
                    SecureField("Client secret", text: $clientSecret, prompt: Text(isNew ? "Required" : "Unchanged"))
                    SecureField("Master password", text: $masterPassword, prompt: Text(isNew ? "Required" : "Unchanged"))
                } header: {
                    Text("Personal API key")
                } footer: {
                    Text("Stored in the login keychain. Find the API key under Settings → Security → Keys in the Bitwarden web vault.")
                }
                Section("Command-line tool") {
                    TextField("bw path", text: $config.bwPath, prompt: Text(verbatim: model.general.bwPath.isEmpty ? "/opt/homebrew/bin/bw" : model.general.bwPath))
                }
                Section {
                    HStack {
                        Button(connected ? "Reconnect" : "Connect", action: connect)
                            .disabled(connecting || problem != nil)
                        if let vault {
                            Button("Sync now") {
                                Task { error = await model.syncVault(vault.id) }
                            }
                        }
                        if connecting { ProgressView().controlSize(.small) }
                    }
                    if collections.isEmpty {
                        Text(connected ? "This account has no collections." : "Connect to list the collections.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(collections) { collection in
                            Toggle(isOn: Binding(
                                get: { selected.contains(collection.id) },
                                set: { on in if on { selected.insert(collection.id) } else { selected.remove(collection.id) } }
                            )) {
                                Text(verbatim: collection.name)
                            }
                        }
                    }
                    Toggle("Expose items without an organization (personal vault)", isOn: $config.exposePersonal)
                } header: {
                    Text("Exposed items")
                } footer: {
                    Text("Only items in the checked collections are listed to paired hosts.")
                }
                if let error {
                    Section("bw error") {
                        Text(verbatim: error).foregroundStyle(.red).textSelection(.enabled).font(.callout.monospaced())
                    }
                }
            }
            .formStyle(.grouped)
            SheetButtons(saveTitle: isNew ? "Add" : "Save", problem: problem, saving: saving, cancel: { dismiss() }, save: save)
        }
        .frame(width: 520, height: 640)
        .onAppear(perform: load)
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let vault, case let .bitwarden(existing) = vault.config else { return }
        name = vault.name
        config = existing
        selected = Set(existing.collectionIDs)
        connect()
    }

    private func connect() {
        connecting = true
        error = nil
        let draft = draft
        Task {
            do {
                collections = try await model.connectBitwarden(draft)
                connected = true
            } catch {
                self.error = error.localizedDescription
            }
            connecting = false
        }
    }

    private func save() {
        saving = true
        let draft = draft
        Task {
            if let failure = await model.saveVault(draft) {
                error = failure
                saving = false
            } else {
                dismiss()
            }
        }
    }
}

// MARK: - .env

private struct EnvFileSheet: View {
    let model: AppModel
    let vault: VaultItem?
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var path = ""
    @State private var choosing = false
    @State private var error: String?
    @State private var saving = false
    @State private var loaded = false

    private var problem: String? {
        if let problem = vaultNameProblem(name) { return problem }
        if path.isEmpty { return "Choose a file." }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $name)
                    LabeledContent("File") {
                        HStack {
                            Text(verbatim: path.isEmpty ? "None" : path)
                                .foregroundStyle(path.isEmpty ? .secondary : .primary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Button("Choose…") { choosing = true }
                        }
                    }
                } footer: {
                    Text("Every key with a non-empty value in this file is exposed to paired hosts. Lines that are not simple KEY=value assignments are skipped.")
                }
                if let error {
                    Text(verbatim: error).foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            SheetButtons(saveTitle: vault == nil ? "Add" : "Save", problem: problem, saving: saving, cancel: { dismiss() }, save: save)
        }
        .frame(width: 520, height: 300)
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.item]) { result in
            switch result {
            case let .success(url):
                path = url.path(percentEncoded: false)
                if name.isEmpty { name = url.deletingPathExtension().lastPathComponent.trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
            case let .failure(failure):
                error = failure.localizedDescription
            }
        }
        .fileDialogBrowserOptions([.includeHiddenFiles])
        .onAppear {
            guard !loaded else { return }
            loaded = true
            if let vault, case let .envFile(existing) = vault.config {
                name = vault.name
                path = existing
            }
        }
    }

    private func save() {
        saving = true
        let draft = VaultDraftItem.envFile(id: vault?.id, name: name.trimmingCharacters(in: .whitespaces), path: path)
        Task {
            if let failure = await model.saveVault(draft) {
                error = failure
                saving = false
            } else {
                dismiss()
            }
        }
    }
}

// MARK: - Keychain

private struct KeychainSheet: View {
    let model: AppModel
    let vault: VaultItem?
    @Environment(\.dismiss) private var dismiss

    @State private var name = "Keychain"
    @State private var error: String?
    @State private var saving = false
    @State private var loaded = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $name)
                } footer: {
                    Text("All passwords and secure notes of the login keychain are exposed to paired hosts. iCloud Keychain items are not readable. macOS may ask for permission when a value is first read.")
                }
                if let error {
                    Text(verbatim: error).foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            SheetButtons(saveTitle: vault == nil ? "Add" : "Save", problem: vaultNameProblem(name), saving: saving, cancel: { dismiss() }, save: save)
        }
        .frame(width: 520, height: 260)
        .onAppear {
            guard !loaded else { return }
            loaded = true
            if let vault { name = vault.name }
        }
    }

    private func save() {
        saving = true
        let draft = VaultDraftItem.keychain(id: vault?.id, name: name.trimmingCharacters(in: .whitespaces))
        Task {
            if let failure = await model.saveVault(draft) {
                error = failure
                saving = false
            } else {
                dismiss()
            }
        }
    }
}

/// Cancel / Save row at the bottom of a sheet; shows why saving is not possible yet.
struct SheetButtons: View {
    let saveTitle: LocalizedStringKey
    let problem: String?
    let saving: Bool
    let cancel: () -> Void
    let save: () -> Void

    var body: some View {
        HStack {
            if let problem {
                Text(verbatim: problem).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if saving { ProgressView().controlSize(.small) }
            Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
            Button(saveTitle, action: save)
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil || saving)
        }
        .padding()
    }
}
