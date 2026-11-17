import AppKit
import SwiftUI
import UniformTypeIdentifiers

private struct GeneratorSheet: Identifiable {
    var generator: GeneratorItem?
    var id: String { generator?.id ?? "new" }
}

struct GeneratorsPane: View {
    let model: AppModel
    @State private var selection: String?
    @State private var sheet: GeneratorSheet?
    @State private var removing: GeneratorItem?
    @State private var error: String?

    private var selected: GeneratorItem? { model.generators.first { $0.id == selection } }

    var body: some View {
        VStack(spacing: 0) {
            if model.generators.isEmpty {
                EmptyStateLine(text: "No generators yet. Add one with +.")
            } else {
                Table(model.generators, selection: $selection) {
                    TableColumn("Name") { generator in Text(verbatim: generator.name) }
                    TableColumn("Provider") { _ in Text("GitHub App") }
                    TableColumn("Output") { _ in
                        Text(verbatim: "GH_TOKEN · GITHUB_TOKEN").font(.body.monospaced())
                    }
                    TableColumn("Status") { generator in
                        Label(generator.state.title, systemImage: generator.state == .ready ? "checkmark.circle" : "exclamationmark.triangle")
                            .help(generator.state.title)
                    }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let id = ids.first, let generator = model.generators.first(where: { $0.id == id }) {
                        Button("Edit…") { sheet = GeneratorSheet(generator: generator) }
                        Button("Remove…", role: .destructive) { removing = generator }
                    }
                } primaryAction: { ids in
                    if let id = ids.first, let generator = model.generators.first(where: { $0.id == id }) {
                        sheet = GeneratorSheet(generator: generator)
                    }
                }
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Menu {
                    Button("GitHub App…") { sheet = GeneratorSheet(generator: nil) }
                } label: {
                    Label("Add generator", systemImage: "plus")
                }
                Button {
                    if let selected { sheet = GeneratorSheet(generator: selected) }
                } label: { Label("Edit", systemImage: "pencil") }
                .disabled(selected == nil)
                Button { removing = selected } label: { Label("Remove", systemImage: "minus") }
                    .disabled(selected == nil)
            }
        }
        .sheet(item: $sheet) { sheet in GithubAppSheet(model: model, generator: sheet.generator) }
        .confirmationDialog(
            "Remove generator “\(removing?.name ?? "")”?",
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            presenting: removing
        ) { generator in
            Button("Remove", role: .destructive) {
                Task { error = await model.removeGenerator(generator.id) }
            }
        } message: { _ in
            Text("Its leases are invalidated and sentinels stop working. ASM attempts to revoke issued tokens; raw copies may remain usable until GitHub expiry if revocation fails.")
        }
        .errorAlert($error)
    }
}

private struct GithubAppSheet: View {
    let model: AppModel
    let generator: GeneratorItem?
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var clientID = ""
    @State private var installationID = ""
    @State private var privateKeyPEM = ""
    @State private var keyFileName: String?
    @State private var choosingKey = false
    @State private var importingKey = false
    @State private var installation: GithubInstallationItem?
    @State private var choices = GithubGrantItem(installationID: 0, repositories: [], permissions: [.init(name: "metadata", level: .read)])
    @State private var claims = GithubClaimsSelection()
    @State private var identityRevision: UInt64 = 0
    @State private var loaded = false
    @State private var connecting = false
    @State private var saving = false
    @State private var error: String?
    @State private var savedWarning: String?

    private var identityProblem: String? {
        if let problem = vaultNameProblem(name) { return problem }
        if clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Enter the GitHub App client ID." }
        if clientID.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0) }) {
            return "The client ID cannot contain whitespace or control characters."
        }
        if UInt64(installationID).map({ $0 > 0 }) != true { return "Enter a positive installation ID." }
        if generator == nil && privateKeyPEM.isEmpty { return "Import the app’s RSA private key PEM." }
        return nil
    }

    private var problem: String? {
        if let identityProblem { return identityProblem }
        if connecting || importingKey { return "Wait for the current operation." }
        if claims.repositoryIDs.isEmpty { return "Choose at least one repository after connecting." }
        if claims.repositoryIDs.count > 500 { return "Choose at most 500 repositories." }
        if claims.permissions["metadata"] != .read { return "Metadata read is required." }
        return nil
    }

    private var draft: GeneratorDraftItem {
        let id = UInt64(installationID) ?? 0
        var ceiling = claims.grant(within: choices)
        ceiling.installationID = id
        return GeneratorDraftItem(
            id: generator?.id, name: name.trimmingCharacters(in: .whitespaces),
            config: .githubApp(GithubAppConfigItem(clientID: clientID.trimmingCharacters(in: .whitespacesAndNewlines), installationID: id, ceiling: ceiling)),
            privateKeyPEM: privateKeyPEM
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("GitHub App generator") {
                    TextField("Name", text: $name)
                    LabeledContent("Outputs") { Text(verbatim: "GH_TOKEN · GITHUB_TOKEN").font(.body.monospaced()) }
                    Text("These names are aliases of one credential. The configuration name distinguishes apps.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Section {
                    TextField("Client ID", text: $clientID)
                    TextField("Installation ID", text: $installationID)
                    LabeledContent("RSA private key") {
                        HStack {
                            Text(keyFileName ?? (generator == nil ? "Not imported" : "Stored key retained"))
                                .foregroundStyle(.secondary)
                            Button("Import PEM…") { choosingKey = true }
                                .disabled(importingKey)
                        }
                    }
                    if !privateKeyPEM.isEmpty, generator != nil {
                        Button("Keep stored key") { privateKeyPEM = ""; keyFileName = nil }
                    }
                } header: { Text("Installation authentication") } footer: {
                    Text("Use the app’s RSA private key, not a client secret. The key is stored only in the manager’s login keychain and is never returned to hosts. Leaving the key unchanged retains the stored key.")
                }
                Section {
                    HStack {
                        Button(installation == nil ? "Connect" : "Reconnect", action: connect)
                            .disabled(identityProblem != nil || connecting || saving || importingKey)
                        if connecting { ProgressView().controlSize(.small).accessibilityLabel("Connecting to GitHub") }
                        if let installation {
                            Text("\(installation.accountLogin) · installation \(installation.installationID)")
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let warning = installation?.warning { Text(warning).font(.callout) }
                    if choices.repositories.isEmpty {
                        Text("Connect to discover repositories and permission levels. New installations start with no repositories selected.")
                            .foregroundStyle(.secondary)
                    } else {
                        GithubClaimsEditor(ceiling: choices, selection: $claims)
                    }
                } header: { Text("Maximum approved scope") } footer: {
                    Text("Choose 1–500 repositories. Metadata read is mandatory. New repositories require a configuration edit and new approval. Repository selection does not restrict organization, account, or enterprise permissions. Saving validates the configuration locally; every issuance verifies GitHub’s actual grant.")
                }
                if generator != nil {
                    Section {
                        Text("Changing authentication or scope invalidates this generator’s leases. Renaming it preserves existing grants.")
                    }
                }
                if let error {
                    Section("Error") { Text(error).foregroundStyle(.primary).textSelection(.enabled) }
                }
            }
            .formStyle(.grouped)
            .disabled(saving)
            SheetButtons(saveTitle: generator == nil ? "Add" : "Save", problem: problem, saving: saving, cancel: { dismiss() }, save: save)
        }
        .frame(minWidth: 560, idealWidth: 600, maxWidth: 760, minHeight: 500, idealHeight: 680)
        .onAppear(perform: load)
        .onChange(of: clientID) { _, _ in resetDiscovery() }
        .onChange(of: installationID) { _, _ in resetDiscovery() }
        .onChange(of: privateKeyPEM) { _, _ in resetDiscovery() }
        .fileImporter(isPresented: $choosingKey, allowedContentTypes: [.item]) { result in importKey(result) }
        .alert("Generator saved", isPresented: Binding(get: { savedWarning != nil }, set: { if !$0 { savedWarning = nil; dismiss() } })) {
            Button("OK") { savedWarning = nil; dismiss() }
        } message: { Text(savedWarning ?? "") }
    }

    private func load() {
        guard !loaded else { return }
        // onChange receives the completed initial configuration; initial loading is not a credential edit.
        if let generator {
            name = generator.name
            let config = generator.config.github
            clientID = config.clientID
            installationID = String(config.installationID)
            choices = config.ceiling
            claims.repositoryIDs = Set(config.ceiling.repositories.map(\.id))
            claims.permissions = Dictionary(config.ceiling.permissions.map { ($0.name, $0.level) }, uniquingKeysWith: { a, _ in a })
        }
        loaded = true
    }

    private func resetDiscovery() {
        guard loaded else { return }
        // Keep the initial edit scope until identity actually differs from its saved value.
        if identityRevision == 0, let generator {
            let config = generator.config.github
            if clientID == config.clientID, installationID == String(config.installationID), privateKeyPEM.isEmpty { return }
        }
        identityRevision &+= 1
        installation = nil
        choices = GithubGrantItem(installationID: UInt64(installationID) ?? 0, repositories: [], permissions: [.init(name: "metadata", level: .read)])
        claims = GithubClaimsSelection()
        error = nil
    }

    private func connect() {
        guard identityProblem == nil, !connecting else { return }
        connecting = true
        error = nil
        let revision = identityRevision
        var request = draft
        var config = request.config.github
        config.ceiling.repositories = []
        config.ceiling.permissions = [.init(name: "metadata", level: .read)]
        request.config = .githubApp(config)
        let captured = request
        Task {
            defer { connecting = false }
            do {
                let found = try await model.githubConnect(captured)
                guard identityRevision == revision else { return }
                installation = found
                choices = GithubGrantItem(installationID: found.installationID, repositories: found.repositories, permissions: found.permissions)
                claims.repositoryIDs.formIntersection(found.repositories.map(\.id))
                claims.permissions = claims.permissions.filter { name, level in
                    found.permissions.contains { $0.name == name && $0.allowedLevels.contains(level) }
                }
                claims.permissions["metadata"] = .read
            } catch {
                guard identityRevision == revision else { return }
                self.error = error.localizedDescription
            }
        }
    }

    private func importKey(_ result: Result<URL, Error>) {
        switch result {
        case let .failure(error): self.error = error.localizedDescription
        case let .success(url):
            importingKey = true
            Task {
                defer { importingKey = false }
                do {
                    let pem = try await Task.detached(priority: .userInitiated) {
                        let accessed = url.startAccessingSecurityScopedResource()
                        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                        guard size > 0, size <= 1_048_576 else { throw AppError(message: "Choose a PEM file smaller than 1 MiB.") }
                        let bytes = try Data(contentsOf: url)
                        guard let pem = String(data: bytes, encoding: .utf8) else { throw AppError(message: "The PEM file must be UTF-8 text.") }
                        return pem
                    }.value
                    privateKeyPEM = pem
                    keyFileName = url.lastPathComponent
                    error = nil
                } catch { self.error = error.localizedDescription }
            }
        }
    }

    private func save() {
        guard problem == nil, !saving else { return }
        saving = true
        error = nil
        let captured = draft
        Task {
            do {
                let saved = try await model.saveGenerator(captured)
                privateKeyPEM = ""
                if let warning = saved.warning { savedWarning = warning } else { dismiss() }
            } catch {
                self.error = error.localizedDescription
                saving = false
            }
        }
    }
}

/// Shared stable-ID scope controls for configuration ceilings and individual approvals.
struct GithubClaimsEditor: View {
    let ceiling: GithubGrantItem
    @Binding var selection: GithubClaimsSelection

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Repositories (\(selection.repositoryIDs.count) selected)").font(.subheadline.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            ForEach(ceiling.repositories) { repository in
                Toggle(isOn: $selection[repository: repository.id]) {
                    Text(verbatim: repository.fullName)
                }
                .accessibilityLabel(Text(verbatim: repository.fullName))
                .disabled(!selection.repositoryIDs.contains(repository.id) && selection.repositoryIDs.count >= 500)
                .help("Repository ID \(repository.id)")
            }
            Text("Permissions").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            ForEach(ceiling.permissions) { permission in
                GithubPermissionControl(permission: permission, level: $selection.permissions[permission.name])
            }
            Text("Repository selection does not restrict organization, account, or enterprise permissions.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct GithubPermissionControl: View {
    let permission: GithubPermissionItem
    @Binding var level: GithubPermissionLevel?

    var body: some View {
        if permission.name == "metadata" {
            LabeledContent("metadata") { Text("Read (required)") }
        } else {
            Picker(permission.scopeLabel, selection: $level) {
                Text("None").tag(Optional<GithubPermissionLevel>.none)
                ForEach(permission.allowedLevels, id: \.self) { option in
                    Text(option.rawValue).tag(Optional(option))
                }
            }
            .accessibilityLabel(permission.scopeLabel)
        }
    }
}
