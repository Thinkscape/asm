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
                            .help(generator.warning ?? generator.state.title)
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
    let savedConfig: GithubAppConfigItem?
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var clientID: String
    @State private var installations: [GithubGrantItem]
    @State private var verifiedAccounts: [UInt64: String] = [:]
    @State private var privateKeyPEM = ""
    @State private var keyFileName: String?
    @State private var choosingKey = false
    @State private var importingKey = false
    @State private var editingInstallation: GithubInstallationEdit?
    @State private var removingInstallation: GithubGrantItem?
    @State private var saving = false
    @State private var error: String?
    @State private var savedWarning: String?

    init(model: AppModel, generator: GeneratorItem?) {
        self.model = model
        self.generator = generator
        let savedConfig = generator?.config.github
        self.savedConfig = savedConfig
        _name = State(initialValue: generator?.name ?? "")
        _clientID = State(initialValue: savedConfig?.clientID ?? "")
        _installations = State(initialValue: savedConfig?.installations ?? [])
    }

    private var usingStoredAuthentication: Bool { clientID == savedConfig?.clientID && privateKeyPEM.isEmpty }

    private func canUse(_ installation: GithubGrantItem) -> Bool {
        verifiedAccounts[installation.id] != nil
            || (usingStoredAuthentication && savedConfig?.installations.contains(where: { $0.id == installation.id }) == true)
    }

    private var identityProblem: String? {
        if let problem = vaultNameProblem(name) { return problem }
        if clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Enter the GitHub App client ID." }
        if clientID.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0) }) {
            return "The client ID cannot contain whitespace or control characters."
        }
        if generator == nil && privateKeyPEM.isEmpty { return "Import the app’s RSA private key PEM." }
        return nil
    }

    private var problem: String? {
        if let identityProblem { return identityProblem }
        if importingKey { return "Wait for the key import to finish." }
        if installations.isEmpty { return "Add at least one verified installation." }
        if installations.contains(where: { !canUse($0) }) { return "Verify each installation with the current app credentials." }
        return nil
    }

    private func draft(installations: [GithubGrantItem]) -> GeneratorDraftItem {
        GeneratorDraftItem(
            id: generator?.id, name: name.trimmingCharacters(in: .whitespaces),
            config: .githubApp(GithubAppConfigItem(clientID: clientID, installations: installations)),
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
                } header: { Text("GitHub App authentication") } footer: {
                    Text("Use the app’s RSA private key, not a client secret. The key is stored only in the manager’s login keychain and is never returned to hosts. Leaving the key unchanged retains the stored key.")
                }
                GithubInstallationsSection(
                    installations: installations, accounts: verifiedAccounts, canUse: canUse,
                    authenticationReady: identityProblem == nil && !importingKey,
                    add: { editingInstallation = .add },
                    edit: { editingInstallation = .edit($0) },
                    remove: { removingInstallation = $0 }
                )
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
        .onChange(of: clientID) { _, _ in resetVerification() }
        .onChange(of: privateKeyPEM) { _, _ in resetVerification() }
        .fileImporter(isPresented: $choosingKey, allowedContentTypes: [.item]) { result in importKey(result) }
        .sheet(item: $editingInstallation) { edit in
            GithubInstallationEditor(
                model: model, discoveryDraft: draft(installations: []), existing: edit.grant,
                knownAccount: edit.grant.flatMap { verifiedAccounts[$0.id] },
                configuredIDs: Set(installations.map(\.id)),
                mustVerify: edit.grant.map { !canUse($0) } ?? true,
                apply: applyInstallation
            )
        }
        .confirmationDialog(
            "Remove installation?",
            isPresented: Binding(
                get: { removingInstallation != nil },
                set: { if !$0 { removingInstallation = nil } }
            ),
            presenting: removingInstallation
        ) { installation in
            Button("Remove Installation", role: .destructive) {
                installations.removeAll { $0.id == installation.id }
                verifiedAccounts.removeValue(forKey: installation.id)
            }
        } message: { installation in
            Text("Installation \(String(installation.id)) will be removed when you save. Saving scope changes invalidates this generator’s leases.")
        }
        .alert("Generator saved", isPresented: Binding(get: { savedWarning != nil }, set: { if !$0 { savedWarning = nil; dismiss() } })) {
            Button("OK") { savedWarning = nil; dismiss() }
        } message: { Text(savedWarning ?? "") }
    }

    private func resetVerification() {
        verifiedAccounts.removeAll()
        error = nil
    }

    private func applyInstallation(_ grant: GithubGrantItem, verifiedAccount: String?) {
        if let index = installations.firstIndex(where: { $0.id == grant.id }) {
            installations[index] = grant
        } else {
            installations.append(grant)
        }
        if let verifiedAccount { verifiedAccounts[grant.id] = verifiedAccount }
        error = nil
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
        let captured = draft(installations: installations)
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

private enum GithubInstallationEdit: Identifiable {
    case add
    case edit(GithubGrantItem)

    var id: UInt64? { grant?.id }

    var grant: GithubGrantItem? {
        if case let .edit(grant) = self { return grant }
        return nil
    }
}

private struct GithubInstallationsSection: View {
    let installations: [GithubGrantItem]
    let accounts: [UInt64: String]
    let canUse: (GithubGrantItem) -> Bool
    let authenticationReady: Bool
    let add: () -> Void
    let edit: (GithubGrantItem) -> Void
    let remove: (GithubGrantItem) -> Void

    var body: some View {
        Section {
            if installations.isEmpty {
                Text("Add an installation to choose its repository and permission limits.")
                    .foregroundStyle(.secondary)
            }
            ForEach(installations) { grant in
                let account = accounts[grant.id] ?? grant.repositoryOwner
                VStack(alignment: .leading, spacing: 8) {
                    DisclosureGroup {
                        GithubScopeSummary(grant: grant)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            GithubInstallationLabel(account: account, installationID: grant.id)
                            Text("Repositories: \(grant.repositories.count) · Permissions: \(grant.permissions.count)")
                                .font(.caption).foregroundStyle(.secondary)
                            if !canUse(grant) {
                                Text("Verify with the current credentials")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .accessibilityElement(children: .combine)
                    }
                    HStack {
                        Button("Edit Limits…") { edit(grant) }
                            .accessibilityLabel("Edit limits for installation \(String(grant.id))")
                            .disabled(!authenticationReady)
                        Button("Remove…", role: .destructive) { remove(grant) }
                            .accessibilityLabel("Remove installation \(String(grant.id))")
                    }
                }
            }
            Button("Add Installation…", action: add).disabled(!authenticationReady)
        } header: {
            Text("Installations")
        } footer: {
            Text("Each installation has separate limits. A token can use repositories and permissions from only one installation.")
        }
    }
}

private struct GithubInstallationLabel: View {
    let account: String?
    let installationID: UInt64

    var body: some View {
        if let account {
            Text("\(account) · installation \(String(installationID))")
        } else {
            Text("Installation \(String(installationID))")
        }
    }
}

private struct GithubInstallationEditor: View {
    private enum Operation { case list, verify }

    let model: AppModel
    let discoveryDraft: GeneratorDraftItem
    let existing: GithubGrantItem?
    let knownAccount: String?
    let configuredIDs: Set<UInt64>
    let mustVerify: Bool
    let apply: (GithubGrantItem, String?) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var choices: GithubGrantItem?
    @State private var claims: GithubClaimsSelection
    @State private var selectedID: UInt64?
    @State private var manualID = ""
    @State private var accounts: [GithubInstallationAccountItem]?
    @State private var verifiedAccount: String?
    @State private var operation: Operation?
    @State private var warning: String?
    @State private var error: String?
    @State private var limitsChanged = false

    init(
        model: AppModel, discoveryDraft: GeneratorDraftItem, existing: GithubGrantItem?,
        knownAccount: String?, configuredIDs: Set<UInt64>, mustVerify: Bool,
        apply: @escaping (GithubGrantItem, String?) -> Void
    ) {
        self.model = model
        self.discoveryDraft = discoveryDraft
        self.existing = existing
        self.knownAccount = knownAccount
        self.configuredIDs = configuredIDs
        self.mustVerify = mustVerify
        self.apply = apply
        _choices = State(initialValue: existing)
        _claims = State(initialValue: existing.map(GithubClaimsSelection.init(ceiling:)) ?? .init())
    }

    private var installationID: UInt64? {
        existing?.id ?? selectedID ?? UInt64(manualID.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private var idProblem: String? {
        guard let id = installationID, id > 0 else { return "Enter a positive installation ID or choose an account." }
        if existing == nil && configuredIDs.contains(id) { return "This installation is already configured." }
        return nil
    }

    private var problem: String? {
        if operation != nil { return "Wait for GitHub to respond." }
        if let idProblem { return idProblem }
        if choices?.id != installationID || (mustVerify && verifiedAccount == nil) {
            return "Verify this installation with GitHub."
        }
        if claims.repositoryIDs.isEmpty { return "Choose at least one repository." }
        if claims.repositoryIDs.count > GithubGrantItem.repositoryLimit {
            return "Choose at most \(GithubGrantItem.repositoryLimit) repositories."
        }
        if claims.permissions["metadata"] != .read { return "Metadata read is required." }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section(existing == nil ? "Add GitHub installation" : "Edit GitHub installation") {
                    if let existing {
                        GithubInstallationLabel(
                            account: verifiedAccount ?? knownAccount ?? existing.repositoryOwner,
                            installationID: existing.id
                        )
                    } else {
                        Button("Find Installations", action: listAccounts)
                        if let accounts {
                            if accounts.isEmpty {
                                Text("No additional GitHub installations found. You can still enter an installation ID.")
                                    .foregroundStyle(.secondary)
                            } else {
                                Picker("Installation account", selection: $selectedID) {
                                    Text("Enter ID manually").tag(Optional<UInt64>.none)
                                    ForEach(accounts) { account in
                                        Text("\(account.account) · installation \(String(account.id))").tag(Optional(account.id))
                                    }
                                }
                            }
                        }
                        if selectedID == nil { TextField("Installation ID", text: $manualID) }
                    }
                    HStack {
                        Button("Verify with GitHub", action: verify).disabled(idProblem != nil)
                        if let operation {
                            ProgressView().controlSize(.small)
                                .accessibilityLabel(operation == .list ? "Finding GitHub installations" : "Verifying GitHub installation")
                        } else if let verifiedAccount, existing == nil, let installationID {
                            GithubInstallationLabel(account: verifiedAccount, installationID: installationID)
                        } else if verifiedAccount != nil {
                            Text("Verified").foregroundStyle(.secondary)
                        }
                    }
                    if let warning { Text(warning).font(.callout) }
                }
                Section("Maximum approved scope") {
                    if limitsChanged {
                        Text("GitHub no longer allows some previously selected limits. Review the remaining selection before applying.")
                            .font(.callout)
                    }
                    if let choices, choices.id == installationID {
                        if choices.repositories.isEmpty {
                            Text("No repositories are available for this installation.")
                        } else {
                            GithubClaimsEditor(ceiling: choices, selection: $claims)
                                .disabled(mustVerify && verifiedAccount == nil)
                        }
                    } else {
                        Text("Verify the installation to discover its repositories and permissions.")
                            .foregroundStyle(.secondary)
                    }
                }
                if let error {
                    Section("Error") { Text(error).textSelection(.enabled) }
                }
            }
            .formStyle(.grouped)
            .disabled(operation != nil)
            SheetButtons(
                saveTitle: existing == nil ? "Add Installation" : "Apply Limits",
                problem: problem, saving: false, cancel: { dismiss() }, save: commitLimits
            )
        }
        .frame(minWidth: 500, idealWidth: 560, minHeight: 440, idealHeight: 580)
        .onChange(of: installationID) { _, _ in
            choices = nil
            claims = GithubClaimsSelection()
            verifiedAccount = nil
            limitsChanged = false
            warning = nil
            error = nil
        }
    }

    private func listAccounts() {
        guard operation == nil else { return }
        operation = .list
        error = nil
        Task {
            defer { operation = nil }
            do {
                let found = try await model.githubListInstallations(discoveryDraft)
                let additional = found.filter { !configuredIDs.contains($0.id) }
                accounts = additional
                if let selectedID, !additional.contains(where: { $0.id == selectedID }) {
                    self.selectedID = nil
                }
            } catch { self.error = error.localizedDescription }
        }
    }

    private func verify() {
        guard operation == nil, idProblem == nil, let installationID else { return }
        var config = discoveryDraft.config.github
        config.installations = [GithubGrantItem(installationID: installationID, repositories: [], permissions: [])]
        var draft = discoveryDraft
        draft.config = .githubApp(config)
        operation = .verify
        error = nil
        verifiedAccount = nil
        warning = nil
        Task {
            defer { operation = nil }
            do {
                let found = try await model.githubConnect(draft)
                guard self.installationID == installationID else { return }
                guard found.installationID == installationID else {
                    throw AppError(message: "GitHub returned a different installation ID.")
                }
                let previous = claims
                choices = GithubGrantItem(installationID: found.installationID, repositories: found.repositories, permissions: found.permissions)
                claims.repositoryIDs.formIntersection(found.repositories.lazy.map(\.id))
                claims.permissions = claims.permissions.filter { name, level in
                    found.permissions.contains { $0.name == name && $0.allowedLevels.contains(level) }
                }
                claims.permissions["metadata"] = .read
                limitsChanged = limitsChanged || previous != claims
                verifiedAccount = found.accountLogin
                warning = found.warning
            } catch { self.error = error.localizedDescription }
        }
    }

    private func commitLimits() {
        guard problem == nil, let choices else { return }
        apply(claims.grant(within: choices), verifiedAccount)
        dismiss()
    }
}

struct GithubScopeSummary: View {
    let grant: GithubGrantItem

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Repositories").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            ForEach(grant.repositories) { repository in
                Text(verbatim: repository.fullName).font(.callout).textSelection(.enabled)
            }
            Text("Permissions").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            ForEach(grant.permissions) { permission in
                Text("\(permission.scopeLabel): \(permission.level.rawValue)").font(.callout)
            }
            Text("Repository selection does not restrict organization, account, or enterprise permissions.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Stable-ID controls for editing a single installation’s ceiling.
private struct GithubClaimsEditor: View {
    let ceiling: GithubGrantItem
    @Binding var selection: GithubClaimsSelection

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            let selected = selection.repositoryIDs.count
            let exceedsLimit = ceiling.repositories.count > GithubGrantItem.repositoryLimit
            let clearSelection = selected == ceiling.repositories.count || exceedsLimit
            HStack {
                Text("Repositories (\(selected) selected)").font(.subheadline.weight(.semibold))
                    .accessibilityAddTraits(.isHeader)
                Spacer()
                Button(clearSelection ? "Deselect all" : "Select all") {
                    if clearSelection {
                        selection.repositoryIDs.removeAll()
                    } else {
                        selection.repositoryIDs = Set(ceiling.repositories.lazy.map(\.id))
                    }
                }
                .disabled(ceiling.repositories.isEmpty || (exceedsLimit && selected == 0))
            }
            if exceedsLimit {
                Text("Choose up to \(GithubGrantItem.repositoryLimit) repositories individually.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(ceiling.repositories) { repository in
                Toggle(isOn: $selection[repository: repository.id]) {
                    Text(verbatim: repository.fullName)
                }
                .accessibilityLabel(Text(verbatim: repository.fullName))
                .disabled(!selection.repositoryIDs.contains(repository.id) && selected >= GithubGrantItem.repositoryLimit)
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
