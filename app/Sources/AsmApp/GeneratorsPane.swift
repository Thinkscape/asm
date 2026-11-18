import AppKit
import SwiftUI
import UniformTypeIdentifiers

private enum GeneratorSheet: Identifiable {
    case addGithubApp
    case addGcloudConnection
    case edit(GeneratorItem)

    var id: String {
        switch self {
        case .addGithubApp: "new-github"
        case .addGcloudConnection: "new-gcloud"
        case let .edit(generator): generator.id
        }
    }
}

struct GeneratorsPane: View {
    let model: AppModel
    @State private var section: Section = .generators

    private enum Section: Hashable {
        case generators, serviceAccounts
    }

    private var showsServiceAccounts: Bool {
        model.hasRecordedGcloudAccounts || model.generators.contains { $0.config.isGoogleCloud }
    }

    var body: some View {
        VStack(spacing: 0) {
            if showsServiceAccounts && section == .serviceAccounts {
                // Keep the ledger's wrapped header and footer from setting the split
                // view's minimum height during AppKit's narrow fitting-size probe.
                GeometryReader { viewport in
                    GcloudOwnedAccountsPane(model: model)
                        .frame(width: viewport.size.width, height: viewport.size.height)
                }
            } else {
                GeneratorListPane(model: model)
            }
        }
        .toolbar {
            if showsServiceAccounts {
                ToolbarItem(placement: .principal) {
                    Picker("Generator settings", selection: $section) {
                        Text("Generators").tag(Section.generators)
                        Text("Google Service Accounts").tag(Section.serviceAccounts)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                }
            }
        }
        .onChange(of: showsServiceAccounts) { _, visible in
            if !visible { section = .generators }
        }
    }
}

private struct GeneratorListPane: View {
    let model: AppModel
    @Environment(\.openURL) private var openURL
    @State private var selection: String?
    @State private var sheet: GeneratorSheet?
    @State private var removing: GeneratorItem?
    @State private var error: String?

    private var selected: GeneratorItem? { model.generators.first { $0.id == selection } }

    private var selectedIsLegacyGcloud: Bool {
        guard let selected, case .gcloud = selected.config else { return false }
        return true
    }

    var body: some View {
        VStack(spacing: 0) {
            if model.generators.isEmpty {
                EmptyStateLine(text: "No generators yet. Add one with +.")
            } else {
                Table(model.generators, selection: $selection) {
                    TableColumn("Name") { generator in Text(verbatim: generator.name) }
                    TableColumn("Provider") { generator in Text(generator.config.providerName) }
                    TableColumn("Output") { generator in
                        let output = switch generator.config {
                        case .githubApp: "\(generator.config.outputName) · GITHUB_TOKEN"
                        case .gcloud, .gcloudConnection: generator.config.outputName
                        }
                        Text(verbatim: output).font(.body.monospaced()).help(output)
                    }
                    .width(min: 150, ideal: 245)
                    TableColumn("Status") { generator in
                        Label(generator.state.title, systemImage: generator.state == .ready ? "checkmark.circle" : "exclamationmark.triangle")
                            .help(generator.warning ?? generator.state.title)
                    }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let id = ids.first, let generator = model.generators.first(where: { $0.id == id }) {
                        if case .gcloud = generator.config {
                            Button("Details…") { sheet = .edit(generator) }
                        } else {
                            Button("Edit…") { sheet = .edit(generator) }
                        }
                        Button("Remove…", role: .destructive) { removing = generator }
                    }
                } primaryAction: { ids in
                    if let id = ids.first, let generator = model.generators.first(where: { $0.id == id }) {
                        sheet = .edit(generator)
                    }
                }
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Menu {
                    Button("GitHub App…") { sheet = .addGithubApp }
                    Button("Google Cloud…") { sheet = .addGcloudConnection }
                } label: {
                    Label("Add generator", systemImage: "plus")
                }
                Button {
                    if let selected { sheet = .edit(selected) }
                } label: {
                    Label(
                        selectedIsLegacyGcloud ? "Details" : "Edit",
                        systemImage: selectedIsLegacyGcloud ? "info.circle" : "pencil"
                    )
                }
                .disabled(selected == nil)
                Button { removing = selected } label: { Label("Remove", systemImage: "minus") }
                    .disabled(selected == nil)
            }
        }
        .sheet(item: $sheet) { sheet in
            switch sheet {
            case .addGithubApp:
                GithubAppSheet(model: model, generator: nil, savedConfig: nil)
            case .addGcloudConnection:
                GcloudGeneratorSheet(model: model)
            case let .edit(generator):
                switch generator.config {
                case let .githubApp(config):
                    GithubAppSheet(model: model, generator: generator, savedConfig: config)
                case let .gcloud(config):
                    GcloudLegacyGeneratorSheet(generator: generator, config: config)
                case let .gcloudConnection(config):
                    GcloudGeneratorSheet(model: model, editing: (generator, config))
                }
            }
        }
        .confirmationDialog(
            "Remove generator “\(removing?.name ?? "")”?",
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            presenting: removing
        ) { generator in
            Button("Remove", role: .destructive) {
                Task { error = await model.removeGenerator(generator.id) }
            }
            if generator.config.isGoogleCloud {
                Button("Google account permissions…") { openURL(GcloudGeneratorSheet.accountPermissionsURL) }
            }
        } message: { generator in
            switch generator.config {
            case .githubApp:
                Text("Its leases are invalidated and sentinels stop working. ASM attempts to revoke issued tokens; raw copies may remain usable until GitHub expiry if revocation fails.")
            case .gcloud:
                Text("This removes the saved sign-in from ASM and ends its leases. Google consent, the bound service account, and IAM grants are unchanged. Google access tokens cannot be individually revoked; issued copies remain usable until they expire.")
            case .gcloudConnection:
                Text("This removes the saved sign-in from ASM and ends its leases. Google consent, provisioned service accounts, and IAM bindings remain. Find those accounts under Google Service Accounts in Generators. Google access tokens cannot be individually revoked; issued copies remain usable until they expire.")
            }
        }
        .errorAlert($error)
    }
}

private extension GeneratorConfigItem {
    var isGoogleCloud: Bool {
        switch self {
        case .gcloud, .gcloudConnection: true
        case .githubApp: false
        }
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

    init(model: AppModel, generator: GeneratorItem?, savedConfig: GithubAppConfigItem?) {
        self.model = model
        self.generator = generator
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
        let config = GithubAppConfigItem(clientID: clientID, installations: installations)
        return GeneratorDraftItem(
            id: generator?.id, name: name.trimmingCharacters(in: .whitespaces),
            config: .githubApp(config),
            credentials: privateKeyPEM.isEmpty ? .keep : .githubPrivateKey(pem: privateKeyPEM)
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
                let label = GithubInstallationLabel(account: account, installationID: grant.id)
                VStack(alignment: .leading, spacing: 8) {
                    DisclosureGroup {
                        GrantScopeSummary(grant: grant)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            label
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
        if claims.repositoryIDs.count > GithubClaimsEditor.repositoryLimit { return "Choose at most \(GithubClaimsEditor.repositoryLimit) repositories." }
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
                            GithubClaimsEditor(ceiling: choices, selection: $claims, allowsBulkRepositorySelection: true)
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
                accounts = found.filter { !configuredIDs.contains($0.id) }
                if let selectedID, accounts?.contains(where: { $0.id == selectedID }) != true {
                    self.selectedID = nil
                }
            } catch { self.error = error.localizedDescription }
        }
    }

    private func verify() {
        guard operation == nil, idProblem == nil, let installationID,
              case var .githubApp(config) = discoveryDraft.config else { return }
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
                claims.repositoryIDs.formIntersection(found.repositories.map(\.id))
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

struct ScopeSummaryHeading: View {
    let title: LocalizedStringKey

    init(_ title: LocalizedStringKey) {
        self.title = title
    }

    var body: some View {
        Text(title).font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
    }
}

struct GrantScopeSummary: View {
    let grant: GithubGrantItem

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ScopeSummaryHeading("Repositories")
            ForEach(grant.repositories) { repository in
                resource(repository.fullName)
            }
            ScopeSummaryHeading("Permissions")
            ForEach(grant.permissions) { permission in
                permissionRow(Text(verbatim: permission.scopeLabel), level: Text(verbatim: permission.level.rawValue))
            }
            Text("Repository selection does not restrict organization, account, or enterprise permissions.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func resource(_ name: String) -> some View {
        Text(verbatim: name).font(.callout).textSelection(.enabled)
    }

    private func permissionRow(_ name: Text, level: Text) -> some View {
        Text("\(name): \(level)").font(.callout)
    }
}

/// Shared controls for editing a single installation’s ceiling or an individual grant.
struct GithubClaimsEditor: View {
    static let repositoryLimit = 500

    let ceiling: GithubGrantItem?
    @Binding var selection: GithubClaimsSelection
    var request: GithubScopeRequestItem? = nil
    var allowsBulkRepositorySelection = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GithubRepositoryClaims(
                repositories: ceiling?.repositories, requested: request?.repositories ?? [],
                allowsBulkSelection: allowsBulkRepositorySelection, selection: $selection
            )
            GithubPermissionClaims(
                permissions: ceiling?.permissions, requested: request?.effectivePermissions ?? [], levels: $selection.permissions
            )
            if ceiling != nil {
                Text("Repository selection does not restrict organization, account, or enterprise permissions.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct GithubRepositoryClaims: View {
    let repositories: [GithubRepositoryItem]?
    let requested: [String]
    let allowsBulkSelection: Bool
    @Binding var selection: GithubClaimsSelection

    var body: some View {
        if let repositories {
            let match = GithubRequestedRepositories(requested, in: repositories)
            let selected = selection.repositoryIDs.count
            let limit = GithubClaimsEditor.repositoryLimit
            let exceedsLimit = repositories.count > limit
            let clearSelection = selected == repositories.count || exceedsLimit
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SectionLabel("Repositories (\(selected) selected)").accessibilityAddTraits(.isHeader)
                    if allowsBulkSelection {
                        Spacer()
                        Button(clearSelection ? "Deselect all" : "Select all") {
                            if clearSelection {
                                selection.repositoryIDs.removeAll()
                            } else {
                                selection.repositoryIDs = Set(repositories.lazy.map(\.id))
                            }
                        }
                        .disabled(repositories.isEmpty || (exceedsLimit && selected == 0))
                    }
                }
                if exceedsLimit {
                    Text("Choose up to \(limit) repositories individually.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(repositories) { repository in
                    let label = if match.matchedIDs.contains(repository.id) {
                        Text("\(repository.fullName) (requested)", comment: "The placeholder is the GitHub repository requested by the client.")
                    } else if match.ambiguousIDs.contains(repository.id) {
                        Text("\(repository.fullName) · ID \(String(repository.id))", comment: "An ambiguous GitHub repository name disambiguated by its stable numeric ID.")
                    } else {
                        Text(verbatim: repository.fullName)
                    }
                    Toggle(isOn: $selection[repository: repository.id]) { label }
                        .fixedSize(horizontal: false, vertical: true)
                        .disabled(selected >= limit && !selection.repositoryIDs.contains(repository.id))
                        .help("Repository ID \(repository.id)")
                }
                ForEach(match.unavailable) { repository in
                    let label = repository.ambiguous
                        ? Text("\(repository.name) (requested) (ambiguous)", comment: "The requested GitHub repository name matches multiple repositories.")
                        : Text("\(repository.name) (requested) (unavailable)", comment: "The requested GitHub repository is outside the selected installation’s limits.")
                    Toggle(isOn: .constant(false)) { label }
                        .fixedSize(horizontal: false, vertical: true)
                        .disabled(true)
                }
            }
        } else if !requested.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel("Requested repositories").accessibilityAddTraits(.isHeader)
                ForEach(requested, id: \.self) { name in
                    Text(verbatim: name).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

private struct GithubPermissionClaims: View {
    let permissions: [GithubPermissionItem]?
    let requested: [GithubPermissionItem]
    @Binding var levels: [String: GithubPermissionLevel]

    var body: some View {
        if let permissions {
            let requestedLevels = Dictionary(requested.lazy.map { ($0.name, $0.level) }, uniquingKeysWith: { first, _ in first })
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel("Permissions").accessibilityAddTraits(.isHeader)
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                    ForEach(permissions) { permission in
                        GridRow {
                            if permission.name == "metadata" {
                                Text("metadata")
                                let required = String(localized: "Read (required)")
                                PermissionLevelPicker(label: "metadata", options: [required], requested: nil,
                                                      allowsNone: false, level: .constant(required))
                                    .disabled(true)
                            } else {
                                let requestedLevel = requestedLevels[permission.name]
                                GithubPermissionLabel(
                                    name: permission.scopeLabel,
                                    unavailableLevel: requestedLevel.flatMap { permission.permits($0) ? nil : $0 }
                                )
                                PermissionLevelPicker(
                                    label: permission.scopeLabel, options: permission.allowedLevels.map(\.rawValue),
                                    requested: requestedLevel?.rawValue,
                                    level: Binding(get: { levels[permission.name]?.rawValue }, set: { raw in
                                        levels[permission.name] = raw.flatMap(GithubPermissionLevel.init(rawValue:))
                                    })
                                )
                            }
                        }
                    }
                    if !requested.isEmpty {
                        let availableNames = Set(permissions.lazy.map(\.name))
                        let unavailable = requested.filter { $0.name != "metadata" && !availableNames.contains($0.name) }
                        ForEach(unavailable) { permission in
                            GridRow {
                                GithubPermissionLabel(
                                    name: permission.scopeLabel, unavailableLevel: permission.level
                                )
                                Text("None")
                            }
                            .disabled(true)
                        }
                    }
                }
            }
        } else if !requested.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel("Requested permissions").accessibilityAddTraits(.isHeader)
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                    ForEach(requested) { permission in
                        GridRow {
                            Text(verbatim: permission.scopeLabel)
                            if permission.name == "metadata" {
                                Text("Read (required)")
                            } else {
                                Text(verbatim: permission.level.rawValue)
                            }
                        }
                    }
                }
            }
        }
    }
}


private struct GithubPermissionLabel: View {
    let name: String
    let unavailableLevel: GithubPermissionLevel?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: name)
            if let unavailableLevel {
                Text("Requested: \(unavailableLevel.rawValue) (unavailable)", comment: "Requested GitHub permission level that exceeds the selected installation’s limit.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .combine)
    }
}
